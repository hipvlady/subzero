"""
Token Pool Manager for pre-computed token generation
Amortises cryptographic costs across idle periods
"""

import asyncio
import time
import secrets
import base64
from typing import Dict, Optional, List
from collections import deque
try:
    import orjson
except ImportError:
    import json as orjson


class TokenPool:
    """
    Pre-computes tokens during idle time to reduce latency spikes
    Maintains pool of ready-to-use signed tokens
    """

    def __init__(self, pool_size: int = 1000, key_manager=None):
        self.pool_size = pool_size
        self.key_manager = key_manager

        # Use deque for O(1) append/popleft operations
        self.token_pool = deque(maxlen=pool_size)

        # Background task handle
        self.precompute_task = None

        # Metrics
        self.tokens_generated = 0
        self.tokens_consumed = 0
        self.pool_misses = 0

    async def start_precomputation(self):
        """Start background token generation"""
        self.precompute_task = asyncio.create_task(self._precompute_loop())

    async def stop_precomputation(self):
        """Stop background token generation"""
        if self.precompute_task:
            self.precompute_task.cancel()
            try:
                await self.precompute_task
            except asyncio.CancelledError:
                pass

    async def _precompute_loop(self):
        """Background loop generating tokens during idle time"""
        while True:
            try:
                pool_deficit = self.pool_size - len(self.token_pool)

                if pool_deficit > 0:
                    # Generate batch of tokens
                    batch_size = min(pool_deficit, 10)

                    for _ in range(batch_size):
                        # Create template token without user context
                        template_token = await self._generate_template_token()
                        self.token_pool.append(template_token)
                        self.tokens_generated += 1

                # Yield to main event loop
                await asyncio.sleep(0.001)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Token precomputation error: {e}")
                await asyncio.sleep(1)

    def _generate_jti(self) -> str:
        """Generate unique JWT ID"""
        random_bytes = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

    async def _generate_template_token(self) -> Dict:
        """Generate template token with placeholder values"""
        current_time = int(time.time())

        # Template claims (user-specific fields filled later)
        template_claims = {
            'iss': '__CLIENT_ID__',
            'sub': '__USER_ID__',
            'aud': '__AUDIENCE__',
            'iat': current_time,
            'exp': current_time + 300,
            'jti': self._generate_jti(),
            '_template': True,
            '_generated_at': current_time
        }

        # Pre-sign the template if key manager available
        if self.key_manager:
            # Sign with EdDSA (0.3ms)
            signed_template = self.key_manager.sign_jwt(template_claims)
        else:
            try:
                signed_template = orjson.dumps(template_claims).decode('utf-8')
            except AttributeError:
                signed_template = orjson.dumps(template_claims)

        return {
            'template': signed_template,
            'generated_at': current_time,
            'jti': template_claims['jti']
        }

    async def get_token(self, user_id: str, client_id: str,
                       audience: str) -> Optional[str]:
        """Get pre-computed token and inject user context"""
        if not self.token_pool:
            self.pool_misses += 1
            return None

        try:
            # Get pre-computed template
            template_data = self.token_pool.popleft()
            self.tokens_consumed += 1

            # Check if template is still fresh (not older than 4 minutes)
            if time.time() - template_data['generated_at'] > 240:
                # Template too old, discard
                self.pool_misses += 1
                return None

            # Inject user-specific data
            # This is much faster than full JWT generation
            token = self._inject_user_context(
                template_data['template'],
                user_id=user_id,
                client_id=client_id,
                audience=audience
            )

            return token

        except IndexError:
            self.pool_misses += 1
            return None

    def _inject_user_context(self, template: str, **kwargs) -> str:
        """Fast string replacement to inject user data"""
        # Convert to string for replacement
        token_str = template

        # Replace placeholders
        token_str = token_str.replace('__USER_ID__', kwargs['user_id'])
        token_str = token_str.replace('__CLIENT_ID__', kwargs['client_id'])
        token_str = token_str.replace('__AUDIENCE__', kwargs['audience'])

        return token_str

    def get_pool_status(self) -> Dict:
        """Get pool status and metrics"""
        return {
            'pool_size': self.pool_size,
            'current_tokens': len(self.token_pool),
            'fill_ratio': len(self.token_pool) / self.pool_size,
            'tokens_generated': self.tokens_generated,
            'tokens_consumed': self.tokens_consumed,
            'pool_misses': self.pool_misses,
            'hit_ratio': self.tokens_consumed / max(self.tokens_consumed + self.pool_misses, 1)
        }


class AdaptiveTokenPool:
    """
    Adaptive token pool that adjusts pool size based on demand
    """

    def __init__(self, initial_size: int = 500, max_size: int = 5000,
                 key_manager=None):
        self.current_pool_size = initial_size
        self.max_pool_size = max_size
        self.min_pool_size = initial_size
        self.key_manager = key_manager

        # Multiple pools for different token types
        self.pools: Dict[str, TokenPool] = {}

        # Demand tracking
        self.demand_history = deque(maxlen=100)
        self.last_adjustment_time = time.time()

        # Create default pool
        self.pools['default'] = TokenPool(
            pool_size=self.current_pool_size,
            key_manager=key_manager
        )

    async def start(self):
        """Start all token pools"""
        for pool in self.pools.values():
            await pool.start_precomputation()

        # Start adaptive sizing task
        asyncio.create_task(self._adaptive_sizing_loop())

    async def stop(self):
        """Stop all token pools"""
        for pool in self.pools.values():
            await pool.stop_precomputation()

    async def get_token(self, user_id: str, client_id: str,
                       audience: str, pool_type: str = 'default') -> Optional[str]:
        """Get token from appropriate pool"""
        # Record demand
        self.demand_history.append(time.time())

        # Get from specified pool
        if pool_type not in self.pools:
            pool_type = 'default'

        return await self.pools[pool_type].get_token(
            user_id, client_id, audience
        )

    async def _adaptive_sizing_loop(self):
        """Adjust pool sizes based on demand patterns"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                # Calculate demand rate (requests per minute)
                current_time = time.time()
                recent_demands = [
                    t for t in self.demand_history
                    if current_time - t < 60
                ]
                demand_rate = len(recent_demands)

                # Adjust pool size based on demand
                if demand_rate > self.current_pool_size * 0.8:
                    # High demand - increase pool size
                    new_size = min(
                        int(self.current_pool_size * 1.5),
                        self.max_pool_size
                    )
                    if new_size > self.current_pool_size:
                        await self._resize_pools(new_size)

                elif demand_rate < self.current_pool_size * 0.2:
                    # Low demand - decrease pool size
                    new_size = max(
                        int(self.current_pool_size * 0.7),
                        self.min_pool_size
                    )
                    if new_size < self.current_pool_size:
                        await self._resize_pools(new_size)

            except Exception as e:
                print(f"Adaptive sizing error: {e}")
                await asyncio.sleep(60)

    async def _resize_pools(self, new_size: int):
        """Resize all pools to new size"""
        self.current_pool_size = new_size

        for pool_name, pool in self.pools.items():
            # Create new pool with new size
            new_pool = TokenPool(
                pool_size=new_size,
                key_manager=self.key_manager
            )

            # Transfer existing tokens
            while pool.token_pool and new_pool.token_pool.__len__() < new_size:
                try:
                    token = pool.token_pool.popleft()
                    new_pool.token_pool.append(token)
                except IndexError:
                    break

            # Start new pool
            await new_pool.start_precomputation()

            # Stop old pool
            await pool.stop_precomputation()

            # Replace pool
            self.pools[pool_name] = new_pool

        print(f"Token pools resized to {new_size}")

    def get_metrics(self) -> Dict:
        """Get comprehensive metrics for all pools"""
        total_tokens = sum(len(p.token_pool) for p in self.pools.values())
        total_generated = sum(p.tokens_generated for p in self.pools.values())
        total_consumed = sum(p.tokens_consumed for p in self.pools.values())
        total_misses = sum(p.pool_misses for p in self.pools.values())

        return {
            'current_pool_size': self.current_pool_size,
            'total_tokens_available': total_tokens,
            'total_generated': total_generated,
            'total_consumed': total_consumed,
            'total_misses': total_misses,
            'overall_hit_ratio': total_consumed / max(total_consumed + total_misses, 1),
            'demand_rate_per_min': len([
                t for t in self.demand_history
                if time.time() - t < 60
            ]),
            'pools': {
                name: pool.get_pool_status()
                for name, pool in self.pools.items()
            }
        }