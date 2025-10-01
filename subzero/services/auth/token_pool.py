"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Token Pool Management for High-Performance Token Reuse
Implements object pooling pattern for JWT tokens
"""

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class PooledToken:
    """Pooled token with metadata"""

    token: str
    created_at: float
    expires_at: float
    user_id: str
    scopes: set[str]
    metadata: dict[str, Any] | None = None

    def is_expired(self) -> bool:
        """Check if token is expired"""
        return time.time() >= self.expires_at

    def is_valid(self) -> bool:
        """Check if token is still valid"""
        # Consider token invalid if it expires in less than 60 seconds
        return time.time() < (self.expires_at - 60)


class TokenPool:
    """
    Token pool for efficient token reuse

    Features:
    - Pre-generated token pools
    - Automatic expiration handling
    - Fast token acquisition
    - Minimal allocation overhead
    """

    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        """
        Initialize token pool

        Args:
            max_size: Maximum pool size
            default_ttl: Default token TTL in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl

        # Token pools by user_id
        self.pools: dict[str, deque[PooledToken]] = {}

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "expired": 0,
            "evictions": 0,
        }

    def get_token(self, user_id: str, required_scopes: set[str] | None = None) -> PooledToken | None:
        """
        Get token from pool

        Args:
            user_id: User ID
            required_scopes: Required scopes (if any)

        Returns:
            Pooled token if available, None otherwise
        """
        if user_id not in self.pools:
            self.stats["misses"] += 1
            return None

        pool = self.pools[user_id]

        # Find valid token with required scopes
        while pool:
            token = pool.popleft()

            # Check if expired
            if token.is_expired():
                self.stats["expired"] += 1
                continue

            # Check if valid
            if not token.is_valid():
                self.stats["expired"] += 1
                continue

            # Check scopes
            if required_scopes and not required_scopes.issubset(token.scopes):
                # Put back and continue
                pool.append(token)
                break

            # Found valid token
            self.stats["hits"] += 1
            return token

        self.stats["misses"] += 1
        return None

    def return_token(self, token: PooledToken):
        """
        Return token to pool

        Args:
            token: Token to return
        """
        if not token.is_valid():
            return

        user_id = token.user_id

        if user_id not in self.pools:
            self.pools[user_id] = deque(maxlen=self.max_size)

        pool = self.pools[user_id]

        # Check pool size
        if len(pool) >= self.max_size:
            self.stats["evictions"] += 1
            return

        pool.append(token)

    def put_token(
        self, user_id: str, token: str, expires_at: float, scopes: set[str], metadata: dict[str, Any] | None = None
    ):
        """
        Put new token in pool

        Args:
            user_id: User ID
            token: Token string
            expires_at: Expiration timestamp
            scopes: Token scopes
            metadata: Optional metadata
        """
        pooled_token = PooledToken(
            token=token,
            created_at=time.time(),
            expires_at=expires_at,
            user_id=user_id,
            scopes=scopes,
            metadata=metadata,
        )

        self.return_token(pooled_token)

    def clear_user(self, user_id: str):
        """Clear all tokens for user"""
        if user_id in self.pools:
            del self.pools[user_id]

    def clear_expired(self):
        """Clear all expired tokens"""
        for user_id in list(self.pools.keys()):
            pool = self.pools[user_id]
            valid_tokens = deque([t for t in pool if t.is_valid()])

            if valid_tokens:
                self.pools[user_id] = valid_tokens
            else:
                del self.pools[user_id]

    async def start_precomputation(self):
        """Start background token precomputation"""
        if not self.is_precomputing and self.key_manager:
            self.is_precomputing = True
            self.precomputation_task = asyncio.create_task(self._precomputation_loop())

    async def stop_precomputation(self):
        """Stop background token precomputation"""
        self.is_precomputing = False
        if self.precomputation_task:
            self.precomputation_task.cancel()
            try:
                await self.precomputation_task
            except asyncio.CancelledError:
                pass
            self.precomputation_task = None

    async def _precomputation_loop(self):
        """Background loop for token precomputation"""
        while self.is_precomputing:
            try:
                # Check if pool needs refilling
                if len(self.precomputed_pool) < self.max_size * 0.8:  # Keep pool 80% full
                    # Generate a batch of tokens
                    await self._generate_token_batch(10)

                # Sleep based on generation rate
                await asyncio.sleep(1.0 / self.generation_rate)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in precomputation loop: {e}")
                await asyncio.sleep(1.0)

    async def _generate_token_batch(self, count: int = 10):
        """Generate a batch of tokens"""
        if not self.key_manager:
            return

        for _ in range(count):
            if len(self.precomputed_pool) >= self.max_size:
                break

            # Generate generic token
            expires_at = time.time() + self.default_ttl
            payload = {
                "sub": "precomputed",
                "exp": int(expires_at),
                "iat": int(time.time()),
                "type": "generic",
            }

            token = self.key_manager.sign_jwt(payload)
            self.precomputed_pool.append(token)
            self.stats["precomputed"] += 1

    async def get_token(
        self,
        user_id: str,
        client_id: str,
        audience: str,
        scopes: set[str] | None = None
    ) -> str | None:
        """
        Get token from pool (with precomputation support)

        Args:
            user_id: User ID
            client_id: Client ID
            audience: Token audience
            scopes: Required scopes

        Returns:
            Token string or None
        """
        # Try to get from precomputed pool
        if self.precomputed_pool:
            token = self.precomputed_pool.popleft()
            self.stats["hits"] += 1
            return token

        # Try to get from user-specific pool
        if scopes:
            pooled = self.get_token(user_id, scopes)
            if pooled:
                return pooled.token

        self.stats["misses"] += 1
        return None

    def get_pool_status(self) -> dict[str, Any]:
        """Get pool status"""
        return {
            "current_tokens": len(self.precomputed_pool),
            "max_tokens": self.max_size,
            "is_precomputing": self.is_precomputing,
            "fill_percent": (len(self.precomputed_pool) / self.max_size * 100) if self.max_size > 0 else 0,
            "total_precomputed": self.stats["precomputed"],
        }

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0.0

        return {
            **self.stats,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
            "pool_count": len(self.pools),
            "total_tokens": sum(len(pool) for pool in self.pools.values()),
            "precomputed_tokens": len(self.precomputed_pool),
        }


class AdaptiveTokenPool(TokenPool):
    """
    Adaptive token pool with dynamic sizing

    Features:
    - Automatic pool size adjustment based on usage
    - Background cleanup of expired tokens
    - Hit rate monitoring and optimization
    """

    def __init__(self, initial_size: int = 1000, min_size: int = 100, max_size: int = 10000):
        """
        Initialize adaptive pool

        Args:
            initial_size: Initial pool size
            min_size: Minimum pool size
            max_size: Maximum pool size
        """
        super().__init__(max_size=initial_size)

        self.min_size = min_size
        self.max_pool_size = max_size
        self.cleanup_task: asyncio.Task | None = None

    async def start_cleanup_task(self):
        """Start background cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup_task(self):
        """Stop background cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None

    async def _cleanup_loop(self):
        """Background cleanup loop"""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                self.clear_expired()
                self._adjust_pool_size()
            except asyncio.CancelledError:
                break

    def _adjust_pool_size(self):
        """Adjust pool size based on hit rate"""
        stats = self.get_stats()
        hit_rate = stats["hit_rate"]

        # Increase size if hit rate is good
        if hit_rate > 0.8 and self.max_size < self.max_pool_size:
            self.max_size = min(int(self.max_size * 1.2), self.max_pool_size)

        # Decrease size if hit rate is poor
        elif hit_rate < 0.5 and self.max_size > self.min_size:
            self.max_size = max(int(self.max_size * 0.8), self.min_size)
