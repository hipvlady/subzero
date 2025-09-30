"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

High-Performance Rate Limiter with Token Bucket Algorithm
Distributed rate limiting with Redis backend

Features:
- Token bucket algorithm for smooth rate limiting
- Sliding window counters
- Distributed coordination via Redis
- Per-user, per-IP, and global rate limits
- Burst handling
"""

import time
from dataclasses import dataclass
from enum import Enum

import redis.asyncio as redis

from subzero.config.defaults import settings


class LimitType(str, Enum):
    """Types of rate limits"""

    PER_USER = "per_user"
    PER_IP = "per_ip"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"


@dataclass
class RateLimit:
    """Rate limit configuration"""

    requests: int  # Number of requests allowed
    window: int  # Time window in seconds
    burst: int = 0  # Burst allowance


class TokenBucket:
    """
    Token bucket algorithm implementation
    Allows burst traffic while maintaining average rate
    """

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket

        Args:
            rate: Token refill rate (tokens per second)
            capacity: Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens available, False otherwise
        """
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill

        # Calculate tokens to add
        tokens_to_add = elapsed * self.rate

        # Refill bucket (capped at capacity)
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def get_wait_time(self, tokens: int = 1) -> float:
        """
        Get time to wait until tokens available

        Args:
            tokens: Number of tokens needed

        Returns:
            Wait time in seconds
        """
        self._refill()

        if self.tokens >= tokens:
            return 0.0

        tokens_needed = tokens - self.tokens
        return tokens_needed / self.rate


class DistributedRateLimiter:
    """
    Distributed rate limiter using Redis
    Implements token bucket and sliding window algorithms
    """

    def __init__(self, redis_url: str = None, default_limits: dict[LimitType, RateLimit] | None = None):
        """
        Initialize rate limiter

        Args:
            redis_url: Redis connection URL
            default_limits: Default rate limit configurations
        """
        self.redis_url = redis_url or settings.REDIS_URL

        # Initialize Redis connection
        self.redis = redis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

        # Default rate limits from settings
        self.default_limits = default_limits or {
            LimitType.PER_USER: RateLimit(
                requests=settings.RATE_LIMIT_REQUESTS,
                window=settings.RATE_LIMIT_WINDOW,
                burst=int(settings.RATE_LIMIT_REQUESTS * 0.2),  # 20% burst
            ),
            LimitType.PER_IP: RateLimit(
                requests=settings.RATE_LIMIT_REQUESTS * 2,
                window=settings.RATE_LIMIT_WINDOW,
                burst=int(settings.RATE_LIMIT_REQUESTS * 0.3),
            ),
            LimitType.GLOBAL: RateLimit(
                requests=settings.RATE_LIMIT_REQUESTS * 1000,
                window=settings.RATE_LIMIT_WINDOW,
                burst=int(settings.RATE_LIMIT_REQUESTS * 200),
            ),
        }

        # Local token buckets for hot keys
        self.local_buckets: dict[str, TokenBucket] = {}

        # Metrics
        self.requests_allowed = 0
        self.requests_denied = 0

    async def check_rate_limit(
        self, key: str, limit_type: LimitType = LimitType.PER_USER, custom_limit: RateLimit | None = None
    ) -> tuple[bool, dict]:
        """
        Check if request is within rate limit

        Args:
            key: Identifier (user_id, IP, etc.)
            limit_type: Type of rate limit to apply
            custom_limit: Optional custom rate limit

        Returns:
            Tuple of (allowed, metadata)
        """
        start_time = time.perf_counter()

        # Get applicable rate limit
        rate_limit = custom_limit or self.default_limits.get(limit_type)

        if not rate_limit:
            return True, {"reason": "no_limit_configured"}

        # Check local token bucket first (fast path)
        bucket_key = f"{limit_type.value}:{key}"

        if bucket_key in self.local_buckets:
            bucket = self.local_buckets[bucket_key]
            if bucket.consume():
                self.requests_allowed += 1
                return True, {
                    "source": "local_bucket",
                    "remaining": int(bucket.tokens),
                    "latency_ms": (time.perf_counter() - start_time) * 1000,
                }

        # Fall back to Redis-based sliding window
        allowed, metadata = await self._check_sliding_window(key, rate_limit, limit_type)

        if allowed:
            self.requests_allowed += 1

            # Create local bucket for hot keys
            rate = rate_limit.requests / rate_limit.window
            capacity = rate_limit.requests + rate_limit.burst

            self.local_buckets[bucket_key] = TokenBucket(rate, capacity)

        else:
            self.requests_denied += 1

        metadata["latency_ms"] = (time.perf_counter() - start_time) * 1000

        return allowed, metadata

    async def _check_sliding_window(self, key: str, rate_limit: RateLimit, limit_type: LimitType) -> tuple[bool, dict]:
        """
        Sliding window rate limit check using Redis

        Args:
            key: Identifier
            rate_limit: Rate limit configuration
            limit_type: Limit type

        Returns:
            Tuple of (allowed, metadata)
        """
        current_time = time.time()
        window_start = current_time - rate_limit.window

        redis_key = f"rate_limit:{limit_type.value}:{key}"

        try:
            # Use Redis sorted set for sliding window
            pipe = self.redis.pipeline()

            # Remove old entries outside the window
            pipe.zremrangebyscore(redis_key, 0, window_start)

            # Count requests in current window
            pipe.zcard(redis_key)

            # Add current request
            pipe.zadd(redis_key, {str(current_time): current_time})

            # Set expiration
            pipe.expire(redis_key, rate_limit.window + 1)

            results = await pipe.execute()

            # Extract count from results
            request_count = results[1]  # zcard result

            # Check if within limit
            max_requests = rate_limit.requests + rate_limit.burst
            allowed = request_count < max_requests

            return allowed, {
                "source": "sliding_window",
                "current_count": request_count,
                "limit": rate_limit.requests,
                "window_seconds": rate_limit.window,
                "remaining": max(0, max_requests - request_count - 1),
                "reset_at": window_start + rate_limit.window,
            }

        except Exception as e:
            print(f"❌ Rate limit check error: {e}")
            # Fail open - allow request if Redis unavailable
            return True, {"source": "error_fallback", "error": str(e)}

    async def reset_rate_limit(self, key: str, limit_type: LimitType):
        """
        Reset rate limit for a key

        Args:
            key: Identifier
            limit_type: Limit type
        """
        redis_key = f"rate_limit:{limit_type.value}:{key}"
        bucket_key = f"{limit_type.value}:{key}"

        # Delete from Redis
        await self.redis.delete(redis_key)

        # Delete from local cache
        if bucket_key in self.local_buckets:
            del self.local_buckets[bucket_key]

    async def get_current_usage(self, key: str, limit_type: LimitType) -> dict:
        """
        Get current rate limit usage for a key

        Args:
            key: Identifier
            limit_type: Limit type

        Returns:
            Usage statistics
        """
        redis_key = f"rate_limit:{limit_type.value}:{key}"
        rate_limit = self.default_limits.get(limit_type)

        if not rate_limit:
            return {"error": "no_limit_configured"}

        try:
            current_time = time.time()
            window_start = current_time - rate_limit.window

            # Count requests in window
            count = await self.redis.zcount(redis_key, window_start, current_time)

            max_requests = rate_limit.requests + rate_limit.burst

            return {
                "current_count": count,
                "limit": rate_limit.requests,
                "burst_allowance": rate_limit.burst,
                "total_capacity": max_requests,
                "remaining": max(0, max_requests - count),
                "window_seconds": rate_limit.window,
                "usage_percent": (count / max_requests) * 100 if max_requests > 0 else 0,
            }

        except Exception as e:
            return {"error": str(e)}

    async def get_global_stats(self) -> dict:
        """Get global rate limiter statistics"""
        total_requests = self.requests_allowed + self.requests_denied
        deny_rate = (self.requests_denied / max(total_requests, 1)) * 100

        return {
            "requests_allowed": self.requests_allowed,
            "requests_denied": self.requests_denied,
            "deny_rate_percent": deny_rate,
            "local_buckets": len(self.local_buckets),
            "configured_limits": {
                limit_type.value: {"requests": limit.requests, "window": limit.window, "burst": limit.burst}
                for limit_type, limit in self.default_limits.items()
            },
        }

    async def close(self):
        """Close Redis connection"""
        await self.redis.close()


# Decorators for FastAPI integration


def rate_limit(limit_type: LimitType = LimitType.PER_USER, requests: int = None, window: int = None):
    """
    Decorator for rate limiting FastAPI endpoints

    Usage:
        @app.get("/api/endpoint")
        @rate_limit(LimitType.PER_USER, requests=100, window=60)
        async def endpoint(request: Request):
            ...
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract request object
            request = None
            for arg in args:
                if hasattr(arg, "client"):
                    request = arg
                    break

            if not request:
                # No request object, skip rate limiting
                return await func(*args, **kwargs)

            # Initialize rate limiter
            limiter = DistributedRateLimiter()

            # Determine key based on limit type
            if limit_type == LimitType.PER_USER:
                # Extract user_id from token or session
                key = request.state.user_id if hasattr(request.state, "user_id") else "anonymous"
            elif limit_type == LimitType.PER_IP:
                key = request.client.host
            else:
                key = "global"

            # Custom rate limit if provided
            custom_limit = None
            if requests and window:
                custom_limit = RateLimit(requests=requests, window=window)

            # Check rate limit
            allowed, metadata = await limiter.check_rate_limit(key, limit_type, custom_limit)

            if not allowed:
                # Rate limit exceeded
                from fastapi import HTTPException

                raise HTTPException(
                    status_code=429, detail={"error": "rate_limit_exceeded", "message": "Too many requests", **metadata}
                )

            # Add rate limit info to response headers
            response = await func(*args, **kwargs)

            if hasattr(response, "headers"):
                response.headers["X-RateLimit-Limit"] = str(metadata.get("limit", 0))
                response.headers["X-RateLimit-Remaining"] = str(metadata.get("remaining", 0))
                response.headers["X-RateLimit-Reset"] = str(int(metadata.get("reset_at", 0)))

            await limiter.close()

            return response

        return wrapper

    return decorator
