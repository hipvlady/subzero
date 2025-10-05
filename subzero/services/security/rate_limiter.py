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
    """
    Rate limit scope types for controlling access patterns.

    Defines different granularities for applying rate limits to incoming
    requests. Each type uses a different identifier for tracking usage.

    Attributes
    ----------
    PER_USER : str
        Rate limit per authenticated user ID. Tracks requests individually
        for each user account.
    PER_IP : str
        Rate limit per client IP address. Useful for protecting against
        distributed attacks or limiting anonymous users.
    PER_ENDPOINT : str
        Rate limit per API endpoint. Controls traffic to specific routes
        regardless of user or IP.
    GLOBAL : str
        Global rate limit across the entire application. Provides system-wide
        protection against traffic spikes.
    """

    PER_USER = "per_user"
    PER_IP = "per_ip"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"


@dataclass
class RateLimit:
    """
    Rate limit configuration parameters.

    Defines the constraints for rate limiting including request capacity,
    time window, and burst allowance for handling traffic spikes.

    Attributes
    ----------
    requests : int
        Maximum number of requests allowed within the time window under
        normal conditions.
    window : int
        Time window in seconds for counting requests. After this period,
        the counter resets.
    burst : int, default 0
        Additional requests allowed beyond the base limit to accommodate
        short-term traffic bursts. Total capacity is requests + burst.

    Examples
    --------
    Create a rate limit allowing 100 requests per minute with 20 burst:

    >>> limit = RateLimit(requests=100, window=60, burst=20)
    >>> limit.requests
    100
    """

    requests: int  # Number of requests allowed
    window: int  # Time window in seconds
    burst: int = 0  # Burst allowance


class TokenBucket:
    """
    Token bucket algorithm for rate limiting with burst support.

    Implements the classic token bucket algorithm that allows controlled
    burst traffic while maintaining a specified average rate. Tokens are
    refilled at a constant rate, and each request consumes one or more tokens.

    Parameters
    ----------
    rate : float
        Token refill rate in tokens per second. Determines the sustained
        throughput allowed by the bucket.
    capacity : int
        Maximum number of tokens the bucket can hold. Controls the maximum
        burst size allowed.

    Attributes
    ----------
    rate : float
        Token refill rate (tokens per second).
    capacity : int
        Maximum bucket capacity.
    tokens : float
        Current number of tokens available in the bucket.
    last_refill : float
        Timestamp of the last token refill operation.

    Notes
    -----
    The token bucket algorithm provides smooth rate limiting by:
    1. Refilling tokens at a constant rate
    2. Allowing requests to consume tokens if available
    3. Permitting bursts up to the capacity limit

    This is more flexible than fixed window counters as it allows natural
    traffic bursts while preventing sustained overload.

    Examples
    --------
    Create a bucket allowing 10 requests/second with burst capacity of 50:

    >>> bucket = TokenBucket(rate=10.0, capacity=50)
    >>> bucket.consume(1)  # Consume one token
    True
    >>> bucket.consume(100)  # Try to consume more than capacity
    False
    """

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.

        Parameters
        ----------
        rate : float
            Token refill rate (tokens per second)
        capacity : int
            Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from the bucket.

        Refills the bucket based on elapsed time, then checks if enough
        tokens are available. If so, consumes them and returns True.

        Parameters
        ----------
        tokens : int, default 1
            Number of tokens to consume for this request

        Returns
        -------
        bool
            True if tokens were available and consumed, False if insufficient
            tokens available

        Examples
        --------
        >>> bucket = TokenBucket(rate=5.0, capacity=10)
        >>> bucket.consume(3)
        True
        >>> bucket.tokens
        7.0
        """
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    def _refill(self):
        """
        Refill tokens based on elapsed time.

        Calculates tokens to add based on time elapsed since last refill
        and the configured refill rate. Caps total tokens at capacity.
        """
        now = time.time()
        elapsed = now - self.last_refill

        # Calculate tokens to add
        tokens_to_add = elapsed * self.rate

        # Refill bucket (capped at capacity)
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def get_wait_time(self, tokens: int = 1) -> float:
        """
        Calculate wait time until requested tokens become available.

        Useful for implementing retry logic or providing feedback to users
        about when they can make the next request.

        Parameters
        ----------
        tokens : int, default 1
            Number of tokens needed for the next request

        Returns
        -------
        float
            Wait time in seconds until the requested tokens will be available.
            Returns 0.0 if tokens are already available.

        Notes
        -----
        The wait time is calculated as: (tokens_needed - current_tokens) / rate
        This assumes constant refill rate and no other token consumption.

        Examples
        --------
        >>> bucket = TokenBucket(rate=10.0, capacity=20)
        >>> bucket.consume(20)  # Consume all tokens
        True
        >>> bucket.get_wait_time(10)  # How long until 10 tokens available?
        1.0
        """
        self._refill()

        if self.tokens >= tokens:
            return 0.0

        tokens_needed = tokens - self.tokens
        return tokens_needed / self.rate


class DistributedRateLimiter:
    """
    Distributed rate limiter using Redis for coordination.

    Implements both token bucket (local, in-memory) and sliding window
    (Redis-backed) algorithms to provide high-performance distributed
    rate limiting across multiple application instances.

    The limiter uses a two-tier approach:
    1. Hot keys are cached locally with token buckets for fast checking
    2. Cold keys use Redis sliding windows for accurate distributed limits

    Parameters
    ----------
    redis_url : str, optional
        Redis connection URL. Defaults to settings.REDIS_URL if not provided.
    default_limits : dict[LimitType, RateLimit], optional
        Default rate limit configurations for each limit type. If not provided,
        uses sensible defaults from application settings.

    Attributes
    ----------
    redis_url : str
        Redis connection URL being used.
    redis : redis.asyncio.Redis
        Async Redis client instance.
    default_limits : dict[LimitType, RateLimit]
        Configured rate limits for each limit type.
    local_buckets : dict[str, TokenBucket]
        In-memory token buckets for frequently accessed keys.
    requests_allowed : int
        Counter for allowed requests (metrics).
    requests_denied : int
        Counter for denied requests (metrics).

    Notes
    -----
    Performance characteristics:
    - Local bucket checks: ~10-50 microseconds
    - Redis sliding window checks: ~1-5 milliseconds
    - Automatically promotes hot keys to local buckets
    - Fails open if Redis is unavailable (allows requests)

    The sliding window algorithm provides more accurate rate limiting than
    fixed windows by tracking individual request timestamps in Redis sorted sets.

    Examples
    --------
    Basic usage with default configuration:

    >>> limiter = DistributedRateLimiter()
    >>> allowed, metadata = await limiter.check_rate_limit("user_123", LimitType.PER_USER)
    >>> if allowed:
    ...     print(f"Request allowed, {metadata['remaining']} remaining")

    Custom rate limit:

    >>> custom_limit = RateLimit(requests=50, window=60, burst=10)
    >>> allowed, metadata = await limiter.check_rate_limit(
    ...     "user_456",
    ...     LimitType.PER_USER,
    ...     custom_limit=custom_limit
    ... )
    """

    def __init__(self, redis_url: str = None, default_limits: dict[LimitType, RateLimit] | None = None):
        """
        Initialize distributed rate limiter.

        Parameters
        ----------
        redis_url : str, optional
            Redis connection URL
        default_limits : dict[LimitType, RateLimit], optional
            Default rate limit configurations
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
        Check if a request is within the configured rate limit.

        Uses a two-tier strategy: first checks local token bucket for hot
        keys (fast path), then falls back to Redis sliding window for cold
        keys or when local bucket is exhausted.

        Parameters
        ----------
        key : str
            Identifier for the rate limit (user_id, IP address, etc.)
        limit_type : LimitType, default LimitType.PER_USER
            Type of rate limit to apply
        custom_limit : RateLimit, optional
            Custom rate limit to use instead of default for this limit_type

        Returns
        -------
        tuple[bool, dict]
            A tuple containing:
            - allowed : bool
                True if request is within limit, False if rate limit exceeded
            - metadata : dict
                Dictionary with rate limit information:
                - 'source' : str
                    Where the check was performed ('local_bucket', 'sliding_window', etc.)
                - 'remaining' : int
                    Number of requests remaining in current window
                - 'latency_ms' : float
                    Time taken for the rate limit check in milliseconds
                - 'current_count' : int (sliding_window only)
                    Current number of requests in the window
                - 'limit' : int
                    Maximum requests allowed
                - 'window_seconds' : int
                    Time window in seconds
                - 'reset_at' : float (sliding_window only)
                    Unix timestamp when the window resets

        Notes
        -----
        Performance optimization: Hot keys (frequently accessed) are promoted
        to local token buckets for sub-millisecond checks. This reduces Redis
        load and improves response times.

        Examples
        --------
        Check rate limit for a user:

        >>> allowed, metadata = await limiter.check_rate_limit("user_123", LimitType.PER_USER)
        >>> if not allowed:
        ...     print(f"Rate limited! Try again in {metadata.get('reset_at', 0)} seconds")

        Check with custom limit:

        >>> custom = RateLimit(requests=10, window=60, burst=2)
        >>> allowed, meta = await limiter.check_rate_limit("192.168.1.1", LimitType.PER_IP, custom)
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
        Perform sliding window rate limit check using Redis sorted sets.

        Implements the sliding window algorithm by storing request timestamps
        in a Redis sorted set and counting requests within the current window.

        Parameters
        ----------
        key : str
            Identifier for the rate limit
        rate_limit : RateLimit
            Rate limit configuration to apply
        limit_type : LimitType
            Type of limit being checked

        Returns
        -------
        tuple[bool, dict]
            A tuple containing:
            - allowed : bool
                True if request is within limit
            - metadata : dict
                Dictionary with detailed limit information

        Notes
        -----
        Algorithm steps:
        1. Remove expired entries (older than window start)
        2. Count remaining entries (current request count)
        3. Add current request timestamp
        4. Compare count against limit + burst capacity
        5. Set expiration on the sorted set

        Uses Redis pipeline for atomic operations and reduced round trips.
        Fails open if Redis is unavailable to prevent complete service outage.
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
        Reset rate limit counters for a specific key.

        Clears both Redis-based sliding window data and local token bucket
        cache for the specified key and limit type. Useful for admin operations
        or testing.

        Parameters
        ----------
        key : str
            Identifier to reset (user_id, IP address, etc.)
        limit_type : LimitType
            Type of rate limit to reset

        Examples
        --------
        >>> await limiter.reset_rate_limit("user_123", LimitType.PER_USER)
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
        Get current rate limit usage statistics for a key.

        Queries Redis to retrieve the current request count and calculates
        remaining capacity, usage percentage, and other metrics.

        Parameters
        ----------
        key : str
            Identifier to check (user_id, IP address, etc.)
        limit_type : LimitType
            Type of rate limit to query

        Returns
        -------
        dict
            Usage statistics dictionary containing:
            - 'current_count' : int
                Number of requests in the current window
            - 'limit' : int
                Base request limit (without burst)
            - 'burst_allowance' : int
                Additional burst capacity
            - 'total_capacity' : int
                Maximum requests allowed (limit + burst)
            - 'remaining' : int
                Remaining request capacity
            - 'window_seconds' : int
                Time window in seconds
            - 'usage_percent' : float
                Percentage of capacity used (0-100)
            - 'error' : str (only if error occurred)
                Error message if retrieval failed

        Examples
        --------
        >>> usage = await limiter.get_current_usage("user_123", LimitType.PER_USER)
        >>> print(f"Used {usage['current_count']}/{usage['total_capacity']} requests")
        >>> print(f"Usage: {usage['usage_percent']:.1f}%")
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
        """
        Get global rate limiter statistics and metrics.

        Aggregates statistics across all rate limit operations performed
        by this limiter instance.

        Returns
        -------
        dict
            Global statistics dictionary containing:
            - 'requests_allowed' : int
                Total number of allowed requests
            - 'requests_denied' : int
                Total number of denied requests
            - 'deny_rate_percent' : float
                Percentage of requests denied (0-100)
            - 'local_buckets' : int
                Number of active local token buckets
            - 'configured_limits' : dict
                Dictionary of configured limits for each limit type

        Examples
        --------
        >>> stats = await limiter.get_global_stats()
        >>> print(f"Deny rate: {stats['deny_rate_percent']:.2f}%")
        >>> print(f"Local buckets: {stats['local_buckets']}")
        """
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
        """
        Close Redis connection and cleanup resources.

        Should be called when shutting down the application to properly
        release Redis connections.
        """
        await self.redis.close()


# Decorators for FastAPI integration


def rate_limit(limit_type: LimitType = LimitType.PER_USER, requests: int = None, window: int = None):
    """
    Decorator for applying rate limits to FastAPI endpoints.

    Automatically checks rate limits before executing the endpoint handler.
    Raises HTTPException with 429 status code if rate limit is exceeded.
    Adds rate limit information to response headers.

    Parameters
    ----------
    limit_type : LimitType, default LimitType.PER_USER
        Type of rate limit to apply (per user, per IP, etc.)
    requests : int, optional
        Custom number of requests allowed. If not specified, uses default
        from limiter configuration.
    window : int, optional
        Custom time window in seconds. If not specified, uses default from
        limiter configuration.

    Returns
    -------
    callable
        Decorated function with rate limiting applied

    Notes
    -----
    The decorator:
    - Extracts the Request object from function arguments
    - Determines the rate limit key based on limit_type
    - Creates a DistributedRateLimiter instance for each request
    - Checks the rate limit before executing the handler
    - Adds X-RateLimit-* headers to successful responses
    - Raises HTTPException(429) if limit exceeded

    Response headers added:
    - X-RateLimit-Limit: Maximum requests allowed
    - X-RateLimit-Remaining: Requests remaining in window
    - X-RateLimit-Reset: Unix timestamp when limit resets

    Examples
    --------
    Apply default per-user rate limiting:

    >>> from fastapi import FastAPI, Request
    >>> app = FastAPI()
    >>> @app.get("/api/data")
    ... @rate_limit(LimitType.PER_USER)
    ... async def get_data(request: Request):
    ...     return {"data": "some data"}

    Apply custom rate limit (10 requests per minute):

    >>> @app.post("/api/upload")
    ... @rate_limit(LimitType.PER_IP, requests=10, window=60)
    ... async def upload_file(request: Request):
    ...     return {"status": "uploaded"}

    Apply global rate limit:

    >>> @app.get("/api/public")
    ... @rate_limit(LimitType.GLOBAL, requests=1000, window=60)
    ... async def public_endpoint(request: Request):
    ...     return {"message": "hello"}
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
