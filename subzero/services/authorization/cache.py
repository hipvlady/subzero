"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

High-Performance Authorization Decision Caching
Implements multi-tier caching strategy for authorization checks

Features:
- L1: In-memory cache with LRU eviction
- L2: Redis distributed cache
- Cache invalidation on permission changes
- Negative caching for failed checks
- TTL-based expiration
- Bloom filter for fast negative lookups
"""

import asyncio
import time
import hashlib
from typing import Dict, Optional, Tuple, List, Set
from dataclasses import dataclass, field
from collections import OrderedDict
from enum import Enum

import numpy as np
from numba import jit
import redis.asyncio as redis


class CacheLevel(str, Enum):
    """Cache tier levels"""

    L1_MEMORY = "l1_memory"
    L2_REDIS = "l2_redis"
    MISS = "miss"


@dataclass
class CacheEntry:
    """Cached authorization decision"""

    allowed: bool
    cached_at: float
    ttl: int
    metadata: Dict = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        return time.time() > (self.cached_at + self.ttl)


@dataclass
class CacheKey:
    """Normalized cache key for authorization checks"""

    subject_type: str
    subject_id: str
    resource_type: str
    resource_id: str
    permission: str

    def to_string(self) -> str:
        """Convert to string representation"""
        return f"{self.subject_type}:{self.subject_id}|{self.resource_type}:{self.resource_id}|{self.permission}"

    def to_hash(self) -> str:
        """Convert to hash for compact storage"""
        key_str = self.to_string()
        return hashlib.sha256(key_str.encode()).hexdigest()


class BloomFilter:
    """
    Space-efficient probabilistic data structure for set membership
    Used for fast negative cache lookups
    """

    def __init__(self, size: int = 100000, hash_count: int = 5):
        """
        Initialize Bloom filter

        Args:
            size: Size of bit array
            hash_count: Number of hash functions
        """
        self.size = size
        self.hash_count = hash_count
        self.bit_array = np.zeros(size, dtype=np.bool_)

    @staticmethod
    @jit(nopython=True, cache=True)
    def _hash_function(data: np.ndarray, seed: int, size: int) -> int:
        """JIT-compiled hash function"""
        hash_val = np.uint64(seed)
        for byte in data:
            hash_val = ((hash_val << 5) + hash_val) + np.uint64(byte)
        return int(hash_val % size)

    def add(self, item: str):
        """Add item to Bloom filter"""
        item_bytes = np.frombuffer(item.encode(), dtype=np.uint8)

        for i in range(self.hash_count):
            index = self._hash_function(item_bytes, i, self.size)
            self.bit_array[index] = True

    def contains(self, item: str) -> bool:
        """
        Check if item might be in set
        Returns True if definitely not in set, False if maybe in set
        """
        item_bytes = np.frombuffer(item.encode(), dtype=np.uint8)

        for i in range(self.hash_count):
            index = self._hash_function(item_bytes, i, self.size)
            if not self.bit_array[index]:
                return False  # Definitely not in set

        return True  # Possibly in set

    def clear(self):
        """Clear all items from Bloom filter"""
        self.bit_array.fill(False)


class LRUCache:
    """
    Thread-safe LRU cache for authorization decisions
    L1 cache tier - fastest access
    """

    def __init__(self, capacity: int = 10000):
        """
        Initialize LRU cache

        Args:
            capacity: Maximum number of entries
        """
        self.capacity = capacity
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = asyncio.Lock()

        # Metrics
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> Optional[CacheEntry]:
        """
        Get cached entry

        Args:
            key: Cache key

        Returns:
            Cache entry or None if not found/expired
        """
        async with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None

            entry = self.cache[key]

            # Check expiration
            if entry.is_expired():
                del self.cache[key]
                self.misses += 1
                return None

            # Move to end (mark as recently used)
            self.cache.move_to_end(key)

            self.hits += 1
            return entry

    async def put(self, key: str, entry: CacheEntry):
        """
        Put entry in cache

        Args:
            key: Cache key
            entry: Cache entry
        """
        async with self.lock:
            # Remove oldest entry if at capacity
            if len(self.cache) >= self.capacity and key not in self.cache:
                self.cache.popitem(last=False)

            self.cache[key] = entry
            self.cache.move_to_end(key)

    async def invalidate(self, key: str):
        """Remove entry from cache"""
        async with self.lock:
            if key in self.cache:
                del self.cache[key]

    async def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching pattern
        Pattern examples:
        - "user:alice|*" - all permissions for user alice
        - "*|document:readme|*" - all permissions for document readme
        """
        async with self.lock:
            keys_to_remove = []

            for key in self.cache.keys():
                if self._matches_pattern(key, pattern):
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.cache[key]

    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Check if key matches wildcard pattern"""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)

    async def clear(self):
        """Clear entire cache"""
        async with self.lock:
            self.cache.clear()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / max(total_requests, 1)) * 100

        return {
            "size": len(self.cache),
            "capacity": self.capacity,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": hit_rate,
        }


class RedisCache:
    """
    Redis-based distributed cache for authorization decisions
    L2 cache tier - shared across instances
    """

    def __init__(self, redis_url: str = "redis://localhost:6379", key_prefix: str = "authz:"):
        """
        Initialize Redis cache

        Args:
            redis_url: Redis connection URL
            key_prefix: Prefix for all cache keys
        """
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.redis_client: Optional[redis.Redis] = None

        # Metrics
        self.hits = 0
        self.misses = 0

    async def connect(self):
        """Establish Redis connection"""
        self.redis_client = await redis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

    async def get(self, key: str) -> Optional[CacheEntry]:
        """
        Get cached entry from Redis

        Args:
            key: Cache key

        Returns:
            Cache entry or None if not found
        """
        if not self.redis_client:
            return None

        try:
            full_key = f"{self.key_prefix}{key}"
            data = await self.redis_client.get(full_key)

            if not data:
                self.misses += 1
                return None

            # Parse JSON data
            import json

            entry_data = json.loads(data)

            entry = CacheEntry(
                allowed=entry_data["allowed"],
                cached_at=entry_data["cached_at"],
                ttl=entry_data["ttl"],
                metadata=entry_data.get("metadata", {}),
            )

            # Check expiration
            if entry.is_expired():
                await self.invalidate(key)
                self.misses += 1
                return None

            self.hits += 1
            return entry

        except Exception as e:
            print(f"Redis get error: {e}")
            self.misses += 1
            return None

    async def put(self, key: str, entry: CacheEntry):
        """
        Put entry in Redis cache

        Args:
            key: Cache key
            entry: Cache entry
        """
        if not self.redis_client:
            return

        try:
            import json

            full_key = f"{self.key_prefix}{key}"

            # Serialize entry
            entry_data = {
                "allowed": entry.allowed,
                "cached_at": entry.cached_at,
                "ttl": entry.ttl,
                "metadata": entry.metadata,
            }

            data = json.dumps(entry_data)

            # Set with TTL
            await self.redis_client.setex(full_key, entry.ttl, data)

        except Exception as e:
            print(f"Redis put error: {e}")

    async def invalidate(self, key: str):
        """Remove entry from Redis"""
        if not self.redis_client:
            return

        try:
            full_key = f"{self.key_prefix}{key}"
            await self.redis_client.delete(full_key)

        except Exception as e:
            print(f"Redis invalidate error: {e}")

    async def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching pattern

        Args:
            pattern: Key pattern with wildcards (e.g., "user:alice|*")
        """
        if not self.redis_client:
            return

        try:
            full_pattern = f"{self.key_prefix}{pattern}"

            # Scan for matching keys
            keys = []
            async for key in self.redis_client.scan_iter(match=full_pattern):
                keys.append(key)

            # Delete in batches
            if keys:
                await self.redis_client.delete(*keys)

        except Exception as e:
            print(f"Redis invalidate pattern error: {e}")

    async def clear(self):
        """Clear all authorization cache entries"""
        if not self.redis_client:
            return

        try:
            await self.invalidate_pattern("*")

        except Exception as e:
            print(f"Redis clear error: {e}")

    def get_stats(self) -> Dict:
        """Get Redis cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / max(total_requests, 1)) * 100

        return {"hits": self.hits, "misses": self.misses, "hit_rate_percent": hit_rate}

    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()


class AuthorizationCache:
    """
    Multi-tier authorization decision cache
    Combines L1 (memory) and L2 (Redis) for optimal performance
    """

    def __init__(
        self,
        l1_capacity: int = 10000,
        redis_url: Optional[str] = None,
        enable_bloom_filter: bool = True,
        default_ttl: int = 300,
    ):
        """
        Initialize authorization cache

        Args:
            l1_capacity: L1 cache capacity
            redis_url: Redis URL for L2 cache (optional)
            enable_bloom_filter: Enable Bloom filter for negative caching
            default_ttl: Default TTL in seconds
        """
        # L1 cache (memory)
        self.l1_cache = LRUCache(capacity=l1_capacity)

        # L2 cache (Redis)
        self.l2_cache: Optional[RedisCache] = None
        if redis_url:
            self.l2_cache = RedisCache(redis_url)

        # Bloom filter for negative caching
        self.bloom_filter: Optional[BloomFilter] = None
        if enable_bloom_filter:
            self.bloom_filter = BloomFilter()

        self.default_ttl = default_ttl

        # Metrics
        self.total_requests = 0
        self.l1_hits = 0
        self.l2_hits = 0
        self.misses = 0

    async def initialize(self):
        """Initialize cache connections"""
        if self.l2_cache:
            await self.l2_cache.connect()

    async def get(self, cache_key: CacheKey) -> Tuple[Optional[bool], CacheLevel]:
        """
        Get authorization decision from cache

        Args:
            cache_key: Cache key

        Returns:
            Tuple of (decision, cache_level)
            decision is None if not in cache
        """
        self.total_requests += 1
        key_str = cache_key.to_hash()

        # Check Bloom filter first (negative cache)
        if self.bloom_filter and not self.bloom_filter.contains(key_str):
            self.misses += 1
            return None, CacheLevel.MISS

        # Check L1 cache
        entry = await self.l1_cache.get(key_str)
        if entry:
            self.l1_hits += 1
            return entry.allowed, CacheLevel.L1_MEMORY

        # Check L2 cache
        if self.l2_cache:
            entry = await self.l2_cache.get(key_str)
            if entry:
                # Promote to L1
                await self.l1_cache.put(key_str, entry)

                self.l2_hits += 1
                return entry.allowed, CacheLevel.L2_REDIS

        # Cache miss
        self.misses += 1
        return None, CacheLevel.MISS

    async def put(self, cache_key: CacheKey, allowed: bool, ttl: Optional[int] = None, metadata: Optional[Dict] = None):
        """
        Put authorization decision in cache

        Args:
            cache_key: Cache key
            allowed: Authorization decision
            ttl: Time to live (seconds)
            metadata: Additional metadata
        """
        key_str = cache_key.to_hash()
        ttl = ttl or self.default_ttl

        entry = CacheEntry(allowed=allowed, cached_at=time.time(), ttl=ttl, metadata=metadata or {})

        # Add to Bloom filter
        if self.bloom_filter:
            self.bloom_filter.add(key_str)

        # Add to L1 cache
        await self.l1_cache.put(key_str, entry)

        # Add to L2 cache
        if self.l2_cache:
            await self.l2_cache.put(key_str, entry)

    async def invalidate(self, cache_key: CacheKey):
        """
        Invalidate specific cache entry

        Args:
            cache_key: Cache key to invalidate
        """
        key_str = cache_key.to_hash()

        await self.l1_cache.invalidate(key_str)

        if self.l2_cache:
            await self.l2_cache.invalidate(key_str)

    async def invalidate_subject(self, subject_type: str, subject_id: str):
        """
        Invalidate all cache entries for a subject

        Args:
            subject_type: Type of subject (e.g., "user")
            subject_id: Subject identifier
        """
        pattern = f"{subject_type}:{subject_id}|*"

        # Hash the pattern for L1 (simple prefix matching)
        await self.l1_cache.invalidate_pattern(pattern)

        if self.l2_cache:
            await self.l2_cache.invalidate_pattern(pattern)

    async def invalidate_resource(self, resource_type: str, resource_id: str):
        """
        Invalidate all cache entries for a resource

        Args:
            resource_type: Type of resource (e.g., "document")
            resource_id: Resource identifier
        """
        pattern = f"*|{resource_type}:{resource_id}|*"

        await self.l1_cache.invalidate_pattern(pattern)

        if self.l2_cache:
            await self.l2_cache.invalidate_pattern(pattern)

    async def clear(self):
        """Clear all caches"""
        await self.l1_cache.clear()

        if self.l2_cache:
            await self.l2_cache.clear()

        if self.bloom_filter:
            self.bloom_filter.clear()

    def get_metrics(self) -> Dict:
        """Get comprehensive cache metrics"""
        total = self.total_requests
        overall_hit_rate = ((self.l1_hits + self.l2_hits) / max(total, 1)) * 100

        metrics = {
            "total_requests": total,
            "l1_hits": self.l1_hits,
            "l2_hits": self.l2_hits,
            "misses": self.misses,
            "overall_hit_rate_percent": overall_hit_rate,
            "l1_stats": self.l1_cache.get_stats(),
        }

        if self.l2_cache:
            metrics["l2_stats"] = self.l2_cache.get_stats()

        return metrics

    async def close(self):
        """Close cache connections"""
        if self.l2_cache:
            await self.l2_cache.close()
