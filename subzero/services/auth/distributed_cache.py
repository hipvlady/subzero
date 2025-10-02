"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Distributed Cache Manager - Multi-Process Shared Cache
Uses multiprocessing.Manager for cross-process cache sharing
Provides better scalability and shared state management
"""

import asyncio
import multiprocessing as mp
import time
from typing import Any

import numpy as np

from subzero.services.auth.cuckoo_cache import CuckooCache


class DistributedCacheManager:
    """
    Distributed cache manager for multi-process applications

    Features:
    - Shared cache across multiple processes
    - Thread-safe and process-safe operations
    - Automatic expiration handling
    - Statistics tracking

    Benefits over local cache:
    - Shared state across processes
    - Better scalability for multi-process apps
    - Centralized cache management
    """

    def __init__(self, capacity: int = 10000):
        """
        Initialize distributed cache manager

        Args:
            capacity: Maximum cache capacity
        """
        self.capacity = capacity

        # Use multiprocessing Manager for shared cache
        self.manager = mp.Manager()
        self.cache_dict = self.manager.dict()
        self.lock = self.manager.Lock()

        # Local cache for hot keys
        self.local_cache = CuckooCache(capacity=min(1000, capacity // 10))

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "local_hits": 0,
        }

    async def get(self, key: str) -> Any | None:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        # Try local cache first
        key_hash = np.uint64(hash(key) & 0xFFFFFFFFFFFFFFFF)
        local_value = self.local_cache.get(key_hash)

        if local_value is not None:
            entry = local_value
            # Check expiration
            if entry.get("expires_at", float("inf")) > time.time():
                self.stats["hits"] += 1
                self.stats["local_hits"] += 1
                return entry["value"]

        # Try distributed cache
        with self.lock:
            if key in self.cache_dict:
                entry = self.cache_dict[key]

                # Check expiration
                if entry.get("expires_at", float("inf")) > time.time():
                    self.stats["hits"] += 1

                    # Update local cache
                    self.local_cache.insert(key_hash, entry)

                    return entry["value"]
                else:
                    # Expired - remove
                    del self.cache_dict[key]

        self.stats["misses"] += 1
        return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
        """
        entry = {
            "value": value,
            "expires_at": time.time() + ttl,
            "created_at": time.time(),
        }

        # Set in distributed cache
        with self.lock:
            self.cache_dict[key] = entry

            # Enforce capacity
            if len(self.cache_dict) > self.capacity:
                # Remove oldest entry
                oldest_key = min(self.cache_dict.keys(), key=lambda k: self.cache_dict[k].get("created_at", 0))
                del self.cache_dict[oldest_key]

        # Set in local cache
        key_hash = np.uint64(hash(key) & 0xFFFFFFFFFFFFFFFF)
        self.local_cache.insert(key_hash, entry)

        self.stats["sets"] += 1

    async def delete(self, key: str):
        """
        Delete key from cache

        Args:
            key: Cache key
        """
        with self.lock:
            if key in self.cache_dict:
                del self.cache_dict[key]
                self.stats["deletes"] += 1

        # Remove from local cache
        key_hash = np.uint64(hash(key) & 0xFFFFFFFFFFFFFFFF)
        self.local_cache.delete(key_hash)

    async def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache_dict.clear()

        self.local_cache.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0.0
        local_hit_rate = self.stats["local_hits"] / self.stats["hits"] if self.stats["hits"] > 0 else 0.0

        with self.lock:
            size = len(self.cache_dict)

        return {
            **self.stats,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
            "local_hit_rate": local_hit_rate,
            "size": size,
            "capacity": self.capacity,
            "load_factor": size / self.capacity if self.capacity > 0 else 0.0,
        }

    async def close(self):
        """Cleanup resources"""
        await self.clear()
        self.manager.shutdown()
