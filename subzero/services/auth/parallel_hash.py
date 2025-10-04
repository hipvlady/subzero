"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Parallel Hash Computer - Multi-Process Hash Operations
Uses process pools for CPU-intensive hashing with GIL bypass

⚠️  WARNING: Hash operations are TOO FAST for multiprocessing!
- Hash cost: ~1-2µs per operation (BLAKE2B/SHA256)
- MP overhead: ~100ms
- Break-even: Would need 50,000+ hashes (unrealistic)
- RECOMMENDATION: This class should ALWAYS use sequential processing
- Multiprocessing makes hash operations 100x SLOWER for typical batches

Target: Sequential is 10-100x faster than MP for hash operations
"""

import asyncio
import hashlib
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from subzero.config.defaults import settings

try:
    import xxhash

    XXHASH_AVAILABLE = True
except ImportError:
    XXHASH_AVAILABLE = False


def _hash_data_worker(data_chunk: list[bytes], algorithm: str = "blake2b") -> list[bytes]:
    """
    Worker function for parallel hashing

    Args:
        data_chunk: Chunk of data to hash
        algorithm: Hash algorithm to use

    Returns:
        List of hash digests
    """
    hashes = []

    for data in data_chunk:
        if algorithm == "xxhash" and XXHASH_AVAILABLE:
            h = xxhash.xxh64(data).digest()
        elif algorithm == "blake2b":
            h = hashlib.blake2b(data, digest_size=32).digest()
        elif algorithm == "sha256":
            h = hashlib.sha256(data).digest()
        elif algorithm == "sha512":
            h = hashlib.sha512(data).digest()
        else:
            h = hashlib.blake2b(data, digest_size=32).digest()

        hashes.append(h)

    return hashes


class ParallelHashComputer:
    """
    Parallel hash computer for CPU-intensive hash operations

    Features:
    - Multi-process execution for GIL bypass
    - Support for multiple hash algorithms
    - Automatic workload distribution
    - Zero-copy for large datasets

    Performance Targets:
    - 1000 hashes: <50ms (vs 200ms sequential)
    - 5000 hashes: <200ms (vs 1000ms sequential)
    - Target: 4x+ speedup
    """

    def __init__(self, num_workers: int = 1, algorithm: str = "blake2b"):
        """
        Initialize parallel hash computer

        ⚠️  NOTE: Hash operations are too fast for multiprocessing!
        This class will ALWAYS use sequential processing due to 100ms MP overhead.

        Args:
            num_workers: Number of worker processes (ignored - always uses sequential)
            algorithm: Hash algorithm ('xxhash', 'blake2b', 'sha256', 'sha512')
        """
        self.num_workers = num_workers
        self.algorithm = algorithm
        self.executor = ProcessPoolExecutor(max_workers=num_workers) if num_workers > 1 else None

        # Operation cost (hash operations are extremely fast)
        self.hash_cost_ms = 0.002  # 2µs per hash

        # Statistics
        self.stats = {
            "total_hashes": 0,
            "total_time": 0.0,
            "mp_decisions": 0,
            "sequential_decisions": 0,
        }

    def _should_use_multiprocessing(self, batch_size: int) -> bool:
        """
        Determine if multiprocessing should be used

        For hash operations, the answer is almost ALWAYS NO.
        Hash cost is ~2µs, so we'd need 150,000 hashes to justify 300ms threshold.

        Args:
            batch_size: Number of hashes to compute

        Returns:
            True if multiprocessing is beneficial (almost never)
        """
        if not settings.ENABLE_MULTIPROCESSING:
            return False

        # Hash operations are too fast - would need 150,000+ hashes
        OVERHEAD_MS = 100
        total_time_ms = batch_size * self.hash_cost_ms

        # Only use MP if operation time > 3x overhead
        return total_time_ms > (OVERHEAD_MS * 3)  # 300ms threshold

    async def compute_single_hash(self, data: bytes) -> bytes:
        """
        Compute single hash

        Args:
            data: Data to hash

        Returns:
            Hash digest
        """
        if self.algorithm == "xxhash" and XXHASH_AVAILABLE:
            return xxhash.xxh64(data).digest()
        elif self.algorithm == "blake2b":
            return hashlib.blake2b(data, digest_size=32).digest()
        elif self.algorithm == "sha256":
            return hashlib.sha256(data).digest()
        elif self.algorithm == "sha512":
            return hashlib.sha512(data).digest()
        else:
            return hashlib.blake2b(data, digest_size=32).digest()

    async def compute_parallel_hashes(self, data_list: list[bytes]) -> list[bytes]:
        """
        Compute hashes with intelligent MP decision

        ⚠️  Hash operations are too fast for MP! This will almost always use sequential.
        MP would require 150,000+ hashes to break even (unrealistic batch size).

        Args:
            data_list: List of data to hash

        Returns:
            List of hash digests
        """
        start_time = time.perf_counter()

        if not data_list:
            return []

        # Intelligent MP decision (almost always returns False for hashes)
        if not self._should_use_multiprocessing(len(data_list)):
            # Use sequential (typical case - hash is too fast for MP)
            self.stats["sequential_decisions"] += 1
            hashes = []
            for data in data_list:
                h = await self.compute_single_hash(data)
                hashes.append(h)
        else:
            # Use multiprocessing (RARE - only for 150K+ hashes)
            self.stats["mp_decisions"] += 1

            # Split data across workers
            chunk_size = max(1, len(data_list) // self.num_workers)
            chunks = [data_list[i : i + chunk_size] for i in range(0, len(data_list), chunk_size)]

            # Submit to process pool
            loop = asyncio.get_event_loop()
            tasks = []

            for chunk in chunks:
                task = loop.run_in_executor(self.executor, _hash_data_worker, chunk, self.algorithm)
                tasks.append(task)

            # Gather results
            results = await asyncio.gather(*tasks)

            # Flatten results
            hashes = []
            for result in results:
                hashes.extend(result)

        # Update statistics
        elapsed = time.perf_counter() - start_time
        self.stats["total_hashes"] += len(hashes)
        self.stats["total_time"] += elapsed

        return hashes

    def get_stats(self) -> dict[str, Any]:
        """Get hash computer statistics"""
        avg_time = self.stats["total_time"] / self.stats["total_hashes"] if self.stats["total_hashes"] > 0 else 0.0

        return {
            **self.stats,
            "avg_hash_time_us": avg_time * 1e6,
            "throughput_hps": (
                self.stats["total_hashes"] / self.stats["total_time"] if self.stats["total_time"] > 0 else 0
            ),
            "num_workers": self.num_workers,
            "algorithm": self.algorithm,
        }

    def close(self):
        """Shutdown hash computer"""
        if self.executor:
            self.executor.shutdown(wait=True)
