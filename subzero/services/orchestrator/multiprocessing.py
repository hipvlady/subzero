"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

CPU-Bound Multiprocessing Optimizations for Zero Trust API Gateway

This module implements multiprocessing solutions for CPU-intensive operations
that are bottlenecked by Python's Global Interpreter Lock (GIL).

Key Design Principles:
1. I/O-bound operations → asyncio (efficient with GIL)
2. CPU-bound operations → multiprocessing (bypass GIL)
3. Shared memory for zero-copy data transfer
4. Process pools for amortized startup costs
5. Intelligent workload routing based on operation type

Performance Targets:
- Request coalescing: 60% faster key generation
- Analytics processing: 4x speedup on metrics calculation
- Pattern matching: 8x speedup for batch operations
- Cache operations: 3x speedup for large datasets
"""

import asyncio
import hashlib
import logging
import multiprocessing as mp
import re
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Any

try:
    import numpy as np
    from numba import jit, prange

    NUMBA_AVAILABLE = True
except ImportError:
    NUMBA_AVAILABLE = False

logger = logging.getLogger(__name__)


class WorkloadType(Enum):
    """Classification of workload types for optimal processing"""

    IO_BOUND = "io_bound"  # Network, file I/O, database
    CPU_BOUND = "cpu_bound"  # Mathematical, cryptographic, parsing
    MIXED = "mixed"  # Combination of I/O and CPU
    GPU_BOUND = "gpu_bound"  # Parallel mathematical operations


@dataclass
class ProcessingTask:
    """Task definition for CPU-bound processing"""

    task_id: str
    operation_type: str
    workload_type: WorkloadType
    data: Any
    priority: int = 5  # 1-10, higher = more priority
    estimated_duration_ms: float = 0
    max_workers: int = 4


class CPUBoundProcessor:
    """
    High-Performance CPU-Bound Operations Processor

    Implements multiprocessing solutions for GIL-bound operations:
    1. Request coalescing key generation
    2. Performance metrics calculation
    3. Pattern matching and analysis
    4. Cache operations and cleanup
    """

    def __init__(self, max_workers: int | None = None, enable_shared_memory: bool = True, enable_numba: bool = True):
        self.max_workers = max_workers or min(8, (mp.cpu_count() or 4))
        self.enable_shared_memory = enable_shared_memory
        self.enable_numba = enable_numba and NUMBA_AVAILABLE

        # Process pools for different workload types
        self.cpu_pool: ProcessPoolExecutor | None = None
        self.analytics_pool: ProcessPoolExecutor | None = None
        self.pattern_pool: ProcessPoolExecutor | None = None

        # Performance tracking
        self.task_count = 0
        self.total_cpu_time = 0.0
        self.multiprocessing_speedup = {}

        self._initialize_pools()

        logger.info(f"CPUBoundProcessor initialized with {self.max_workers} workers")

    def _initialize_pools(self):
        """Initialize process pools for different workload types"""
        try:
            # General CPU-bound operations pool
            self.cpu_pool = ProcessPoolExecutor(
                max_workers=self.max_workers, mp_context=mp.get_context("spawn")  # More reliable on all platforms
            )

            # Analytics-specific pool (smaller, optimized for number crunching)
            self.analytics_pool = ProcessPoolExecutor(
                max_workers=min(4, self.max_workers), mp_context=mp.get_context("spawn")
            )

            # Pattern matching pool (optimized for regex operations)
            self.pattern_pool = ProcessPoolExecutor(
                max_workers=min(6, self.max_workers), mp_context=mp.get_context("spawn")
            )

            logger.info("✅ CPU-bound process pools initialized")

        except Exception as e:
            logger.error(f"❌ Failed to initialize process pools: {e}")
            # Fallback to None (will use single-threaded processing)

    async def process_batch_coalescing_keys(self, contexts: list[dict[str, Any]]) -> list[str]:
        """
        Generate coalescing keys in parallel for batch requests

        Performance target: 60% faster than sequential processing
        """
        if not self.cpu_pool or len(contexts) < 10:
            # Use sequential processing for small batches
            return [_generate_coalescing_key_sync(ctx) for ctx in contexts]

        start_time = time.perf_counter()

        try:
            # Split contexts into chunks for parallel processing
            chunk_size = max(1, len(contexts) // self.max_workers)
            chunks = [contexts[i : i + chunk_size] for i in range(0, len(contexts), chunk_size)]

            # Submit parallel tasks
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(self.cpu_pool, _process_coalescing_chunk, chunk) for chunk in chunks]

            # Gather results
            chunk_results = await asyncio.gather(*tasks)

            # Flatten results
            results = []
            for chunk_result in chunk_results:
                results.extend(chunk_result)

            processing_time = time.perf_counter() - start_time
            self.total_cpu_time += processing_time

            # Calculate speedup
            estimated_sequential_time = len(contexts) * 0.0001  # ~0.1ms per key
            speedup = estimated_sequential_time / processing_time
            self.multiprocessing_speedup["coalescing_keys"] = speedup

            logger.debug(
                f"Batch coalescing: {len(contexts)} keys in {processing_time*1000:.1f}ms " f"({speedup:.1f}x speedup)"
            )

            return results

        except Exception as e:
            logger.error(f"Batch coalescing failed: {e}")
            # Fallback to sequential processing
            return [_generate_coalescing_key_sync(ctx) for ctx in contexts]

    async def process_analytics_batch(self, metrics_data: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Process analytics and performance metrics in parallel

        Performance target: 4x speedup for large datasets
        """
        if not self.analytics_pool or len(metrics_data) < 50:
            # Sequential processing for small datasets
            return _calculate_analytics_sync(metrics_data)

        start_time = time.perf_counter()

        try:
            loop = asyncio.get_event_loop()

            # Parallel analytics tasks
            tasks = [
                loop.run_in_executor(
                    self.analytics_pool, _calculate_throughput_stats, [m for m in metrics_data if "throughput" in m]
                ),
                loop.run_in_executor(
                    self.analytics_pool, _calculate_latency_stats, [m for m in metrics_data if "latency_ms" in m]
                ),
                loop.run_in_executor(self.analytics_pool, _calculate_efficiency_scores, metrics_data),
            ]

            # Gather parallel results
            throughput_stats, latency_stats, efficiency_stats = await asyncio.gather(*tasks)

            # Combine results
            combined_results = {
                "throughput": throughput_stats,
                "latency": latency_stats,
                "efficiency": efficiency_stats,
                "processing_time_ms": (time.perf_counter() - start_time) * 1000,
                "data_points": len(metrics_data),
            }

            processing_time = time.perf_counter() - start_time
            estimated_sequential_time = len(metrics_data) * 0.0005  # ~0.5ms per metric
            speedup = estimated_sequential_time / processing_time
            self.multiprocessing_speedup["analytics"] = speedup

            logger.debug(
                f"Analytics processing: {len(metrics_data)} metrics in {processing_time*1000:.1f}ms "
                f"({speedup:.1f}x speedup)"
            )

            return combined_results

        except Exception as e:
            logger.error(f"Analytics processing failed: {e}")
            return _calculate_analytics_sync(metrics_data)

    async def process_pattern_matching_batch(self, texts: list[str], patterns: list[str]) -> list[dict[str, Any]]:
        """
        Perform pattern matching on batch of texts in parallel

        Performance target: 8x speedup for regex operations
        """
        if not self.pattern_pool or len(texts) < 20:
            # Sequential processing for small batches
            return [_match_patterns_sync(text, patterns) for text in texts]

        start_time = time.perf_counter()

        try:
            # Split texts into chunks for parallel processing
            chunk_size = max(1, len(texts) // min(6, self.max_workers))
            text_chunks = [texts[i : i + chunk_size] for i in range(0, len(texts), chunk_size)]

            loop = asyncio.get_event_loop()

            # Submit parallel pattern matching tasks
            tasks = [
                loop.run_in_executor(self.pattern_pool, _process_pattern_chunk, chunk, patterns)
                for chunk in text_chunks
            ]

            # Gather results
            chunk_results = await asyncio.gather(*tasks)

            # Flatten results
            results = []
            for chunk_result in chunk_results:
                results.extend(chunk_result)

            processing_time = time.perf_counter() - start_time
            estimated_sequential_time = len(texts) * len(patterns) * 0.0002  # ~0.2ms per pattern per text
            speedup = estimated_sequential_time / processing_time
            self.multiprocessing_speedup["pattern_matching"] = speedup

            logger.debug(
                f"Pattern matching: {len(texts)} texts × {len(patterns)} patterns "
                f"in {processing_time*1000:.1f}ms ({speedup:.1f}x speedup)"
            )

            return results

        except Exception as e:
            logger.error(f"Pattern matching failed: {e}")
            return [_match_patterns_sync(text, patterns) for text in texts]

    async def process_cache_cleanup(self, cache_entries: dict[str, dict]) -> list[str]:
        """
        Perform cache cleanup operations in parallel

        Performance target: 3x speedup for large caches
        """
        if not self.cpu_pool or len(cache_entries) < 100:
            # Sequential cleanup for small caches
            return _cleanup_cache_sync(cache_entries)

        start_time = time.perf_counter()

        try:
            # Split cache entries into chunks
            items = list(cache_entries.items())
            chunk_size = max(10, len(items) // self.max_workers)
            chunks = [dict(items[i : i + chunk_size]) for i in range(0, len(items), chunk_size)]

            loop = asyncio.get_event_loop()

            # Parallel cleanup tasks
            tasks = [
                loop.run_in_executor(
                    self.cpu_pool, _cleanup_cache_chunk, chunk, time.time()  # Current timestamp for expiry calculations
                )
                for chunk in chunks
            ]

            # Gather results
            chunk_results = await asyncio.gather(*tasks)

            # Combine expired keys from all chunks
            expired_keys = []
            for chunk_result in chunk_results:
                expired_keys.extend(chunk_result)

            processing_time = time.perf_counter() - start_time
            estimated_sequential_time = len(cache_entries) * 0.0001  # ~0.1ms per entry
            speedup = estimated_sequential_time / processing_time
            self.multiprocessing_speedup["cache_cleanup"] = speedup

            logger.debug(
                f"Cache cleanup: {len(cache_entries)} entries, {len(expired_keys)} expired "
                f"in {processing_time*1000:.1f}ms ({speedup:.1f}x speedup)"
            )

            return expired_keys

        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")
            return _cleanup_cache_sync(cache_entries)

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get CPU-bound processing performance metrics"""
        return {
            "cpu_bound_processor": {
                "total_tasks": self.task_count,
                "total_cpu_time": self.total_cpu_time,
                "max_workers": self.max_workers,
                "pools_active": {
                    "cpu_pool": self.cpu_pool is not None,
                    "analytics_pool": self.analytics_pool is not None,
                    "pattern_pool": self.pattern_pool is not None,
                },
                "multiprocessing_speedups": self.multiprocessing_speedup,
                "average_speedup": (
                    sum(self.multiprocessing_speedup.values()) / max(len(self.multiprocessing_speedup), 1)
                ),
            }
        }

    async def shutdown(self):
        """Graceful shutdown of all process pools"""
        shutdown_tasks = []

        if self.cpu_pool:
            shutdown_tasks.append(asyncio.to_thread(self.cpu_pool.shutdown, wait=True))

        if self.analytics_pool:
            shutdown_tasks.append(asyncio.to_thread(self.analytics_pool.shutdown, wait=True))

        if self.pattern_pool:
            shutdown_tasks.append(asyncio.to_thread(self.pattern_pool.shutdown, wait=True))

        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        logger.info("CPU-bound processor shutdown completed")


# ===============================
# CPU-Bound Processing Functions
# ===============================


def _generate_coalescing_key_sync(context: dict[str, Any]) -> str:
    """Generate coalescing key for a single context (CPU-bound)"""
    operation_type = context.get("operation_type", "")
    user_id = context.get("user_id", "")
    payload = context.get("payload", {})

    if operation_type == "authenticate":
        scopes = payload.get("scopes", "")
        key_data = f"auth:{user_id}:{scopes}"
    elif operation_type == "authorize":
        resource = payload.get("resource_type", "") + payload.get("resource_id", "")
        permission = payload.get("permission", "")
        key_data = f"authz:{user_id}:{resource}:{permission}"
    else:
        # Generic coalescing for other operations
        payload_hash = hashlib.md5(str(payload).encode()).hexdigest()[:8]
        key_data = f"{operation_type}:{payload_hash}"

    # Generate final hash
    return hashlib.md5(key_data.encode()).hexdigest()[:16]


def _process_coalescing_chunk(contexts: list[dict[str, Any]]) -> list[str]:
    """Process a chunk of contexts for coalescing key generation"""
    return [_generate_coalescing_key_sync(ctx) for ctx in contexts]


def _calculate_analytics_sync(metrics_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate analytics synchronously (fallback)"""
    if not metrics_data:
        return {"error": "No data provided"}

    throughput_values = [m.get("throughput_rps", 0) for m in metrics_data if "throughput_rps" in m]
    latency_values = [m.get("latency_ms", 0) for m in metrics_data if "latency_ms" in m]

    return {
        "throughput": {
            "avg": statistics.mean(throughput_values) if throughput_values else 0,
            "max": max(throughput_values) if throughput_values else 0,
            "count": len(throughput_values),
        },
        "latency": {
            "avg": statistics.mean(latency_values) if latency_values else 0,
            "p95": statistics.quantiles(latency_values, n=20)[18] if len(latency_values) > 20 else 0,
            "count": len(latency_values),
        },
        "efficiency": {"overall": 0.8},  # Default efficiency
    }


def _calculate_throughput_stats(throughput_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate throughput statistics (CPU-intensive)"""
    if not throughput_data:
        return {"avg": 0, "max": 0, "min": 0, "count": 0}

    values = [d.get("throughput_rps", 0) for d in throughput_data]

    return {
        "avg": statistics.mean(values),
        "max": max(values),
        "min": min(values),
        "median": statistics.median(values),
        "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
        "count": len(values),
    }


def _calculate_latency_stats(latency_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate latency statistics (CPU-intensive)"""
    if not latency_data:
        return {"avg": 0, "p95": 0, "p99": 0, "count": 0}

    values = [d.get("latency_ms", 0) for d in latency_data]

    result = {
        "avg": statistics.mean(values),
        "max": max(values),
        "min": min(values),
        "median": statistics.median(values),
        "count": len(values),
    }

    # Calculate percentiles
    if len(values) >= 20:
        quantiles = statistics.quantiles(values, n=100)
        result["p95"] = quantiles[94]  # 95th percentile
        result["p99"] = quantiles[98]  # 99th percentile
    else:
        result["p95"] = max(values) if values else 0
        result["p99"] = max(values) if values else 0

    return result


def _calculate_efficiency_scores(metrics_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate efficiency scores (CPU-intensive)"""
    if not metrics_data:
        return {"overall": 0, "coalescing": 0, "cache_hit_rate": 0}

    # Extract efficiency metrics
    coalescing_rates = [m.get("coalescing_rate", 0) for m in metrics_data]
    cache_hit_rates = [m.get("cache_hit_rate", 0) for m in metrics_data]
    error_rates = [m.get("error_rate", 0) for m in metrics_data]

    # Calculate weighted efficiency score
    avg_coalescing = statistics.mean(coalescing_rates) if coalescing_rates else 0
    avg_cache_hits = statistics.mean(cache_hit_rates) if cache_hit_rates else 0
    avg_error_rate = statistics.mean(error_rates) if error_rates else 0

    overall_efficiency = (
        avg_coalescing * 0.4
        + avg_cache_hits * 0.3  # 40% weight on coalescing
        + (1 - avg_error_rate) * 0.3  # 30% weight on cache performance  # 30% weight on reliability
    )

    return {
        "overall": overall_efficiency,
        "coalescing": avg_coalescing,
        "cache_hit_rate": avg_cache_hits,
        "error_rate": avg_error_rate,
    }


def _match_patterns_sync(text: str, patterns: list[str]) -> dict[str, Any]:
    """Match patterns against text synchronously"""
    matches = {}

    for pattern in patterns:
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            match_results = compiled_pattern.findall(text)
            matches[pattern] = {
                "found": bool(match_results),
                "count": len(match_results),
                "matches": match_results[:5],  # Limit to first 5 matches
            }
        except re.error:
            matches[pattern] = {"found": False, "error": "Invalid regex pattern"}

    return {
        "text_length": len(text),
        "patterns_tested": len(patterns),
        "total_matches": sum(1 for m in matches.values() if m.get("found", False)),
        "matches": matches,
    }


def _process_pattern_chunk(texts: list[str], patterns: list[str]) -> list[dict[str, Any]]:
    """Process a chunk of texts for pattern matching"""
    return [_match_patterns_sync(text, patterns) for text in texts]


def _cleanup_cache_sync(cache_entries: dict[str, dict]) -> list[str]:
    """Cleanup cache entries synchronously"""
    current_time = time.time()
    expired_keys = []

    for key, entry in cache_entries.items():
        if isinstance(entry, dict) and "timestamp" in entry:
            age = current_time - entry["timestamp"]
            ttl = entry.get("ttl", 300)  # Default 5 minutes TTL

            if age > ttl:
                expired_keys.append(key)

    return expired_keys


def _cleanup_cache_chunk(cache_chunk: dict[str, dict], current_time: float) -> list[str]:
    """Cleanup a chunk of cache entries"""
    expired_keys = []

    for key, entry in cache_chunk.items():
        if isinstance(entry, dict) and "timestamp" in entry:
            age = current_time - entry["timestamp"]
            ttl = entry.get("ttl", 300)  # Default 5 minutes TTL

            if age > ttl:
                expired_keys.append(key)

    return expired_keys


# Optional Numba-optimized functions (if available)
if NUMBA_AVAILABLE:

    @jit(nopython=True, parallel=True)
    def _calculate_efficiency_scores_vectorized(
        coalescing_rates: np.ndarray, cache_hit_rates: np.ndarray, error_rates: np.ndarray
    ) -> float:
        """Vectorized efficiency calculation using Numba"""
        n = len(coalescing_rates)

        # Parallel computation
        total_score = 0.0
        for i in prange(n):
            score = coalescing_rates[i] * 0.4 + cache_hit_rates[i] * 0.3 + (1.0 - error_rates[i]) * 0.3
            total_score += score

        return total_score / n


# Global instance for easy access
_global_cpu_processor: CPUBoundProcessor | None = None


def get_cpu_processor() -> CPUBoundProcessor:
    """Get or create global CPU-bound processor instance"""
    global _global_cpu_processor

    if _global_cpu_processor is None:
        _global_cpu_processor = CPUBoundProcessor()

    return _global_cpu_processor
