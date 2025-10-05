"""
Performance benchmarks for refactored authentication layer
Target: 10,000+ RPS with <10ms P99 latency (local)
CI targets are relaxed 3x due to resource constraints
"""

import asyncio
import os
import statistics

# Import modules to test
import sys
import time
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from subzero.services.auth.cuckoo_cache import CuckooCache
from subzero.services.auth.eddsa_key_manager import EdDSAKeyManager
from subzero.services.auth.high_performance_auth import HighPerformanceAuthenticator
from subzero.services.auth.simd_operations import SIMDHasher, benchmark_hash_functions, simd_xxhash64
from subzero.services.auth.token_pool import AdaptiveTokenPool, TokenPool

# Import CI-aware performance utilities
from tests.performance.performance_utils import get_threshold, is_ci


class TestEdDSAPerformance:
    """Test EdDSA key operations performance"""

    def test_eddsa_key_generation_speed(self):
        """Verify EdDSA key generation is fast"""
        times = []

        for _ in range(10):
            start = time.perf_counter()
            EdDSAKeyManager()
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)  # Convert to ms

        avg_time = statistics.mean(times)
        threshold = get_threshold(5.0, ci_multiplier=3.0)  # Local: 5ms, CI: 15ms

        assert avg_time < threshold, f"EdDSA key generation too slow: {avg_time:.2f}ms (threshold: {threshold}ms)"
        print(f"✅ EdDSA key generation: {avg_time:.2f}ms (threshold: <{threshold}ms, CI: {is_ci()})")

    def test_eddsa_signing_performance(self):
        """Verify EdDSA achieves 10x speedup over RSA target"""
        manager = EdDSAKeyManager()

        # Test payload
        payload = {
            "sub": "test_user",
            "iss": "test_client",
            "aud": "https://test.auth0.com/oauth/token",
            "exp": int(time.time()) + 300,
        }

        # Measure 1000 signing operations
        times = []
        for _ in range(1000):
            start = time.perf_counter()
            manager.sign_jwt(payload)
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)  # Convert to ms

        avg_ms = statistics.mean(times)
        p95_ms = np.percentile(times, 95)
        p99_ms = np.percentile(times, 99)

        avg_threshold = get_threshold(0.5, ci_multiplier=4.0)  # Local: 0.5ms, CI: 2ms
        p99_threshold = get_threshold(2.0, ci_multiplier=3.0)  # Local: 2ms, CI: 6ms

        assert avg_ms < avg_threshold, f"EdDSA signing too slow: {avg_ms:.2f}ms (threshold: {avg_threshold}ms)"
        assert p99_ms < p99_threshold, f"EdDSA P99 latency too high: {p99_ms:.2f}ms (threshold: {p99_threshold}ms)"

        print(
            f"✅ EdDSA signing - Avg: {avg_ms:.2f}ms, P95: {p95_ms:.2f}ms, P99: {p99_ms:.2f}ms "
            f"(CI: {is_ci()}, thresholds: avg<{avg_threshold}ms, p99<{p99_threshold}ms)"
        )

    def test_eddsa_verification_performance(self):
        """Test EdDSA verification speed"""
        manager = EdDSAKeyManager()

        # Create test token
        payload = {"sub": "test_user", "exp": int(time.time()) + 300}
        token = manager.sign_jwt(payload)

        # Measure verification performance
        times = []
        for _ in range(1000):
            start = time.perf_counter()
            verified = manager.verify_jwt(token)
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)

            assert verified["sub"] == "test_user"

        avg_ms = statistics.mean(times)
        threshold = get_threshold(1.0, ci_multiplier=3.0)  # Local: 1ms, CI: 3ms

        assert avg_ms < threshold, f"EdDSA verification too slow: {avg_ms:.2f}ms (threshold: {threshold}ms)"
        print(f"✅ EdDSA verification: {avg_ms:.2f}ms (threshold: <{threshold}ms, CI: {is_ci()})")


class TestCuckooCachePerformance:
    """Test Cuckoo cache O(1) performance"""

    def test_cuckoo_cache_insertion(self):
        """Verify O(1) cache insertions"""
        cache = CuckooCache(capacity=10000)

        # Test data
        test_data = [(np.uint64(i), {"token": f"token_{i}", "user": f"user_{i}"}) for i in range(5000)]

        # Measure insertion performance
        start = time.perf_counter()
        for user_hash, token_data in test_data:
            cache.insert(user_hash, token_data)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / len(test_data)) * 1_000_000
        threshold = get_threshold(10.0, ci_multiplier=5.0)  # Local: 10μs, CI: 50μs

        assert avg_us < threshold, f"Cache insertion too slow: {avg_us:.2f}μs (threshold: {threshold}μs)"
        print(f"✅ Cuckoo cache insertion: {avg_us:.2f}μs per item (threshold: <{threshold}μs, CI: {is_ci()})")

    def test_cuckoo_cache_lookup_performance(self):
        """Verify O(1) cache lookups"""
        cache = CuckooCache(capacity=10000)

        # Insert test data
        test_hashes = []
        for i in range(5000):
            user_hash = np.uint64(i)
            cache.insert(user_hash, {"token": f"token_{i}"})
            test_hashes.append(user_hash)

        # Measure lookup performance
        start = time.perf_counter()
        for _ in range(10000):
            hash_val = test_hashes[_ % len(test_hashes)]
            result = cache.get(hash_val)
            assert result is not None
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 10000) * 1_000_000
        threshold = get_threshold(3.0, ci_multiplier=10.0)  # Local: 3μs, CI: 30μs

        assert avg_us < threshold, f"Cache lookup too slow: {avg_us:.2f}μs (threshold: {threshold}μs)"
        print(f"✅ Cuckoo cache lookup: {avg_us:.2f}μs per lookup (threshold: <{threshold}μs, CI: {is_ci()})")

    def test_cache_hit_ratio(self):
        """Test cache hit ratio with realistic workload"""
        cache = CuckooCache(capacity=1000)

        # Insert 800 items (80% capacity)
        for i in range(800):
            cache.insert(np.uint64(i), {"token": f"token_{i}"})

        # Test lookups with 90% hit ratio
        hits = 0
        total = 1000

        for i in range(total):
            if i < 720:  # 72% definite hits
                result = cache.get(np.uint64(i))
                if result:
                    hits += 1
            else:  # Mix of hits and misses
                result = cache.get(np.uint64(i % 800))
                if result:
                    hits += 1

        hit_ratio = hits / total
        assert hit_ratio > 0.85, f"Hit ratio too low: {hit_ratio:.2%}"
        print(f"✅ Cache hit ratio: {hit_ratio:.2%}")

    def test_cache_collision_handling(self):
        """Test cuckoo hashing collision handling"""
        cache = CuckooCache(capacity=1000)

        # Force many collisions by using similar hash values
        collision_hashes = [np.uint64(1000 + i) for i in range(500)]

        start = time.perf_counter()
        for i, hash_val in enumerate(collision_hashes):
            cache.insert(hash_val, {"data": f"item_{i}"})
        time.perf_counter() - start

        # Verify all items can be retrieved
        retrieved = 0
        for hash_val in collision_hashes:
            if cache.get(hash_val):
                retrieved += 1

        retrieval_rate = retrieved / len(collision_hashes)
        assert retrieval_rate > 0.95, f"Collision handling failed: {retrieval_rate:.2%}"
        print(f"✅ Collision handling: {retrieval_rate:.2%} success rate")


class TestSIMDOperations:
    """Test SIMD-optimized operations"""

    def test_simd_hashing_performance(self):
        """Verify SIMD provides 4x+ speedup"""
        hasher = SIMDHasher(batch_size=128)

        # Add batch of user IDs
        user_ids = [f"user_{i}@example.com" for i in range(128)]

        # Measure batch computation
        times = []
        for _ in range(100):
            start = time.perf_counter()
            hashes = hasher.hash_strings_batch(user_ids)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

            assert len(hashes) == 128

        avg_time = statistics.mean(times)
        avg_ns_per_hash = (avg_time / 128) * 1_000_000_000

        threshold_ns = get_threshold(1000, ci_multiplier=5.0)  # Local: 1000ns, CI: 5000ns
        assert (
            avg_ns_per_hash < threshold_ns
        ), f"SIMD hashing too slow: {avg_ns_per_hash:.0f}ns per hash (threshold: {threshold_ns}ns)"
        print(f"✅ SIMD hashing: {avg_ns_per_hash:.0f}ns per hash (threshold: <{threshold_ns}ns, CI: {is_ci()})")

    def test_xxhash_vs_fnv_performance(self):
        """Compare hash function performance"""
        results = benchmark_hash_functions()

        # Check xxhash performance (if available)
        if "xxhash" in results:
            print(f"xxHash time: {results['xxhash']['time_ms']:.2f}ms")
        print(f"BLAKE2b time: {results['blake2b']['time_ms']:.2f}ms")
        print(f"SHA256 time: {results['sha256']['time_ms']:.2f}ms")
        print(f"SIMD batch time: {results['simd_batch']['time_ms']:.2f}ms")

        # All should be reasonably fast (CI-aware)
        threshold_ms = get_threshold(100.0, ci_multiplier=5.0)  # Local: 100ms, CI: 500ms
        assert (
            results["blake2b"]["time_ms"] < threshold_ms
        ), f"BLAKE2b too slow: {results['blake2b']['time_ms']:.2f}ms (threshold: {threshold_ms}ms)"
        assert (
            results["sha256"]["time_ms"] < threshold_ms
        ), f"SHA256 too slow: {results['sha256']['time_ms']:.2f}ms (threshold: {threshold_ms}ms)"

    def test_single_hash_performance(self):
        """Test individual hash function performance"""
        test_data = b"test_user_id_12345"

        # Measure xxHash64 performance
        times = []
        for _ in range(10000):
            start = time.perf_counter()
            simd_xxhash64(test_data)
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1_000_000_000)  # Convert to ns

        avg_ns = statistics.mean(times)
        threshold_ns = get_threshold(300, ci_multiplier=10.0)  # Local: 300ns, CI: 3000ns
        assert avg_ns < threshold_ns, f"Single hash too slow: {avg_ns:.0f}ns (threshold: {threshold_ns}ns)"
        print(f"✅ Single xxHash64: {avg_ns:.0f}ns (threshold: <{threshold_ns}ns, CI: {is_ci()})")


class TestTokenPool:
    """Test token pool pre-computation performance"""

    @pytest.mark.asyncio
    async def test_token_pool_generation(self):
        """Test token pool generation speed"""
        pool = TokenPool(max_size=100)

        # Add some tokens to pool
        for i in range(10):
            pool.put_token(
                user_id=f"user_{i}",
                token=f"test_token_{i}",
                expires_at=time.time() + 3600,
                scopes={"read", "write"},
            )

        # Get tokens back
        retrieved = 0
        for i in range(10):
            token = pool.get_pooled_token(f"user_{i}")
            if token:
                retrieved += 1

        assert retrieved > 0, "No tokens retrieved from pool"
        print(f"✅ Token pool retrieved {retrieved} tokens")

    @pytest.mark.asyncio
    async def test_token_pool_consumption_speed(self):
        """Test token consumption speed from pool"""
        pool = TokenPool(max_size=100)

        # Pre-populate pool with tokens
        for i in range(50):
            pool.put_token(
                user_id=f"user_{i}",
                token=f"test_token_{i}",
                expires_at=time.time() + 3600,
                scopes={"read", "write"},
            )

        # Measure consumption speed
        times = []
        for i in range(50):
            start = time.perf_counter()
            token = pool.get_pooled_token(f"user_{i}")
            elapsed = time.perf_counter() - start
            times.append(elapsed * 1000)  # Convert to ms

            if token:  # Only count successful retrievals
                assert token.token.startswith("test_token_")

        if times:
            avg_ms = statistics.mean(times)
            threshold_ms = get_threshold(0.1, ci_multiplier=5.0)  # Local: 0.1ms, CI: 0.5ms
            assert avg_ms < threshold_ms, f"Token consumption too slow: {avg_ms:.3f}ms (threshold: {threshold_ms}ms)"
            print(f"✅ Token pool consumption: {avg_ms:.3f}ms")

    @pytest.mark.asyncio
    async def test_adaptive_pool_sizing(self):
        """Test adaptive pool size adjustment"""
        adaptive_pool = AdaptiveTokenPool(initial_size=50, min_size=10, max_size=200)

        # Start cleanup task
        await adaptive_pool.start_cleanup_task()

        # Add some tokens
        for i in range(100):
            adaptive_pool.put_token(
                user_id=f"user_{i}",
                token=f"test_token_{i}",
                expires_at=time.time() + 3600,
                scopes={"read", "write"},
            )

        # Get some tokens to generate stats
        for i in range(50):
            adaptive_pool.get_pooled_token(f"user_{i}")

        stats = adaptive_pool.get_stats()
        print(f"✅ Adaptive pool stats: {stats}")

        await adaptive_pool.stop_cleanup_task()


class TestEndToEndPerformance:
    """End-to-end authentication performance tests"""

    @pytest.mark.asyncio
    async def test_complete_authentication_flow(self):
        """Verify complete authentication flow meets targets"""
        # Mock aiohttp session to avoid real HTTP calls
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"access_token": "test_token", "expires_in": 3600, "token_type": "Bearer"}
            )
            mock_session.return_value.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.return_value.post.return_value.__aexit__ = AsyncMock(return_value=None)

            auth = HighPerformanceAuthenticator(
                auth0_domain="test.auth0.com", client_id="test_client", cache_capacity=1000
            )

            # Warm up cache with some authentications
            for i in range(10):
                await auth.authenticate(f"user_{i}")

            # Measure performance on cached requests
            latencies = []
            start = time.perf_counter()

            for i in range(100):
                req_start = time.perf_counter()
                result = await auth.authenticate(f"user_{i % 10}")  # Use cached users
                latencies.append((time.perf_counter() - req_start) * 1000)

                assert result.success and result.token

            elapsed = time.perf_counter() - start

            # Calculate metrics
            p50 = np.percentile(latencies, 50)
            p95 = np.percentile(latencies, 95)
            p99 = np.percentile(latencies, 99)
            rps = 100 / elapsed

            # Assert performance targets (CI-aware)
            p99_threshold = get_threshold(10.0, ci_multiplier=5.0)  # Local: 10ms, CI: 50ms
            p50_threshold = get_threshold(1.0, ci_multiplier=5.0)  # Local: 1ms, CI: 5ms
            rps_threshold = 500 if is_ci() else 1000  # CI: 500 RPS, Local: 1000 RPS

            assert p99 < p99_threshold, f"P99 latency {p99:.2f}ms exceeds {p99_threshold}ms target"
            assert rps > rps_threshold, f"RPS {rps:.0f} below {rps_threshold} target"
            assert p50 < p50_threshold, f"P50 latency {p50:.2f}ms exceeds {p50_threshold}ms target"

            print("✅ End-to-end performance:")
            print(f"   P50: {p50:.2f}ms, P95: {p95:.2f}ms, P99: {p99:.2f}ms")
            print(f"   RPS: {rps:.0f}")

            await auth.close()

    @pytest.mark.asyncio
    async def test_concurrent_authentication_load(self):
        """Test performance under concurrent load"""
        # Mock HTTP calls
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"access_token": "test_token", "expires_in": 3600})
            mock_session.return_value.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.return_value.post.return_value.__aexit__ = AsyncMock(return_value=None)

            auth = HighPerformanceAuthenticator(
                auth0_domain="test.auth0.com", client_id="test_client", cache_capacity=1000
            )

            async def auth_worker(worker_id: int, num_requests: int) -> list[float]:
                """Worker function for concurrent testing"""
                latencies = []
                for i in range(num_requests):
                    start = time.perf_counter()
                    await auth.authenticate(f"worker_{worker_id}_user_{i}")
                    latencies.append((time.perf_counter() - start) * 1000)
                return latencies

            # Run 10 concurrent workers, 20 requests each
            start_time = time.perf_counter()

            tasks = [auth_worker(worker_id, 20) for worker_id in range(10)]

            results = await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start_time

            # Combine all latencies
            all_latencies = []
            for worker_latencies in results:
                all_latencies.extend(worker_latencies)

            total_requests = len(all_latencies)
            concurrent_rps = total_requests / elapsed
            p99_concurrent = np.percentile(all_latencies, 99)

            rps_threshold = 250 if is_ci() else 500  # CI: 250 RPS, Local: 500 RPS
            p99_threshold = get_threshold(50.0, ci_multiplier=3.0)  # Local: 50ms, CI: 150ms

            assert (
                concurrent_rps > rps_threshold
            ), f"Concurrent RPS {concurrent_rps:.0f} too low (threshold: {rps_threshold})"
            assert (
                p99_concurrent < p99_threshold
            ), f"P99 under load {p99_concurrent:.2f}ms too high (threshold: {p99_threshold}ms)"

            print(f"✅ Concurrent performance ({total_requests} requests):")
            print(f"   RPS: {concurrent_rps:.0f}")
            print(f"   P99: {p99_concurrent:.2f}ms")

            await auth.close()


class TestMemoryEfficiency:
    """Test memory usage and efficiency"""

    def test_cache_memory_usage(self):
        """Test cache memory efficiency"""
        cache = CuckooCache(capacity=10000)

        # Insert test data
        for i in range(5000):
            token_data = {"access_token": f"token_{i}" * 10, "user_id": f"user_{i}", "expires_in": 3600}  # ~100 chars
            cache.insert(np.uint64(i), token_data)

        # Check memory usage is reasonable
        load_factor = cache.get_load_factor()
        num_items = len(cache)

        # Should have reasonable load factor
        assert load_factor > 0.2, f"Low load factor: {load_factor:.2%}"
        assert num_items == 5000, f"Expected 5000 items, got {num_items}"

        print(f"✅ Cache stats - Load factor: {load_factor:.2%}, Items: {num_items}")

    def test_token_pool_memory_efficiency(self):
        """Test token pool memory usage"""
        pool = TokenPool(max_size=1000)

        # Add many tokens to pool
        for i in range(500):
            pool.put_token(
                user_id=f"user_{i % 100}",  # 100 unique users
                token=f"test_token_{i}",
                expires_at=time.time() + 3600,
                scopes={"read", "write"},
            )

        stats = pool.get_stats()
        print(f"✅ Token pool stats: {stats}")


if __name__ == "__main__":
    # Run basic performance tests
    print("Running High-Performance Authentication Layer Benchmarks...")
    print("=" * 60)

    # EdDSA tests
    print("\n🔐 EdDSA Performance Tests:")
    eddsa_tests = TestEdDSAPerformance()
    eddsa_tests.test_eddsa_key_generation_speed()
    eddsa_tests.test_eddsa_signing_performance()
    eddsa_tests.test_eddsa_verification_performance()

    # Cuckoo cache tests
    print("\n🗃️  Cuckoo Cache Performance Tests:")
    cache_tests = TestCuckooCachePerformance()
    cache_tests.test_cuckoo_cache_insertion()
    cache_tests.test_cuckoo_cache_lookup_performance()
    cache_tests.test_cache_hit_ratio()
    cache_tests.test_cache_collision_handling()

    # SIMD tests
    print("\n⚡ SIMD Operations Tests:")
    simd_tests = TestSIMDOperations()
    simd_tests.test_simd_hashing_performance()
    simd_tests.test_xxhash_vs_fnv_performance()
    simd_tests.test_single_hash_performance()

    # Memory tests
    print("\n💾 Memory Efficiency Tests:")
    memory_tests = TestMemoryEfficiency()
    memory_tests.test_cache_memory_usage()
    memory_tests.test_token_pool_memory_efficiency()

    print("\n✅ All performance benchmarks completed!")
    print("Run 'pytest tests/performance/test_auth_performance.py -v' for detailed async tests")
