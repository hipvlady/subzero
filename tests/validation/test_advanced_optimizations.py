"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Validation Tests for Advanced Performance Optimizations
Tests hierarchical timing wheels, work-stealing pool, adaptive batching, and B+ tree
"""

import asyncio
import time

import pytest


class TestTimingWheels:
    """Test hierarchical timing wheels for O(1) expiry"""

    @pytest.mark.asyncio
    async def test_basic_expiry(self):
        """Test basic expiry scheduling"""
        from subzero.services.cache.timing_wheels import HierarchicalTimingWheels

        wheels = HierarchicalTimingWheels()
        await wheels.start()

        # Track expired keys
        expired_keys = []

        def expiry_callback(key, data):
            expired_keys.append(key)

        # Schedule entries with short expiry
        current_time = time.time()
        wheels.schedule_expiry("key1", current_time + 0.1, expiry_callback)
        wheels.schedule_expiry("key2", current_time + 0.2, expiry_callback)
        wheels.schedule_expiry("key3", current_time + 0.3, expiry_callback)

        # Wait for expirations
        await asyncio.sleep(0.4)

        await wheels.stop()

        # Verify all keys expired
        assert len(expired_keys) == 3
        assert "key1" in expired_keys
        assert "key2" in expired_keys
        assert "key3" in expired_keys

        print(f"✅ Timing wheels: {len(expired_keys)} entries expired correctly")

    @pytest.mark.asyncio
    async def test_cancel_expiry(self):
        """Test canceling scheduled expiry"""
        from subzero.services.cache.timing_wheels import HierarchicalTimingWheels

        wheels = HierarchicalTimingWheels()
        await wheels.start()

        expired_keys = []

        def expiry_callback(key, data):
            expired_keys.append(key)

        # Schedule and cancel
        current_time = time.time()
        wheels.schedule_expiry("key1", current_time + 0.1, expiry_callback)
        wheels.schedule_expiry("key2", current_time + 0.2, expiry_callback)

        # Cancel key2
        wheels.cancel_expiry("key2")

        # Wait for expirations
        await asyncio.sleep(0.3)

        await wheels.stop()

        # Only key1 should expire
        assert len(expired_keys) == 1
        assert "key1" in expired_keys
        assert "key2" not in expired_keys

        print("✅ Timing wheels: Cancellation working correctly")

    @pytest.mark.asyncio
    async def test_performance(self):
        """Test timing wheel performance"""
        from subzero.services.cache.timing_wheels import HierarchicalTimingWheels

        wheels = HierarchicalTimingWheels()
        await wheels.start()

        # Schedule 10,000 entries
        start_time = time.time()
        current_time = time.time()

        for i in range(10000):
            wheels.schedule_expiry(f"key_{i}", current_time + 1.0 + (i * 0.001))

        schedule_duration_ms = (time.time() - start_time) * 1000

        await wheels.stop()

        # Should schedule 10k entries in < 100ms
        assert schedule_duration_ms < 100

        stats = wheels.get_stats()
        print(f"✅ Timing wheels: Scheduled 10,000 entries in {schedule_duration_ms:.2f}ms")
        print(f"   Active entries: {stats['metrics']['active_entries']}")


class TestWorkStealingPool:
    """Test work-stealing thread pool"""

    @pytest.mark.asyncio
    async def test_basic_execution(self):
        """Test basic task execution"""
        from subzero.services.concurrency.work_stealing import WorkStealingPool

        pool = WorkStealingPool(num_workers=4)
        await pool.start()

        # Submit tasks
        def compute(x):
            return x * x

        futures = [pool.submit(compute, i) for i in range(10)]

        # Wait for results
        results = []
        for future in futures:
            result = await asyncio.wrap_future(future)
            results.append(result)

        await pool.stop()

        # Verify results
        expected = [i * i for i in range(10)]
        assert results == expected

        print(f"✅ Work-stealing pool: {len(results)} tasks executed correctly")

    @pytest.mark.asyncio
    async def test_load_balancing(self):
        """Test work stealing and load balancing"""
        from subzero.services.concurrency.work_stealing import WorkStealingPool

        pool = WorkStealingPool(num_workers=4)
        await pool.start()

        # Submit 100 tasks with varying complexity
        async def async_compute(x):
            await asyncio.sleep(0.001 * (x % 10))
            return x * x

        futures = [pool.submit(async_compute, i) for i in range(100)]

        # Wait for all
        results = []
        for future in futures:
            result = await asyncio.wrap_future(future)
            results.append(result)

        stats = pool.get_stats()
        await pool.stop()

        # Check that work was distributed
        worker_stats = stats["workers"]
        tasks_per_worker = [w["stats"]["tasks_processed"] for w in worker_stats]

        print(f"✅ Work-stealing pool: Load balanced across {len(tasks_per_worker)} workers")
        print(f"   Tasks per worker: {tasks_per_worker}")
        print(f"   Total stolen: {sum(w['stats']['tasks_stolen'] for w in worker_stats)}")

        # Ensure at least some stealing occurred (indicates load balancing)
        total_stolen = sum(w["stats"]["tasks_stolen"] for w in worker_stats)
        assert total_stolen > 0


class TestAdaptiveBatching:
    """Test adaptive batching with ML optimization"""

    @pytest.mark.asyncio
    async def test_basic_batching(self):
        """Test basic batch processing"""
        from subzero.services.concurrency.adaptive_batching import AdaptiveBatcher

        processed_batches = []

        async def process_batch(items):
            processed_batches.append(len(items))
            await asyncio.sleep(0.01)

        batcher = AdaptiveBatcher(batch_processor=process_batch, min_batch_size=5, max_batch_size=20, max_wait_ms=50)

        await batcher.start()

        # Add items
        for i in range(25):
            await batcher.add(f"item_{i}")

        # Wait for processing
        await asyncio.sleep(0.2)

        await batcher.stop()

        # Verify batches were created
        assert len(processed_batches) > 0
        assert sum(processed_batches) == 25

        print(f"✅ Adaptive batching: Processed {sum(processed_batches)} items in {len(processed_batches)} batches")
        print(f"   Batch sizes: {processed_batches}")

    @pytest.mark.asyncio
    async def test_adaptive_sizing(self):
        """Test adaptive batch size adjustment"""
        from subzero.services.concurrency.adaptive_batching import AdaptiveBatcher

        async def process_batch(items):
            # Simulate variable processing time based on batch size
            await asyncio.sleep(0.001 * len(items))

        batcher = AdaptiveBatcher(
            batch_processor=process_batch,
            target_latency_ms=10.0,
            min_batch_size=1,
            max_batch_size=50,
            max_wait_ms=20,
        )

        await batcher.start()

        # Add many items to trigger adaptation
        for i in range(200):
            await batcher.add(f"item_{i}")
            await asyncio.sleep(0.001)

        await asyncio.sleep(0.3)

        stats = batcher.get_stats()
        await batcher.stop()

        # Check that batch size adapted
        initial_batch_size = 1
        final_batch_size = stats["stats"]["current_batch_size"]

        print(f"✅ Adaptive batching: Batch size adapted from {initial_batch_size} to {final_batch_size}")
        print(f"   Avg latency: {stats['stats']['avg_latency_ms']:.2f}ms")
        print(f"   Avg throughput: {stats['stats']['avg_throughput']:.0f} items/sec")

        # Batch size should have increased
        assert final_batch_size > initial_batch_size


class TestBPlusTreeIndex:
    """Test B+ tree indexing for permissions"""

    def test_basic_operations(self):
        """Test insert and search"""
        from subzero.services.cache.bplus_tree import BPlusTreeIndex

        index = BPlusTreeIndex(order=8)

        # Insert permissions
        index.insert(user_id=1, resource_id=100, permission="read", value=True)
        index.insert(user_id=1, resource_id=101, permission="write", value=True)
        index.insert(user_id=2, resource_id=100, permission="read", value=True)

        # Search
        perm1 = index.search(user_id=1, resource_id=100)
        assert perm1 is not None
        assert perm1.permission == "read"

        perm2 = index.search(user_id=1, resource_id=101)
        assert perm2 is not None
        assert perm2.permission == "write"

        # Non-existent
        perm3 = index.search(user_id=1, resource_id=999)
        assert perm3 is None

        print("✅ B+ tree: Basic operations working")

    def test_range_query(self):
        """Test range queries"""
        from subzero.services.cache.bplus_tree import BPlusTreeIndex

        index = BPlusTreeIndex(order=8)

        # Insert range of permissions
        for i in range(10):
            index.insert(user_id=1, resource_id=100 + i, permission=f"perm_{i}", value=True)

        # Range query
        results = index.range_query(user_id=1, resource_id_start=102, resource_id_end=105)

        # Should get resources 102, 103, 104, 105
        assert len(results) == 4
        resource_ids = [r.resource_id for r in results]
        assert sorted(resource_ids) == [102, 103, 104, 105]

        print(f"✅ B+ tree: Range query returned {len(results)} entries")

    def test_user_permissions(self):
        """Test getting all user permissions"""
        from subzero.services.cache.bplus_tree import BPlusTreeIndex

        index = BPlusTreeIndex(order=8)

        # Insert multiple users
        for user_id in [1, 2, 3]:
            for resource_id in range(5):
                index.insert(user_id=user_id, resource_id=resource_id, permission="read", value=True)

        # Get user 2's permissions
        user2_perms = index.user_permissions(user_id=2)

        assert len(user2_perms) == 5
        assert all(p.user_id == 2 for p in user2_perms)

        print(f"✅ B+ tree: Retrieved {len(user2_perms)} permissions for user")

    def test_performance(self):
        """Test index performance"""
        from subzero.services.cache.bplus_tree import BPlusTreeIndex

        index = BPlusTreeIndex(order=64)

        # Insert 10,000 permissions
        start_time = time.time()

        for i in range(10000):
            user_id = i // 100  # 100 users
            resource_id = i % 100  # 100 resources each
            index.insert(user_id=user_id, resource_id=resource_id, permission="read", value=True)

        insert_duration_ms = (time.time() - start_time) * 1000

        # Search performance
        start_time = time.time()
        for i in range(1000):
            index.search(user_id=i // 100, resource_id=i % 100)

        search_duration_ms = (time.time() - start_time) * 1000

        stats = index.get_stats()

        print(f"✅ B+ tree: Performance test")
        print(f"   10,000 insertions: {insert_duration_ms:.2f}ms")
        print(f"   1,000 searches: {search_duration_ms:.2f}ms")
        print(f"   Tree height: {stats['tree_height']}")

        # Should be reasonably fast
        assert insert_duration_ms < 500
        assert search_duration_ms < 100


class TestHierarchicalPermissionIndex:
    """Test hierarchical permission indexing"""

    def test_wildcard_matching(self):
        """Test wildcard permission matching"""
        from subzero.services.cache.bplus_tree import HierarchicalPermissionIndex

        index = HierarchicalPermissionIndex()

        # Grant permissions
        index.grant_permission(user_id=1, resource_id=1, permission="document.read")
        index.grant_permission(user_id=1, resource_id=2, permission="document.write")
        index.grant_permission(user_id=1, resource_id=3, permission="image.read")

        # Wildcard match
        doc_perms = index.wildcard_check(user_id=1, resource_pattern="document.*")

        assert len(doc_perms) == 2
        assert all("document" in p.permission for p in doc_perms)

        print(f"✅ Hierarchical index: Wildcard matched {len(doc_perms)} permissions")

    def test_bidirectional_lookup(self):
        """Test user->resource and resource->user lookups"""
        from subzero.services.cache.bplus_tree import HierarchicalPermissionIndex

        index = HierarchicalPermissionIndex()

        # Grant permissions
        index.grant_permission(user_id=1, resource_id=100, permission="read")
        index.grant_permission(user_id=2, resource_id=100, permission="read")
        index.grant_permission(user_id=3, resource_id=100, permission="write")

        # User's resources
        user1_perms = index.get_user_permissions(user_id=1)
        assert len(user1_perms) == 1

        # Resource's users
        resource100_users = index.get_resource_users(resource_id=100)
        assert len(resource100_users) == 3

        print(f"✅ Hierarchical index: Bidirectional lookup working")
        print(f"   User 1 permissions: {len(user1_perms)}")
        print(f"   Resource 100 users: {len(resource100_users)}")


class TestOrchestrationIntegration:
    """Test integration of new components with orchestrator"""

    @pytest.mark.asyncio
    async def test_all_components_registered(self):
        """Test that all new components are registered"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Check new components
        timing_wheels = await orchestrator.get_component("timing_wheels")
        work_pool = await orchestrator.get_component("work_stealing_pool")
        batcher = await orchestrator.get_component("adaptive_batcher")
        bplus_index = await orchestrator.get_component("bplus_tree_index")

        assert timing_wheels is not None
        assert work_pool is not None
        assert batcher is not None
        assert bplus_index is not None

        print("✅ Orchestration: All new components registered")

        # Check status
        status = await orchestrator.get_status()
        print(f"   Total components: {status['summary']['total']}")
        print(f"   Healthy: {status['summary']['healthy']}")

        await orchestrator.shutdown()

        assert status["summary"]["healthy"] >= 4  # At least 4 new components
