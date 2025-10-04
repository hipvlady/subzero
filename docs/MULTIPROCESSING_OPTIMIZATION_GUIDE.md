# Multiprocessing Optimization Guide

## Executive Summary

**TL;DR:** Don't use multiprocessing for lightweight operations. The 100ms overhead makes it slower than sequential processing for operations under 300ms total time.

## Performance Analysis

### Multiprocessing Overhead

| Component | Cost | Impact |
|-----------|------|--------|
| Process startup | 50-100ms | Per-operation overhead |
| IPC serialization | 10-50ms | Data transfer cost |
| Process pool warmup | 100-200ms | One-time initialization |
| **Total overhead** | **~100ms minimum** | **Per multiprocessing call** |

### Operation Cost Analysis

| Operation Type | Time per item | Break-even batch size | Recommendation |
|---------------|---------------|----------------------|----------------|
| Hash (SHA256) | 1-2 µs | Never beneficial | ❌ Sequential only |
| Analytics calculation | <1 ms/batch | Never beneficial | ❌ Sequential only |
| Pattern matching (10 patterns) | ~1 ms/text | ~300 texts | ⚠️ Sequential for <300 |
| Cache cleanup | ~1 µs/entry | Never beneficial | ❌ Sequential only |
| JWT validation | ~500 µs | Never beneficial | ❌ Sequential only |
| Complex numerical (JIT) | 10-100 ms | Always beneficial | ✅ Use multiprocessing |

## Decision Framework

### Rule 1: Calculate Total Operation Time

```python
total_time_ms = batch_size * operation_cost_per_item_ms
```

### Rule 2: Apply 3x Overhead Threshold

```python
MULTIPROCESSING_OVERHEAD_MS = 100
MIN_OPERATION_TIME = MULTIPROCESSING_OVERHEAD_MS * 3  # 300ms

if total_time_ms > MIN_OPERATION_TIME:
    use_multiprocessing()
else:
    use_sequential()
```

### Rule 3: Known Operation Costs

```python
OPERATION_COSTS = {
    "hash_sha256": 0.002,      # 2 µs - NEVER use MP
    "hash_blake2b": 0.001,     # 1 µs - NEVER use MP
    "analytics": 0.01,          # 10 µs - NEVER use MP
    "pattern_match": 0.1,       # 100 µs per pattern - MP for >3000 texts
    "cache_cleanup": 0.001,     # 1 µs - NEVER use MP
    "jwt_validate": 0.5,        # 500 µs - MP for >600 tokens
    "jit_risk_scoring": 0.001,  # 1 µs (post-warmup) - NEVER use MP
    "complex_numerical": 50,    # 50 ms - ALWAYS use MP
}
```

## Implementation Pattern

### ✅ Correct Implementation

```python
from subzero.config.defaults import settings

class IntelligentProcessor:
    def _should_use_multiprocessing(
        self,
        batch_size: int,
        operation_cost_ms: float
    ) -> bool:
        """
        Intelligent multiprocessing decision

        Args:
            batch_size: Number of items to process
            operation_cost_ms: Cost per item in milliseconds

        Returns:
            True if multiprocessing is beneficial
        """
        if not settings.ENABLE_MULTIPROCESSING:
            return False

        # Calculate total operation time
        total_time_ms = batch_size * operation_cost_ms

        # Multiprocessing overhead (process startup, IPC, serialization)
        OVERHEAD_MS = 100

        # Only use MP if benefit > 3x overhead (300ms threshold)
        return total_time_ms > (OVERHEAD_MS * 3)

    async def process_batch(self, items: list):
        """Process items with intelligent MP decision"""
        # Hash operations are ~2µs each - never use MP
        if not self._should_use_multiprocessing(len(items), 0.002):
            return self._process_sequential(items)

        # Use multiprocessing for large batches
        return await self._process_parallel(items)
```

### ❌ Incorrect Implementation

```python
# BAD: Always uses multiprocessing
async def process_batch(self, items: list):
    return await loop.run_in_executor(
        self.executor,
        worker_function,
        items
    )

# Result: 100ms overhead for 2µs operation = 50,000x slower!
```

## Real-World Examples

### Example 1: Hash Operations

```python
# Benchmark results:
# - Sequential: 2µs/hash = 2ms for 1000 hashes
# - Multiprocessing: 100ms overhead + 2ms = 102ms
# - Verdict: Sequential is 51x FASTER

# ✅ Correct
if len(hashes) * 0.002 < 300:  # 2µs per hash
    return [hashlib.sha256(x).digest() for x in data]
else:
    # This branch will NEVER execute for reasonable batch sizes
    # Would need 150,000 hashes to break even!
    pass
```

### Example 2: Analytics Calculations

```python
# Benchmark results:
# - Sequential: 10µs/calculation = 10ms for 1000 items
# - Multiprocessing: 100ms overhead + 10ms = 110ms
# - Verdict: Sequential is 11x FASTER

# ✅ Correct
def compute_analytics(data: list[dict]) -> dict:
    # Simple statistics - too fast for MP
    return {
        "count": len(data),
        "sum": sum(d["value"] for d in data),
        "avg": statistics.mean(d["value"] for d in data)
    }
```

### Example 3: Complex Numerical Operations (When MP Helps)

```python
# Benchmark results:
# - Sequential: 50ms/computation = 500ms for 10 items
# - Multiprocessing: 100ms overhead + 125ms (4-core) = 225ms
# - Verdict: Multiprocessing is 2.2x FASTER

# ✅ Correct - operation is genuinely CPU-intensive
if len(items) * 50 > 300:  # 50ms per item
    return await self._process_parallel(items)
```

## Configuration

### Environment Variables

```bash
# Enable/disable multiprocessing globally
ENABLE_MULTIPROCESSING=true

# Minimum batch size (legacy - use cost-based threshold instead)
BATCH_SIZE_THRESHOLD=10
```

### Recommended Settings

```python
# settings.py
ENABLE_MULTIPROCESSING = True

# Operation-specific thresholds
MP_THRESHOLDS = {
    "hash": float('inf'),          # Never use MP
    "analytics": float('inf'),     # Never use MP
    "pattern_match": 3000,         # Use MP for >3000 texts
    "jwt_validation": 600,         # Use MP for >600 tokens
    "numerical": 1,                # Always use MP (even 1 item)
}
```

## Monitoring & Debugging

### Add Logging

```python
def _should_use_multiprocessing(self, batch_size, cost_ms):
    total_ms = batch_size * cost_ms
    use_mp = total_ms > 300

    if settings.DEBUG_MULTIPROCESSING:
        print(f"MP Decision: batch={batch_size}, "
              f"cost={cost_ms}ms, total={total_ms}ms, "
              f"decision={'MP' if use_mp else 'Sequential'}")

    return use_mp
```

### Performance Metrics

```python
class ProcessorMetrics:
    def __init__(self):
        self.mp_calls = 0
        self.sequential_calls = 0
        self.mp_time = 0.0
        self.sequential_time = 0.0

    def report(self):
        return {
            "mp_calls": self.mp_calls,
            "sequential_calls": self.sequential_calls,
            "mp_avg_time": self.mp_time / max(self.mp_calls, 1),
            "sequential_avg_time": self.sequential_time / max(self.sequential_calls, 1),
            "mp_percentage": self.mp_calls / (self.mp_calls + self.sequential_calls) * 100
        }
```

## Testing Guidelines

### Benchmark Template

```python
def test_mp_decision():
    """Test that MP is only used when beneficial"""
    processor = IntelligentProcessor()

    # Small batch - should use sequential
    small_batch = list(range(100))
    start = time.perf_counter()
    result = await processor.process_batch(small_batch)
    time_small = time.perf_counter() - start

    # Large batch - may use MP if operation is expensive
    large_batch = list(range(10000))
    start = time.perf_counter()
    result = await processor.process_batch(large_batch)
    time_large = time.perf_counter() - start

    # For lightweight operations, sequential should always be faster
    if processor.operation_cost_ms < 0.01:  # <10µs
        assert time_small < 50, "Small batch took >50ms (MP overhead detected)"
        assert time_large < 500, "Large batch too slow"
```

## Common Pitfalls

### ❌ Pitfall 1: "More CPUs = Faster"

```python
# WRONG: Assumes parallelism always helps
ProcessPoolExecutor(max_workers=cpu_count())

# The overhead can make it 100x SLOWER for lightweight operations!
```

### ❌ Pitfall 2: Ignoring Serialization Cost

```python
# WRONG: Large data structures have high serialization cost
await executor.run(heavy_function, massive_dataframe)

# Serialization alone can add 100-500ms overhead
```

### ❌ Pitfall 3: Not Measuring Operation Cost

```python
# WRONG: Guessing that operation is "heavy"
if len(batch) > 100:
    use_multiprocessing()

# CORRECT: Measure actual operation cost
operation_time = benchmark_single_operation()
if len(batch) * operation_time > 300:
    use_multiprocessing()
```

## Summary: When to Use Multiprocessing

### ✅ Use Multiprocessing When:
- Operation cost per item > 50ms
- Total batch time > 300ms
- Operation is truly CPU-bound (not I/O)
- Data serialization cost is low

### ❌ Don't Use Multiprocessing When:
- Operation cost < 10ms per item
- Total batch time < 300ms
- Operation involves I/O (use async instead)
- Data structures are large (high serialization cost)

### 📊 Quick Reference

| Batch Size | Operation Cost | Total Time | Decision |
|------------|---------------|------------|----------|
| 1,000 | 2µs (hash) | 2ms | ❌ Sequential (51x faster) |
| 1,000 | 10µs (analytics) | 10ms | ❌ Sequential (11x faster) |
| 1,000 | 1ms (pattern) | 1,000ms | ✅ MP (2-4x faster) |
| 10 | 50ms (numerical) | 500ms | ✅ MP (2-4x faster) |

## Implementation Checklist

- [ ] Calculate operation cost per item
- [ ] Implement `_should_use_multiprocessing()` with 300ms threshold
- [ ] Add operation cost to all MP calls
- [ ] Enable `ENABLE_MULTIPROCESSING` setting check
- [ ] Add logging for MP decisions (debug mode)
- [ ] Benchmark sequential vs MP for your specific operations
- [ ] Update tests to verify intelligent thresholding
- [ ] Document operation costs in code comments

---

**Key Takeaway:** Multiprocessing has a ~100ms overhead. Only use it when total operation time exceeds 300ms (3x overhead). For operations like hashing, analytics, and small-batch processing, sequential is 10-100x faster.
