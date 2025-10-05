# CI/CD Segmentation Fault Fix

## Problem
The CI/CD pipeline was experiencing segmentation faults when running tests with pytest-xdist parallel execution. The issue occurred at ~1h 58m into the test run, causing the pipeline to hang indefinitely.

## Root Cause
The segfault was caused by **nested multiprocessing** conflicts:

1. **pytest-xdist** spawns worker processes for parallel test execution (`-n auto`)
2. **Performance tests** (`test_cpu_bound_multiprocessing.py`) use `ProcessPoolExecutor` internally
3. On Linux, the default `fork()` method for multiprocessing can cause issues when combined with pytest-xdist
4. This created a resource conflict resulting in segmentation faults

## Solution

### 1. Fixed Multiprocessing Start Method (tests/conftest.py)
Added platform-specific multiprocessing configuration to use `spawn` instead of `fork` on Linux:

```python
def pytest_configure(config):
    """Configure pytest markers and multiprocessing settings."""
    import sys
    import multiprocessing

    # Fix multiprocessing segfaults on Linux (CI environment)
    if sys.platform == "linux":
        try:
            multiprocessing.set_start_method("spawn", force=True)
        except RuntimeError:
            pass  # Method already set
```

**Why this works:**
- `fork()` copies the parent process memory, which can conflict with pytest-xdist's worker processes
- `spawn()` starts a fresh Python interpreter, avoiding memory conflicts
- Only applies on Linux where fork is the default (macOS/Windows already use spawn)

### 2. Separated Performance Tests (.github/workflows/ci.yml)
Moved performance tests to run **serially** (without pytest-xdist) to avoid nested multiprocessing:

```yaml
- name: Run comprehensive test suite
  run: |
    python -m pytest tests/ \
      --ignore=tests/performance/ \
      -n auto \  # Parallel execution for non-performance tests
      ...

- name: Run performance tests (no parallel execution)
  run: |
    python -m pytest tests/performance/ \
      --timeout=600 \  # No -n auto flag
      -v \
      --tb=short
```

### 3. Added Test Marker
Added `@pytest.mark.no_parallel` marker for tests that use multiprocessing internally:

```python
@pytest.mark.asyncio
@pytest.mark.no_parallel
async def test_gil_contention_demonstration():
    ...
```

## Files Modified
1. **tests/conftest.py** - Added multiprocessing configuration
2. **.github/workflows/ci.yml** - Separated performance tests from parallel runs
3. **tests/performance/test_cpu_bound_multiprocessing.py** - Added `no_parallel` marker

## Benefits
- ✅ Eliminates segmentation faults in CI/CD
- ✅ Maintains parallel execution for regular tests (faster)
- ✅ Runs performance tests safely in serial mode
- ✅ Platform-specific fix (only applies on Linux)
- ✅ No performance regression for non-performance tests

## Testing
To test locally:

```bash
# Run regular tests in parallel (should work)
pytest tests/ --ignore=tests/performance/ -n auto -v

# Run performance tests serially (should work)
pytest tests/performance/ -v

# Run all tests
pytest tests/ -v
```

## Expected CI/CD Behavior
- Regular tests: Run in parallel with pytest-xdist (~10-15 minutes)
- Performance tests: Run serially after regular tests (~5-10 minutes)
- Total time: ~20-25 minutes (down from 2+ hours with hangs)
- No more segmentation faults ✅

## References
- Python multiprocessing start methods: https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods
- pytest-xdist documentation: https://pytest-xdist.readthedocs.io/
- Issue: Segmentation fault at 1h 58m 32s into CI run
