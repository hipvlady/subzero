<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Performance Tests

## Current Status (Updated: 2025-10-01)

### Working Tests ✅
- `test_config_performance.py` - Configuration loading benchmarks
  - Settings instantiation: ~1.9ms median
  - Attribute access: ~117ns (very fast)
  - Environment override: ~1.8ms median

### Tests Needing Migration 🔧
The following test files reference old module structures and have been temporarily disabled:
- `test_auth_performance.py` - References old `auth.*` modules
  - Needs migration to `subzero.services.auth.*`
  - Tests: EdDSA performance, Cuckoo cache, SIMD operations, token pools
- `test_multiprocessing_performance.py` - References old `auth.*` and `performance.*` modules
  - Needs migration to `subzero.services.auth.*` and `subzero.services.orchestrator.*`
  - Tests: JWT processing, hash computation, cache operations
- `test_cpu_bound_multiprocessing.py` - References old `src.performance.*` modules
  - Needs migration to `subzero.services.orchestrator.*`
  - Tests: CPU-bound operations, GIL contention, multiprocessing optimizations
- `test_orchestrator_performance.py` - References old `src.performance.*` modules
  - Needs migration to `subzero.services.orchestrator.*`
  - Tests: Event loop orchestration, request coalescing, circuit breakers

These tests were written before the package restructuring (src/ → subzero/) and are currently skipped with pytest.skip().

## Running Benchmarks

```bash
# Run all working performance tests
pytest tests/performance/test_config_performance.py -v

# Run only working tests (skip disabled ones)
pytest tests/performance/ -v -k "config"

# Run all unit tests
pytest tests/unit/ -v

# Generate benchmark comparison
pytest tests/performance/test_config_performance.py --benchmark-compare

# Save benchmark results
pytest tests/performance/test_config_performance.py --benchmark-save=baseline
```

## Latest Benchmark Results

### Configuration Performance (test_config_performance.py)
- **Settings instantiation**: ~1.9ms median (1.36s - 30.6s range)
- **Attribute access**: ~117ns median (100ns - 22.4μs range) ⚡
- **Environment override**: ~1.8ms median

The attribute access is extremely fast (~117 nanoseconds), while instantiation takes slightly longer due to environment variable parsing and validation.

## Migration TODO

### High Priority
- [ ] Migrate `test_orchestrator_performance.py` to use new orchestrator modules
  - Map `src.performance.functional_event_orchestrator` → `subzero.services.orchestrator.event_loop`
  - Verify RequestPriority enum exists or recreate
  - Update FunctionalEventOrchestrator imports

- [ ] Migrate `test_cpu_bound_multiprocessing.py` CPU-bound tests
  - Map `src.performance.cpu_bound_multiprocessing` → `subzero.services.orchestrator.multiprocessing`
  - Recreate CPUBoundProcessor if needed
  - Verify analytics, cache cleanup, pattern matching functions exist

### Medium Priority
- [ ] Migrate `test_auth_performance.py` authentication benchmarks
  - Map `auth.*` → `subzero.services.auth.*`
  - Verify EdDSA, Cuckoo cache, SIMD, token pool modules exist
  - May need to recreate some high-performance modules

- [ ] Migrate `test_multiprocessing_performance.py` multiprocessing tests
  - Update distributed cache, JWT processor, parallel hash imports
  - Map to new `subzero.services.auth.*` and `subzero.services.orchestrator.*`

### Future Enhancements
- [ ] Add benchmarks for newly implemented features:
  - Auth0 FGA permission checks (ReBAC)
  - MCP protocol transport performance
  - Threat detection performance
  - Rate limiting overhead
  - Audit logging performance

## Notes

All tests are configured with `pytest` markers. The disabled tests will show as "SKIPPED" in test results with the reason "Module needs to be migrated to new package structure".
