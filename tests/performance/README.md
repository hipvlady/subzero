# Performance Tests

## Current Status

### Working Tests
- `test_config_performance.py` - Configuration loading benchmarks ✅

### Legacy Tests (Outdated)
The following test files reference old module structures and need to be updated:
- `test_auth_performance.py` - References `auth.*` modules (now `subzero.services.auth.*`)
- `test_multiprocessing_performance.py` - References `auth.*` modules
- `test_cpu_bound_multiprocessing.py` - References `src.performance.*` modules
- `test_orchestrator_performance.py` - References `src.performance.*` modules

These tests were written before the package restructuring and need import path updates.

## Running Benchmarks

```bash
# Run all working performance tests
pytest tests/performance/test_config_performance.py --benchmark-only

# Generate JSON report
pytest tests/performance/test_config_performance.py --benchmark-only --benchmark-json=benchmark-results.json

# Compare benchmarks
pytest tests/performance/test_config_performance.py --benchmark-compare
```

## Benchmark Results (Latest)

Configuration performance benchmarks:
- Settings instantiation: ~1.0ms (938μs median)
- Attribute access: ~119ns (very fast)
- Environment override: ~1.0ms (940μs median)

## TODO

- [ ] Update legacy test imports to use `subzero.*` package structure
- [ ] Verify all referenced modules exist in new structure
- [ ] Add more comprehensive benchmarks for:
  - JWT token validation
  - Auth0 FGA permission checks
  - MCP transport performance
  - Cache operations