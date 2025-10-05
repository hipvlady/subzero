# CI/CD Workflow Documentation

## Overview

This directory contains GitHub Actions workflows for the Subzero Zero Trust API Gateway project. The CI/CD pipeline implements **automated test discovery** that finds and runs all tests in the `/tests/` directory without requiring hardcoded paths.

## Workflows

### Main CI/CD Pipeline (`ci.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Version tags (`v*`)
- Manual dispatch (workflow_dispatch)

## Automated Test Discovery

### How It Works

The test discovery system automatically finds and runs all tests in the `/tests/` directory using pytest's built-in discovery mechanism.

**Test Discovery Process:**

1. **Validation**: Confirms `/tests/` directory exists
2. **Structure Analysis**: Shows test directory organization
3. **File Discovery**: Finds all `test_*.py` files recursively
4. **Collection**: Uses pytest to collect all test items
5. **Execution**: Runs discovered tests with coverage
6. **Reporting**: Generates JUnit XML and HTML reports

### Test File Patterns

The system discovers test files matching these patterns:
- `test_*.py` - Standard pytest pattern
- Located anywhere under `/tests/` directory

### Test Categories

Tests are automatically categorized by directory:

```
tests/
├── unit/              # Unit tests (isolated)
├── integration/       # Integration tests
├── validation/        # Validation tests
├── performance/       # Performance benchmarks (separate job)
├── security/          # Security tests
└── [any new dir]/     # Automatically discovered
```

## Jobs

### 1. Lint (Code Quality & Linting)

**Purpose:** Ensures code quality and consistency

**Tools:**
- Black (formatting check)
- Ruff (linting)
- MyPy (type checking)

**When it runs:** On all pushes and PRs

### 2. Security (Security Scanning)

**Purpose:** Identifies security vulnerabilities

**Tools:**
- Safety (dependency vulnerabilities)
- Bandit (security linting)

**Artifacts:** `bandit-report.json`

### 3. Test (Automated Test Discovery & Execution)

**Purpose:** Discovers and runs all tests automatically

**Matrix Strategy:**
- Python versions: 3.11, 3.12
- OS: ubuntu-latest

**Steps:**

#### 3.1 Validate Test Directory Structure
Shows the test directory layout for transparency:
```bash
📊 Test directory structure:
tests
tests/integration
tests/performance
tests/unit
tests/validation
```

#### 3.2 Discover and Count All Tests
Automatically finds all test files:
```bash
🔍 Discovering all tests in tests/ directory...
Found 21 test files matching pattern: test_*.py
```

#### 3.3 Run Comprehensive Test Suite
Executes ALL discovered tests (except performance) with performance enhancements:
```bash
pytest tests/ \
  --ignore=tests/performance/ \
  -n auto \
  --reruns 2 \
  --reruns-delay 1 \
  --timeout=300 \
  -v --tb=short \
  --cov=subzero \
  --cov-report=xml \
  --cov-report=html \
  --junitxml=test-results.xml
```

**Key Features:**
- ✅ Automatic discovery of all test files
- ✅ No hardcoded paths needed
- ✅ **Parallel execution** (auto-detects CPU count for optimal performance)
- ✅ **Failed test retry** (2 attempts with 1s delay for flaky tests)
- ✅ **Timeout protection** (5 minutes per test to prevent hangs)
- ✅ Coverage reporting (XML + HTML)
- ✅ JUnit XML for test reporting
- ✅ GitHub Step Summary with statistics
- ✅ Flaky test detection and reporting

**Performance Benefits:**
- **2-4x faster** test execution via parallel processing
- **Higher reliability** through automatic retry of intermittent failures
- **Protection** against hanging tests with configurable timeouts

#### 3.4 Category-Specific Runs
Optionally runs tests by category (for clarity):
- Unit tests: `tests/unit/`
- Integration tests: `tests/integration/`

**Test Summary Output:**
```markdown
## 📊 Test Execution Summary
- Test Files Discovered: 21
- Test Items Collected: 156 items
- Python Version: 3.11
- Test Discovery: ✅ Automatic (all tests/ subdirectories)
- Coverage Report: Generated ✅
- JUnit Report: Generated ✅
```

**Artifacts Generated:**
- `test-results.xml` - JUnit test results
- `coverage.xml` - Codecov format
- `htmlcov/` - HTML coverage report

**Integrations:**
- Codecov (coverage tracking)
- Test Reporter (GitHub UI test results)

### 4. Benchmark (Performance Benchmarks)

**Purpose:** Runs performance benchmarks separately

**Discovery:**
```bash
🔍 Discovering performance tests...
Found 5 performance test files
```

**Execution:**
```bash
pytest tests/performance/ \
  --benchmark-only \
  --benchmark-json=benchmark-results.json
```

**Artifacts:** `benchmark-results.json` (90-day retention)

### 5. Build (Package Building)

**Purpose:** Builds Python package

**Dependencies:** `lint` and `test` jobs must pass

**Output:** `dist/` with wheel and sdist

### 6. Docker (Container Image)

**Purpose:** Builds Docker image

**Registry:** GitHub Container Registry (ghcr.io)

**Tags:**
- Branch name (e.g., `main`, `develop`)
- PR number (e.g., `pr-123`)
- Semver tags (e.g., `v1.2.3`, `1.2`)
- Commit SHA
- `latest` (for default branch)

### 7. Publish (PyPI Publishing)

**Trigger:** Only on version tags (`v*`)

**Requirements:** Needs `PYPI_API_TOKEN` secret

### 8. Release (GitHub Release)

**Trigger:** Only on version tags (`v*`)

**Content:** Extracted from `CHANGELOG.md`

## Running Tests Locally

### Discover All Tests
```bash
# See what tests would be discovered
pytest tests/ --collect-only -q

# Count test files
find tests/ -name "test_*.py" | wc -l
```

### Run All Tests (Matches CI)
```bash
# Run everything except performance (basic)
pytest tests/ --ignore=tests/performance/ -v --cov=subzero

# Run with CI enhancements (parallel + retry + timeout)
pytest tests/ \
  --ignore=tests/performance/ \
  -n auto \
  --reruns 2 \
  --reruns-delay 1 \
  --timeout=300 \
  --cov=subzero \
  --cov-report=term-missing \
  --cov-report=html

# Run with coverage reports only (no enhancements)
pytest tests/ \
  --ignore=tests/performance/ \
  --cov=subzero \
  --cov-report=term-missing \
  --cov-report=html
```

**Enhancement Flags Explained:**
- `-n auto`: Parallel execution using all available CPUs
- `--reruns 2`: Retry failed tests up to 2 times
- `--reruns-delay 1`: Wait 1 second between retries
- `--timeout=300`: Kill tests running longer than 5 minutes

### Run Specific Categories
```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# Validation tests only
pytest tests/validation/ -v

# Performance benchmarks
pytest tests/performance/ --benchmark-only
```

## Adding New Tests

### Simple: Just Add Test Files

1. Create test file in `/tests/` directory:
   ```python
   # tests/my_feature/test_new_feature.py
   def test_my_new_feature():
       assert True
   ```

2. Tests will be **automatically discovered** on next CI run

3. No workflow changes needed! ✅

### Test Categories

Choose the appropriate directory:

- **Unit Tests** → `tests/unit/`
  - Fast, isolated tests
  - Mock external dependencies

- **Integration Tests** → `tests/integration/`
  - Test component interactions
  - May use real services (with config)

- **Validation Tests** → `tests/validation/`
  - End-to-end validation
  - Feature verification

- **Performance Tests** → `tests/performance/`
  - Benchmark tests
  - Use `pytest-benchmark`

- **Security Tests** → `tests/security/`
  - Security-specific tests

### Test Markers

Use pytest markers for categorization:

```python
import pytest

@pytest.mark.unit
def test_fast_unit():
    pass

@pytest.mark.integration
def test_integration():
    pass

@pytest.mark.slow
def test_long_running():
    pass
```

## Troubleshooting

### Tests Not Discovered

**Check:**
1. File naming: Must be `test_*.py`
2. Location: Must be under `tests/` directory
3. Syntax: File must be valid Python
4. Imports: All imports must be available

**Debug locally:**
```bash
pytest tests/ --collect-only -v
```

### Tests Not Running in CI

**Check workflow logs for:**
1. "Validate test directory structure" - Shows discovered directories
2. "Discover and count all tests" - Shows test file count
3. Test execution output - Shows actual pytest run

### Coverage Issues

**Ensure:**
- `--cov=subzero` includes your module
- Test files are not in coverage (auto-excluded)
- Source files are in `subzero/` directory

### Performance Test Issues

Performance tests run in a **separate job** with `continue-on-error: true`.

If benchmarks fail, they won't break the build.

## Configuration Files

### Pytest Configuration (`pyproject.toml`)
```toml
[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
asyncio_mode = "auto"
markers = [
    "slow: marks tests as slow",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
    "performance: marks tests as performance tests",
]
```

### Coverage Configuration (`pyproject.toml`)
```toml
[tool.coverage.run]
source = ["subzero"]
omit = ["*/tests/*"]
```

## Workflow Maintenance

### Adding New Python Versions

Update the matrix in `ci.yml`:
```yaml
strategy:
  matrix:
    python-version: ['3.11', '3.12', '3.13']  # Add new version
```

### Changing Test Discovery Behavior

The main test discovery command is:
```bash
python -m pytest tests/ \
  --ignore=tests/performance/ \
  -n auto \
  --reruns 2 \
  --reruns-delay 1 \
  --timeout=300 \
  -v --tb=short \
  --cov=subzero
```

Modify parameters as needed:
- Add `--ignore=tests/slow/` to skip directories
- Change `-v` to `-vv` for more verbosity
- Add `--maxfail=3` to stop after N failures
- Change `-n auto` to `-n 4` to use specific CPU count
- Adjust `--reruns 2` to change retry attempts
- Modify `--timeout=300` to change per-test timeout (seconds)
- Remove parallel/retry/timeout flags if not needed

### Environment Variables

Available in all jobs:
- `PYTHON_VERSION`: Default Python version (3.11)
- `GITHUB_SHA`: Commit SHA
- `GITHUB_REF`: Git ref
- `GITHUB_REPOSITORY`: Repository name

## Best Practices

### ✅ DO

- Write tests following `test_*.py` naming
- Place tests in appropriate category directories
- Use pytest markers for test categorization
- Keep tests independent and idempotent
- Mock external dependencies in unit tests
- Document complex test scenarios

### ❌ DON'T

- Hardcode test paths in workflows (use discovery)
- Commit large test fixtures (use `tests/resources/`)
- Write tests that depend on execution order
- Mix unit and integration tests in same file
- Skip test documentation

## Success Criteria

The workflow is working correctly when:

- ✅ All tests in `/tests/` are discovered automatically
- ✅ Test count is displayed in workflow logs
- ✅ Coverage reports are generated
- ✅ JUnit XML is uploaded for GitHub UI
- ✅ Artifacts are available for download
- ✅ GitHub Step Summary shows statistics
- ✅ New test files are picked up without workflow changes

## Support

**Issues:** Report at https://github.com/subzero-dev/subzero/issues

**Test Failures:** Check:
1. Workflow logs (full pytest output)
2. Test results artifact (JUnit XML)
3. Coverage report artifact (HTML)

**Questions:** See main project README.md
