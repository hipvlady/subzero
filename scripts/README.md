<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Scripts Directory

## Overview

This directory is reserved for production-ready utility scripts for the Subzero Zero Trust API Gateway. Currently, all scripts have been reorganized as follows:

- **Test & Validation Scripts** → Moved to [`/tests/validation/`](../tests/validation/)
- **Development Utilities** → Archived in [`/archive/scripts/development/`](../archive/scripts/development/)

## Project Organization

### Testing & Validation

All test and verification scripts are now located in the `/tests` directory with proper organization:

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Integration tests for component interactions
├── performance/       # Performance benchmarks and load tests
├── security/          # Security validation tests
├── validation/        # Feature verification and endpoint tests
└── conftest.py        # Shared pytest fixtures and configuration
```

**Validation Tests** (formerly in `/scripts`):
- `test_all_endpoints.py` - Comprehensive endpoint verification
- `test_fastapi_server.py` - FastAPI server structure validation
- `test_verify_all_features.py` - Feature completeness verification
- `test_verify_enterprise_features.py` - Enterprise feature validation
- `test_verify_gaps_addressed.py` - Gap coverage verification
- `test_verify_integration.py` - Integration completeness check

### Running Validation Tests

```bash
# Run all validation tests
pytest tests/validation/ -v

# Run specific validation test
pytest tests/validation/test_all_endpoints.py -v

# Run with detailed output
pytest tests/validation/test_verify_enterprise_features.py -v --tb=short
```

### Archived Scripts

Development-only utilities have been archived for historical reference:

- `add_copyright_headers.py` - Bulk copyright header management
- `add_last_updated.py` - Documentation footer management

See [`/archive/ARCHIVE_INDEX.md`](../archive/ARCHIVE_INDEX.md) for details on archived files.

## Adding New Scripts

When adding production scripts to this directory, follow these guidelines:

### Script Requirements

1. **Purpose**: Script must serve a production use case
2. **Documentation**: Include clear docstring and usage examples
3. **Error Handling**: Implement robust error handling
4. **Testing**: Add corresponding tests in `/tests`
5. **Copyright**: Include copyright header
6. **Dependencies**: Document all required dependencies

### Script Template

```python
#!/usr/bin/env python3
"""
Brief description of what the script does.

Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
"""

import argparse
from pathlib import Path


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Script description")
    parser.add_argument("--option", help="Option description")
    args = parser.parse_args()

    # Script logic here
    pass


if __name__ == "__main__":
    main()
```

### Categories for Future Scripts

When adding scripts, categorize them as:

- **Build & Deployment** - Build artifacts, deployment automation
- **Database** - Schema migrations, data imports/exports
- **Maintenance** - Cleanup, optimization, health checks
- **Utilities** - General-purpose helper scripts

## Best Practices

✅ **DO:**
- Use relative paths from project root
- Include `--help` documentation
- Log actions for audit trail
- Handle errors gracefully
- Use type hints (Python 3.11+)
- Follow [PEP 8](https://pep8.org/) style guide

❌ **DON'T:**
- Hardcode credentials or secrets
- Use absolute paths
- Skip error handling
- Create single-use development scripts here
- Modify production data without confirmation

## Requirements

All scripts should be compatible with:
- Python 3.11 or higher
- Project dependencies in `pyproject.toml`

## Support

For issues or questions about scripts:
- **Issues**: https://github.com/subzero-dev/subzero/issues
- **Documentation**: https://subzero.readthedocs.io

---

**Last updated:** 2025-10-05
