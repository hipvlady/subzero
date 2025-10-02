# Contributing to Subzero

Thank you for your interest in contributing to Subzero! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to dev@subzero.dev.

### Our Standards

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility and apologize when appropriate
- Prioritize what is best for the community

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Redis (optional, for caching)
- Auth0 tenant (for testing)

### Development Setup

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/yourusername/subzero.git
   cd subzero
   ```

2. **Create and activate virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   # Install package in editable mode with dev dependencies
   pip install -e ".[dev]"
   ```

4. **Set up environment variables**

   ```bash
   cp .env.example .env
   # Edit .env with your Auth0 credentials
   ```

5. **Run tests to verify setup**

   ```bash
   pytest
   ```

## Code Style

We follow strict code style guidelines to maintain consistency and readability.

### Python Style Guide

- **PEP 8 compliance**: Follow PEP 8 guidelines
- **Line length**: Maximum 120 characters
- **Imports**: Organize imports (standard library, third-party, local)
- **Type hints**: Required for all public functions
- **Docstrings**: NumPy-style docstrings for all public APIs

### Example Code

```python
# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Module docstring following NumPy style.

This module provides [functionality description].
"""

from typing import Optional, Dict, List


def authenticate_user(
    user_id: str,
    token: Optional[str] = None,
    scopes: List[str] = None
) -> Dict[str, any]:
    """
    Authenticate user with JWT token.

    Parameters
    ----------
    user_id : str
        User identifier
    token : str, optional
        JWT token to validate
    scopes : list of str, optional
        Required scopes for authentication

    Returns
    -------
    dict
        Authentication result containing user claims

    Raises
    ------
    AuthenticationError
        If authentication fails

    Examples
    --------
    >>> result = authenticate_user("user123", token="eyJ0...")
    >>> result['user_id']
    'user123'
    """
    # Implementation here
    pass
```

### Tools

We use the following tools to enforce code quality:

```bash
# Format code with black
black subzero/ tests/

# Lint with ruff
ruff check subzero/ tests/

# Type check with mypy
mypy subzero/

# Run all checks
make lint
```

### Pre-commit Hooks

We recommend using pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

## Testing

### Test Organization

Tests are organized into four categories:

```
tests/
├── unit/           # Fast, isolated unit tests
├── integration/    # Integration tests with external services
├── performance/    # Performance benchmarks
└── security/       # Security-specific tests
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test category
pytest tests/unit/
pytest tests/integration/
pytest tests/performance/
pytest tests/security/

# Run with coverage
pytest --cov=subzero --cov-report=html

# Run performance benchmarks
pytest tests/performance/ --benchmark-only
```

### Writing Tests

All new features must include tests:

```python
import pytest
from subzero.services.auth.jwt import JWTAuthenticator


class TestJWTAuthenticator:
    """Tests for JWT authentication."""

    def test_valid_token_authentication(self):
        """Test authentication with valid JWT token."""
        authenticator = JWTAuthenticator()
        result = authenticator.verify_token("valid_token")
        assert result.is_valid
        assert result.user_id is not None

    @pytest.mark.asyncio
    async def test_async_authentication(self):
        """Test async authentication flow."""
        authenticator = JWTAuthenticator()
        result = await authenticator.authenticate_async("user123")
        assert result.success
```

### Test Requirements

- **Unit tests**: Required for all new functions
- **Integration tests**: Required for API endpoints
- **Performance tests**: Required for critical paths
- **Coverage**: Maintain >80% code coverage
- **Documentation**: All tests must have docstrings

## Submitting Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-oauth-support` - New features
- `fix/authentication-bug` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/auth-module` - Code refactoring
- `test/add-integration-tests` - Test improvements

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed description of changes, motivation, and context.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Example:**

```
feat(auth): add Private Key JWT authentication

Implement RFC 7523 Private Key JWT authentication for
secretless auth flow. Includes JIT-compiled token validation
and contiguous memory caching.

- Add PrivateKeyJWTAuthenticator class
- Implement token validation with Numba JIT
- Add comprehensive unit tests
- Update documentation

Fixes #42
```

### Pull Request Process

1. **Create a pull request**

   - Use a clear, descriptive title
   - Reference related issues
   - Provide detailed description of changes
   - Include screenshots/examples if applicable

2. **Ensure all checks pass**

   - All tests passing
   - Code coverage maintained
   - Linting passed
   - Documentation updated

3. **Request review**

   - Request review from maintainers
   - Address review comments
   - Update PR as needed

4. **Merge requirements**

   - At least one approval from maintainer
   - All CI checks passing
   - No merge conflicts
   - Up-to-date with main branch

### Pull Request Template

```markdown
## Description

Brief description of changes

## Related Issues

Fixes #(issue number)

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests passing
- [ ] Coverage maintained/improved

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added and passing
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, security patches

### Release Checklist

1. Update version in `subzero/_version.py`
2. Update `CHANGELOG.md` with release notes
3. Run full test suite
4. Create git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. CI/CD automatically builds and publishes to PyPI
7. Create GitHub release with notes
8. Announce release

## Development Guidelines

### Performance Considerations

- Profile code for critical paths
- Use Numba JIT for CPU-bound operations
- Implement caching for expensive operations
- Use AsyncIO for I/O-bound operations
- Benchmark changes with pytest-benchmark

### Security Considerations

- Never commit secrets or credentials
- Use environment variables for configuration
- Follow OWASP security guidelines
- Include security tests for authentication/authorization
- Report security issues privately to security@subzero.dev

### Documentation

- Update README for user-facing changes
- Add docstrings for all public APIs
- Include code examples in docstrings
- Update architecture documentation
- Add entries to CHANGELOG.md

## Getting Help

- **Documentation**: https://subzero.readthedocs.io
- **Issues**: https://github.com/subzero-dev/subzero/issues
- **Discussions**: https://github.com/subzero-dev/subzero/discussions
- **Email**: dev@subzero.dev

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- CONTRIBUTORS file (for significant contributions)

Thank you for contributing to Subzero!

---

**Last updated:** 2025-10-02
