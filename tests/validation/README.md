<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Validation Tests

## Overview

This directory contains comprehensive validation tests that verify the completeness and correctness of the Subzero Zero Trust API Gateway implementation. These tests ensure that all claimed features exist, are properly integrated, and function as documented.

## Test Files

### Endpoint Validation

#### `test_all_endpoints.py`
Comprehensive endpoint verification for the FastAPI server.

**Purpose:** Validates that all 8 required API endpoints are present and properly configured.

**What it tests:**
- ✅ Gateway information endpoint (`GET /`)
- ✅ Health check endpoint (`GET /health`)
- ✅ Metrics endpoint (`GET /metrics`)
- ✅ API documentation (`GET /docs`)
- ✅ Authentication endpoint (`POST /auth/authenticate`)
- ✅ AI prompt validation (`POST /ai/validate-prompt`)
- ✅ Token vault storage (`POST /vault/store`)
- ✅ Authorization check (`POST /authz/check`)

**Backend integration verified:**
- UnifiedZeroTrustGateway
- Functional Event Orchestrator (request coalescing)
- LLM Security Guard (OWASP LLM Top 10)
- Audit Trail Service (GDPR/HIPAA compliance)
- Auth0 Private Key JWT
- Token Vault (Auth0 + Fernet encryption)
- Triple-layer Authorization

**Usage:**
```bash
pytest tests/validation/test_all_endpoints.py -v
```

#### `test_fastapi_server.py`
Quick validation of FastAPI server structure.

**Purpose:** Verifies FastAPI app metadata and route structure.

**What it tests:**
- App title, version, and configuration
- Route registration
- Middleware setup
- Expected endpoint paths

**Usage:**
```bash
pytest tests/validation/test_fastapi_server.py -v
```

---

### Feature Verification

#### `test_verify_all_features.py`
Comprehensive feature and metrics verification.

**Purpose:** Verifies all claimed features exist in the codebase with actual performance metrics.

**Feature categories tested:**
1. **MCP OAuth 2.1**
   - Authorization Code Flow, PKCE, Token Exchange
   - Dynamic Client Registration (RFC 7591)
   - Token Introspection (RFC 7662)
   - DPoP Validation (RFC 9449)
   - Metadata Discovery (RFC 8414)

2. **OWASP LLM Security**
   - All 10 OWASP LLM threat types
   - Input/output validation
   - Rate limiting
   - Action authorization

3. **XAA Protocol**
   - Token delegation
   - Bidirectional communication
   - 3 token types, 5 access scopes
   - App registration

4. **Token Vault**
   - 8+ provider support (Google, Microsoft, Slack, GitHub, etc.)
   - Store/retrieve/refresh/revoke operations

5. **Authorization (ReBAC/ABAC/OPA)**
   - ReBAC engine with check/expand/batch operations
   - ABAC evaluation and risk calculation
   - OPA client integration

6. **ISPM (Identity Security Posture Management)**
   - Risk assessment and auto-remediation
   - Security posture tracking
   - Compliance checking

**Performance metrics collected:**
- ReBAC check latency
- ABAC evaluation latency
- LLM input validation latency

**Usage:**
```bash
pytest tests/validation/test_verify_all_features.py -v
```

#### `test_verify_enterprise_features.py`
Enterprise feature validation per gap analysis.

**Purpose:** Validates Auth0/Okta enterprise features and implementation completeness.

**What it tests:**
1. **XAA Protocol** (90% complete)
   - Token types and access scopes
   - Delegation chains
   - Application registry
   - Metrics tracking

2. **ISPM Engine** (85% complete)
   - Risk levels and remediation actions
   - Security findings and posture
   - Compliance rules
   - Auto-remediation

3. **Token Vault** (95% complete)
   - Provider support (8 major providers)
   - Token operations
   - Metrics tracking

4. **MCP Protocol** (95% complete)
   - Dynamic capability discovery
   - OAuth metadata
   - OIDC configuration
   - Multi-step workflows

5. **Threat Detection** (95% complete)
   - Auth0 2025 threat landscape
   - Signup fraud (46.1% target)
   - Account takeover (16.9% target)
   - MFA abuse (7.3% target)

6. **Additional Features**
   - Auth0 Actions
   - Social connections
   - Extended Management API
   - Audit trail system

**Usage:**
```bash
pytest tests/validation/test_verify_enterprise_features.py -v
```

#### `test_verify_gaps_addressed.py`
Gap coverage verification for new modules.

**Purpose:** Confirms all new modules load successfully and integrate properly.

**Modules verified:**
1. **MCP OAuth 2.1 Authorization**
   - OAuth 2.1 methods and flows
   - Grant types and token types
   - Client registration

2. **MCP Metadata Discovery**
   - OAuth metadata endpoints
   - OIDC configuration
   - JWKS endpoints

3. **Auth0 Actions Integration**
   - Action triggers and handlers
   - Post-login, pre/post-registration
   - Credentials exchange

4. **Social Connection OAuth Providers**
   - Multiple social provider support
   - OAuth flow methods
   - User profile retrieval

5. **Extended Management API**
   - User management operations
   - Log streaming
   - Organization management
   - Attack protection

6. **Audit Integration**
   - Event logging across modules
   - Event types verification
   - Statistics tracking

7. **Integration Completeness**
   - Cross-module compatibility
   - Code metrics (modules, classes, methods, LOC)

**Usage:**
```bash
pytest tests/validation/test_verify_gaps_addressed.py -v
```

#### `test_verify_integration.py`
Integration completeness verification.

**Purpose:** Verifies all components are properly integrated and can be imported.

**What it tests:**
- Module import success for all components
- Key class availability
- Integration architecture integrity

**Component categories:**
- Core Orchestrator (Event loop, Multiprocessing)
- Authentication (JWT, OAuth, Vault, XAA, Registry)
- Authorization (FGA, ReBAC, ABAC, OPA, Cache)
- Security (Threat detection, ISPM, Rate limiting, Audit, Health)
- MCP (Capabilities, Transports, Discovery)
- Configuration Management

**Visual architecture diagram included.**

**Usage:**
```bash
pytest tests/validation/test_verify_integration.py -v
```

---

## Running Validation Tests

### Run All Validation Tests
```bash
# Run all validation tests
pytest tests/validation/ -v

# Run with detailed output
pytest tests/validation/ -v --tb=short

# Run with output capture disabled (see print statements)
pytest tests/validation/ -v -s
```

### Run Specific Test Suites
```bash
# Endpoint validation only
pytest tests/validation/test_all_endpoints.py tests/validation/test_fastapi_server.py -v

# Feature verification only
pytest tests/validation/test_verify_all_features.py tests/validation/test_verify_enterprise_features.py -v

# Integration verification only
pytest tests/validation/test_verify_integration.py tests/validation/test_verify_gaps_addressed.py -v
```

### CI/CD Integration
```bash
# Run validation tests with strict mode
pytest tests/validation/ -v --strict-markers --tb=short

# Generate validation report
pytest tests/validation/ -v --html=validation-report.html --self-contained-html
```

---

## Expected Results

All validation tests should **PASS** for a production-ready release:

- ✅ All endpoints present and functional
- ✅ All claimed features implemented
- ✅ Performance targets met
- ✅ Enterprise features verified
- ✅ Integration completeness confirmed
- ✅ No import errors or missing modules

### Success Criteria

| Test File | Success Criteria |
|-----------|-----------------|
| `test_all_endpoints.py` | All 8 endpoints present |
| `test_fastapi_server.py` | All expected routes and structure valid |
| `test_verify_all_features.py` | 100% feature verification pass rate |
| `test_verify_enterprise_features.py` | All 6 verifications pass, 90%+ implementation |
| `test_verify_gaps_addressed.py` | All 7 verifications pass |
| `test_verify_integration.py` | All components import successfully |

---

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure package is installed in development mode
pip install -e ".[dev]"

# Check Python path
python -c "import subzero; print(subzero.__file__)"
```

**Missing Dependencies:**
```bash
# Install all dependencies
pip install -e ".[dev]"

# Check for specific missing packages
pip list | grep auth0
```

**Test Failures:**
- Review the specific error message
- Check if all services are properly initialized
- Verify configuration values in test fixtures
- Ensure no conflicting environment variables

---

## Adding New Validation Tests

When adding new validation tests:

1. **Follow naming convention:** `test_verify_*.py` or `test_validate_*.py`
2. **Include docstrings:** Clearly document what is being validated
3. **Use descriptive output:** Print clear success/failure messages
4. **Test in isolation:** Each test should be independent
5. **Add to this README:** Document the new test and its purpose

### Template for New Validation Test

```python
#!/usr/bin/env python3
"""
Validation test for [Feature Name]

Tests that [Feature] is properly implemented and integrated.
"""

import asyncio
import sys


def print_section(title: str):
    """Print section header"""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


async def verify_feature():
    """Verify [Feature] implementation"""
    print_section("Feature Validation")

    try:
        from subzero.module import FeatureClass

        # Test feature
        feature = FeatureClass()
        assert hasattr(feature, "key_method"), "Method missing"

        print("✅ Feature verified")
        return True

    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False


async def main():
    """Run validation"""
    result = await verify_feature()
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
```

---

## Related Documentation

- [Testing Documentation](../../docs/testing.md)
- [Integration Tests](../integration/README.md)
- [Performance Tests](../performance/README.md)
- [Scripts README](../../scripts/README.md)

---

**Last updated:** 2025-10-05
