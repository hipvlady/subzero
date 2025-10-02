<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Code Examples and Usage Patterns

This document provides practical code examples for using Subzero Zero Trust API Gateway.

## Table of Contents

- [Basic Setup](#basic-setup)
- [Authentication Examples](#authentication-examples)
- [Authorization Examples](#authorization-examples)
- [Logging Examples](#logging-examples)
- [Security Features](#security-features)
- [Integration Patterns](#integration-patterns)
- [Error Handling](#error-handling)

## Basic Setup

### Minimal Configuration

```python
from subzero.config.defaults import Settings
from subzero.subzeroapp import UnifiedZeroTrustGateway

# Load configuration from environment variables
settings = Settings()

# Initialize gateway
gateway = UnifiedZeroTrustGateway(settings)

# Start gateway
await gateway.start()
```

### With Custom Configuration

```python
from subzero.config.defaults import Settings

# Override defaults
settings = Settings(
    AUTH0_DOMAIN="your-tenant.auth0.com",
    AUTH0_CLIENT_ID="your_client_id",
    CACHE_CAPACITY=50000,
    MAX_CONNECTIONS=2000,
    LOG_LEVEL="DEBUG",
)

gateway = UnifiedZeroTrustGateway(settings)
await gateway.start()
```

## Authentication Examples

### Example 1: Private Key JWT Authentication

```python
from subzero.services.auth.jwt import PrivateKeyJWTAuthenticator

# Initialize authenticator
authenticator = PrivateKeyJWTAuthenticator(
    auth0_domain="your-tenant.auth0.com",
    client_id="your_client_id",
    cache_capacity=10000
)

# Authenticate user
result = await authenticator.authenticate(
    user_id="user_123",
    scopes="openid profile email"
)

print(f"Access Token: {result['access_token']}")
print(f"Token Type: {result['token_type']}")
print(f"Expires In: {result['expires_in']} seconds")

# Validate existing token
is_valid = await authenticator.validate_token(result['access_token'])
print(f"Token Valid: {is_valid}")
```

**Output:**
```
✅ New authentication - Latency: 45.23ms
Access Token: eyJ0eXAiOiJKV1QiLCJhbGc...
Token Type: Bearer
Expires In: 3600 seconds
✅ Cache hit - Authentication latency: 2.34ms
Token Valid: True
```

### Example 2: OAuth 2.1 + PKCE Flow

```python
from subzero.services.auth.oauth import OAuth21PKCEFlow
import secrets

# Initialize OAuth flow
oauth = OAuth21PKCEFlow(
    auth0_domain="your-tenant.auth0.com",
    client_id="your_client_id",
    redirect_uri="https://your-app.com/callback"
)

# Step 1: Generate authorization URL with PKCE
code_verifier = secrets.token_urlsafe(64)
code_challenge = oauth.generate_code_challenge(code_verifier)

auth_url = oauth.get_authorization_url(
    state="random_state_string",
    code_challenge=code_challenge,
    scope="openid profile email"
)

print(f"Redirect user to: {auth_url}")

# Step 2: Exchange authorization code for tokens
# (after user authorization and redirect back)
token_data = await oauth.exchange_code_for_token(
    authorization_code="received_auth_code",
    code_verifier=code_verifier
)

print(f"Access Token: {token_data['access_token']}")
print(f"Refresh Token: {token_data['refresh_token']}")
print(f"ID Token: {token_data['id_token']}")

# Step 3: Refresh tokens
new_tokens = await oauth.refresh_tokens(
    refresh_token=token_data['refresh_token']
)
```

### Example 3: XAA Protocol (AI Agent Auth)

```python
from subzero.services.auth.xaa import XAAProtocol

# Initialize XAA
xaa = XAAProtocol(
    auth0_domain="your-tenant.auth0.com",
    max_delegation_depth=5
)

# Agent delegates to another agent
delegation_token = await xaa.delegate_token(
    original_token="agent_primary_token",
    target_subject="agent_secondary_id",
    scopes=["read:data", "write:data"],
    delegation_metadata={
        "purpose": "data_processing",
        "context": "batch_job_123"
    }
)

print(f"Delegation Token: {delegation_token}")

# Verify delegation chain
chain_info = await xaa.verify_delegation_chain(delegation_token)
print(f"Chain Depth: {chain_info['depth']}")
print(f"Original Subject: {chain_info['original_subject']}")
print(f"Current Subject: {chain_info['current_subject']}")
```

## Authorization Examples

### Example 1: ReBAC (Relationship-Based Access Control)

```python
from subzero.services.authorization.rebac import ReBACEngine

# Initialize ReBAC engine
rebac = ReBACEngine(auth0_fga_store_id="your_store_id")

# Define relationships
await rebac.write_tuple(
    object_type="document",
    object_id="doc_123",
    relation="owner",
    subject_type="user",
    subject_id="user_alice"
)

await rebac.write_tuple(
    object_type="document",
    object_id="doc_123",
    relation="viewer",
    subject_type="user",
    subject_id="user_bob"
)

# Check permissions
can_read = await rebac.check(
    user_id="user_bob",
    object_type="document",
    object_id="doc_123",
    relation="viewer"
)
print(f"Bob can view document: {can_read}")  # True

can_edit = await rebac.check(
    user_id="user_bob",
    object_type="document",
    object_id="doc_123",
    relation="owner"
)
print(f"Bob can edit document: {can_edit}")  # False

# List all users who can view document
viewers = await rebac.expand(
    object_type="document",
    object_id="doc_123",
    relation="viewer"
)
print(f"Document viewers: {viewers}")
```

### Example 2: ABAC (Attribute-Based Access Control)

```python
from subzero.services.authorization.abac import ABACEngine

# Initialize ABAC engine
abac = ABACEngine()

# Define policy
policy = {
    "name": "document_access",
    "description": "Users can access documents in their department",
    "rules": [
        {
            "effect": "allow",
            "subject": {"department": "engineering"},
            "resource": {"type": "document", "classification": "internal"},
            "action": "read"
        },
        {
            "effect": "allow",
            "subject": {"role": "manager"},
            "resource": {"type": "document"},
            "action": ["read", "write"]
        }
    ]
}

abac.add_policy(policy)

# Evaluate permission
context = {
    "subject": {
        "user_id": "user_123",
        "department": "engineering",
        "role": "developer"
    },
    "resource": {
        "type": "document",
        "id": "doc_456",
        "classification": "internal"
    },
    "action": "read"
}

decision = await abac.evaluate(context)
print(f"Access allowed: {decision['allowed']}")
print(f"Reason: {decision['reason']}")
```

### Example 3: OPA Integration

```python
from subzero.services.authorization.opa import OPAIntegration

# Initialize OPA
opa = OPAIntegration(opa_url="http://opa:8181")

# Load policy
policy = """
package authz

default allow = false

allow {
    input.method == "GET"
    input.path[0] == "public"
}

allow {
    input.user.role == "admin"
}
"""

await opa.upload_policy("authz", policy)

# Evaluate policy
input_data = {
    "method": "GET",
    "path": ["public", "docs"],
    "user": {
        "id": "user_123",
        "role": "user"
    }
}

result = await opa.evaluate("authz/allow", input_data)
print(f"Allow: {result['result']}")
```

## Logging Examples

### Example 1: Structured Logging Setup

```python
from subzero.utils.structured_logging import setup_logging, get_logger

# Production configuration
setup_logging(
    log_level="INFO",
    structured=True,
    audit_log_file="/var/log/subzero/audit.log"
)

logger = get_logger(__name__)

# Log with structured data
logger.info(
    "User authenticated successfully",
    extra={
        "user_id": "user_123",
        "auth_method": "jwt",
        "latency_ms": 45.2
    }
)
```

**Output (JSON):**
```json
{
  "timestamp": "2025-10-01T10:30:45.123Z",
  "level": "INFO",
  "logger": "subzero.auth",
  "message": "User authenticated successfully",
  "module": "jwt",
  "function": "authenticate",
  "line": 142,
  "user_id": "user_123",
  "auth_method": "jwt",
  "latency_ms": 45.2
}
```

### Example 2: Request Context Logging

```python
from subzero.utils.structured_logging import RequestLogger, get_logger

logger = get_logger(__name__)

async def handle_request(request_id: str, user_id: str):
    with RequestLogger(logger, request_id, "GET", "/api/users", user_id):
        # Your request processing logic
        await process_request()
        return {"status": "success"}
```

**Output:**
```json
{
  "timestamp": "2025-10-01T10:30:45.100Z",
  "level": "INFO",
  "message": "Request started",
  "request_id": "req-123",
  "method": "GET",
  "path": "/api/users",
  "user_id": "user_456"
}
{
  "timestamp": "2025-10-01T10:30:45.145Z",
  "level": "INFO",
  "message": "Request completed",
  "request_id": "req-123",
  "method": "GET",
  "path": "/api/users",
  "user_id": "user_456",
  "latency_ms": 45.0,
  "status_code": 200
}
```

### Example 3: Error Logging with Context

```python
logger = get_logger(__name__)

try:
    result = await authenticate_user(token)
except AuthenticationError as e:
    logger.error(
        "Authentication failed",
        extra={
            "user_id": user_id,
            "error_type": "invalid_token",
            "token_age_seconds": calculate_age(token)
        },
        exc_info=True
    )
    raise
```

## Security Features

### Example 1: Threat Detection

```python
from subzero.services.security.threat_detection import (
    SignupFraudDetector,
    AccountTakeoverDetector
)

# Signup fraud detection
fraud_detector = SignupFraudDetector()

signup_data = {
    "email": "user@example.com",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "signup_speed": 5.2,  # seconds to fill form
    "device_fingerprint": "abc123...",
}

risk_score = await fraud_detector.analyze(signup_data)
print(f"Fraud Risk Score: {risk_score:.2f}")

if risk_score > 0.8:
    print("⚠️ High fraud risk - require additional verification")
elif risk_score > 0.5:
    print("⚠️ Medium fraud risk - enable email verification")
else:
    print("✅ Low fraud risk - proceed with signup")

# Account takeover detection
ato_detector = AccountTakeoverDetector()

login_data = {
    "user_id": "user_123",
    "ip_address": "203.0.113.50",
    "location": "New York, US",
    "device": "iPhone",
    "time_since_last_login": 86400,  # 24 hours
}

ato_score = await ato_detector.analyze(login_data)
print(f"ATO Risk Score: {ato_score:.2f}")

if ato_score > 0.7:
    print("🚨 Require MFA challenge")
```

### Example 2: Rate Limiting

```python
from subzero.services.security.rate_limiter import RateLimiter

# Initialize rate limiter
rate_limiter = RateLimiter(
    redis_url="redis://localhost:6379/0",
    requests_per_window=100,
    window_seconds=60
)

# Check rate limit
user_id = "user_123"
is_allowed = await rate_limiter.check_rate_limit(
    key=f"user:{user_id}",
    limit=100,
    window=60
)

if is_allowed:
    # Process request
    await handle_request()
else:
    # Return 429 Too Many Requests
    return {"error": "Rate limit exceeded"}

# Get current usage
usage = await rate_limiter.get_usage(f"user:{user_id}")
print(f"Requests used: {usage['count']}/{usage['limit']}")
print(f"Reset in: {usage['reset_in']} seconds")
```

### Example 3: ISPM (Identity Security Posture Management)

```python
from subzero.services.security.ispm import IdentitySecurityPostureManager

# Initialize ISPM
ispm = IdentitySecurityPostureManager()

# Assess identity security posture
posture = await ispm.assess_posture(user_id="user_123")

print(f"Security Score: {posture['score']}/100")
print(f"Risk Level: {posture['risk_level']}")

# Check specific security controls
print("\nSecurity Controls:")
for control in posture['controls']:
    status = "✅" if control['passed'] else "❌"
    print(f"{status} {control['name']}: {control['status']}")

# Example output:
# Security Score: 85/100
# Risk Level: LOW
#
# Security Controls:
# ✅ MFA Enabled: active
# ✅ Strong Password: compliant
# ✅ Recent Activity: normal
# ❌ Device Trust: unknown
# ✅ Geolocation: expected
```

## Integration Patterns

### Example 1: FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from subzero.services.auth.jwt import PrivateKeyJWTAuthenticator

app = FastAPI()
security = HTTPBearer()
authenticator = PrivateKeyJWTAuthenticator(
    auth0_domain="your-tenant.auth0.com",
    client_id="your_client_id"
)

async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Verify JWT token and return claims"""
    token = credentials.credentials

    try:
        claims = await authenticator.validate_token(token)
        return claims
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials"
        )

@app.get("/api/protected")
async def protected_endpoint(claims: dict = Depends(verify_token)):
    """Protected endpoint requiring authentication"""
    user_id = claims.get("sub")
    return {
        "message": f"Hello, {user_id}!",
        "claims": claims
    }

@app.get("/api/admin")
async def admin_endpoint(claims: dict = Depends(verify_token)):
    """Admin-only endpoint"""
    scopes = claims.get("scope", "").split()

    if "admin" not in scopes:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions"
        )

    return {"message": "Admin access granted"}
```

### Example 2: Background Task Processing

```python
import asyncio
from subzero.services.auth.jwt import PrivateKeyJWTAuthenticator

async def process_batch_with_auth():
    """Process batch of items with authentication"""
    authenticator = PrivateKeyJWTAuthenticator(
        auth0_domain="your-tenant.auth0.com",
        client_id="batch_processor_client"
    )

    # Authenticate once for batch processing
    auth_result = await authenticator.authenticate(
        user_id="batch_processor",
        scopes="batch:process batch:write"
    )

    token = auth_result['access_token']

    # Process items concurrently
    items = await fetch_items_to_process()

    async def process_item(item):
        # Use token for authenticated API calls
        result = await process_with_token(item, token)
        return result

    # Process all items in parallel
    results = await asyncio.gather(
        *[process_item(item) for item in items]
    )

    print(f"Processed {len(results)} items")
```

### Example 3: WebSocket Authentication

```python
from fastapi import WebSocket, WebSocketDisconnect
from subzero.services.auth.jwt import PrivateKeyJWTAuthenticator

authenticator = PrivateKeyJWTAuthenticator(...)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        # Receive authentication message
        auth_message = await websocket.receive_json()
        token = auth_message.get("token")

        # Validate token
        claims = await authenticator.validate_token(token)
        user_id = claims.get("sub")

        await websocket.send_json({
            "type": "auth_success",
            "user_id": user_id
        })

        # Continue with authenticated WebSocket connection
        while True:
            data = await websocket.receive_json()
            # Process authenticated messages
            await handle_message(user_id, data)

    except WebSocketDisconnect:
        print(f"Client disconnected")
    except Exception as e:
        await websocket.send_json({
            "type": "error",
            "message": str(e)
        })
        await websocket.close()
```

## Error Handling

### Example 1: Graceful Degradation

```python
from subzero.services.security.degradation import GracefulDegradation

degradation = GracefulDegradation()

try:
    # Try primary auth method
    result = await primary_auth(user_id)
except Auth0Unavailable:
    # Fallback to cached validation
    result = await degradation.fallback_auth(user_id)
    logger.warning("Using cached authentication", extra={
        "user_id": user_id,
        "mode": "degraded"
    })
```

### Example 2: Circuit Breaker Pattern

```python
from subzero.services.security.health import CircuitBreaker

circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60
)

@circuit_breaker.protect
async def call_external_api():
    """Protected external API call"""
    response = await http_client.get("https://api.example.com/data")
    return response.json()

try:
    data = await call_external_api()
except CircuitBreakerOpen:
    # Circuit breaker is open, fail fast
    logger.error("Circuit breaker open for external API")
    return {"error": "Service temporarily unavailable"}
```

### Example 3: Retry with Exponential Backoff

```python
import asyncio

async def retry_with_backoff(func, max_retries=3, base_delay=1):
    """Retry function with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise

            delay = base_delay * (2 ** attempt)
            logger.warning(
                f"Attempt {attempt + 1} failed, retrying in {delay}s",
                extra={"error": str(e)}
            )
            await asyncio.sleep(delay)

# Usage
result = await retry_with_backoff(
    lambda: authenticator.validate_token(token),
    max_retries=3
)
```

## Performance Optimization Examples

### Example 1: Batch Operations

```python
# Inefficient: Individual requests
for user_id in user_ids:
    await authenticate_user(user_id)  # 100ms each × 100 = 10,000ms

# Efficient: Batch processing
results = await asyncio.gather(
    *[authenticate_user(uid) for uid in user_ids]
)  # 100ms total (parallel)
```

### Example 2: Caching Strategy

```python
from functools import lru_cache
import asyncio

# Memory cache for hot data
@lru_cache(maxsize=1000)
def get_user_permissions_cached(user_id: str) -> list:
    return fetch_permissions(user_id)

# Async cache with TTL
class AsyncCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl

    async def get_or_fetch(self, key, fetch_func):
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value

        value = await fetch_func()
        self.cache[key] = (value, time.time())
        return value
```

## References

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Performance](performance.md)
- [API Reference](../README.md#api-reference)

---

**Last updated:** 2025-10-01
