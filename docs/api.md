<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# API Reference

Complete API reference for Subzero Zero Trust API Gateway.

## Table of Contents

- [REST API Endpoints](#rest-api-endpoints)
- [Authentication API](#authentication-api)
- [Authorization API](#authorization-api)
- [Health & Monitoring](#health--monitoring)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)

---

## REST API Endpoints

### Base URL

```
Production: https://api.your-domain.com
Development: http://localhost:8000
```

### Authentication

All API requests (except health checks) require authentication via JWT token in the `Authorization` header:

```http
Authorization: Bearer <your-jwt-token>
```

---

## Authentication API

### POST /api/auth/token

Generate access token using Private Key JWT.

**Request:**

```http
POST /api/auth/token HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<jwt-assertion>",
  "scope": "openid profile email"
}
```

**Response (200 OK):**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

**Response (401 Unauthorized):**

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

---

### POST /api/auth/validate

Validate JWT token and return claims.

**Request:**

```http
POST /api/auth/validate HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <token-to-validate>
```

**Response (200 OK):**

```json
{
  "valid": true,
  "claims": {
    "sub": "user_123",
    "aud": "https://api.your-domain.com",
    "iss": "https://your-tenant.auth0.com/",
    "exp": 1735714800,
    "iat": 1735711200,
    "scope": "openid profile email"
  },
  "expires_at": "2025-01-01T12:00:00Z"
}
```

**Response (401 Unauthorized):**

```json
{
  "valid": false,
  "error": "token_expired",
  "error_description": "Token has expired"
}
```

---

### POST /api/auth/refresh

Refresh access token using refresh token.

**Request:**

```http
POST /api/auth/refresh HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": "v1.MRqDW7Jd...",
  "client_id": "your_client_id"
}
```

**Response (200 OK):**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "v1.MRqDW7Jd...",
  "scope": "openid profile email"
}
```

---

### POST /api/auth/logout

Revoke tokens and logout user.

**Request:**

```http
POST /api/auth/logout HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <access-token>

{
  "refresh_token": "v1.MRqDW7Jd..."
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Tokens revoked successfully"
}
```

---

## Authorization API

### POST /api/authz/check

Check if user has permission to access resource.

**Request:**

```http
POST /api/authz/check HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <access-token>

{
  "user_id": "user_123",
  "resource": {
    "type": "document",
    "id": "doc_456"
  },
  "action": "read"
}
```

**Response (200 OK):**

```json
{
  "allowed": true,
  "decision": "allow",
  "reason": "User has viewer permission on document",
  "cached": true,
  "latency_ms": 2.3
}
```

**Response (403 Forbidden):**

```json
{
  "allowed": false,
  "decision": "deny",
  "reason": "Insufficient permissions",
  "required_permissions": ["document:read"],
  "user_permissions": []
}
```

---

### POST /api/authz/batch

Check multiple permissions in a single request.

**Request:**

```http
POST /api/authz/batch HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <access-token>

{
  "user_id": "user_123",
  "checks": [
    {
      "resource": {"type": "document", "id": "doc_1"},
      "action": "read"
    },
    {
      "resource": {"type": "document", "id": "doc_2"},
      "action": "write"
    }
  ]
}
```

**Response (200 OK):**

```json
{
  "results": [
    {
      "resource": {"type": "document", "id": "doc_1"},
      "action": "read",
      "allowed": true
    },
    {
      "resource": {"type": "document", "id": "doc_2"},
      "action": "write",
      "allowed": false
    }
  ],
  "latency_ms": 5.7
}
```

---

### GET /api/authz/permissions/{user_id}

List all permissions for a user.

**Request:**

```http
GET /api/authz/permissions/user_123 HTTP/1.1
Host: api.your-domain.com
Authorization: Bearer <access-token>
```

**Response (200 OK):**

```json
{
  "user_id": "user_123",
  "permissions": [
    {
      "resource": {"type": "document", "id": "doc_1"},
      "relation": "owner",
      "granted_at": "2025-01-01T10:00:00Z"
    },
    {
      "resource": {"type": "document", "id": "doc_2"},
      "relation": "viewer",
      "granted_at": "2025-01-01T11:00:00Z"
    }
  ],
  "total": 2
}
```

---

### POST /api/authz/grant

Grant permission to user.

**Request:**

```http
POST /api/authz/grant HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "user_id": "user_123",
  "resource": {
    "type": "document",
    "id": "doc_456"
  },
  "relation": "viewer"
}
```

**Response (201 Created):**

```json
{
  "success": true,
  "permission": {
    "user_id": "user_123",
    "resource": {"type": "document", "id": "doc_456"},
    "relation": "viewer",
    "granted_at": "2025-01-01T12:00:00Z"
  }
}
```

---

### DELETE /api/authz/revoke

Revoke permission from user.

**Request:**

```http
DELETE /api/authz/revoke HTTP/1.1
Host: api.your-domain.com
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "user_id": "user_123",
  "resource": {
    "type": "document",
    "id": "doc_456"
  },
  "relation": "viewer"
}
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Permission revoked successfully"
}
```

---

## Health & Monitoring

### GET /health

Basic health check endpoint.

**Request:**

```http
GET /health HTTP/1.1
Host: api.your-domain.com
```

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 86400,
  "timestamp": "2025-01-01T12:00:00Z"
}
```

**Response (503 Service Unavailable):**

```json
{
  "status": "unhealthy",
  "version": "0.1.0",
  "errors": [
    "Redis connection failed",
    "Auth0 API unreachable"
  ],
  "timestamp": "2025-01-01T12:00:00Z"
}
```

---

### GET /ready

Readiness probe for Kubernetes.

**Request:**

```http
GET /ready HTTP/1.1
Host: api.your-domain.com
```

**Response (200 OK):**

```json
{
  "ready": true,
  "checks": {
    "auth0": "connected",
    "redis": "connected",
    "fga": "connected"
  }
}
```

**Response (503 Service Unavailable):**

```json
{
  "ready": false,
  "checks": {
    "auth0": "connected",
    "redis": "disconnected",
    "fga": "connected"
  }
}
```

---

### GET /metrics

Prometheus metrics endpoint.

**Request:**

```http
GET /metrics HTTP/1.1
Host: api.your-domain.com
```

**Response (200 OK):**

```
# HELP subzero_requests_total Total number of requests
# TYPE subzero_requests_total counter
subzero_requests_total{method="GET",endpoint="/api/auth/validate"} 12345

# HELP subzero_request_duration_seconds Request duration in seconds
# TYPE subzero_request_duration_seconds histogram
subzero_request_duration_seconds_bucket{le="0.005"} 8234
subzero_request_duration_seconds_bucket{le="0.01"} 11456
subzero_request_duration_seconds_bucket{le="0.05"} 12234
subzero_request_duration_seconds_sum 234.56
subzero_request_duration_seconds_count 12345

# HELP subzero_cache_hits_total Total cache hits
# TYPE subzero_cache_hits_total counter
subzero_cache_hits_total 11987

# HELP subzero_cache_misses_total Total cache misses
# TYPE subzero_cache_misses_total counter
subzero_cache_misses_total 358
```

---

## Error Responses

All errors follow a consistent format:

### Error Response Structure

```json
{
  "error": "error_code",
  "error_description": "Human-readable error message",
  "error_details": {
    "field": "additional context"
  },
  "request_id": "req-123",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

### HTTP Status Codes

| Code | Description | Common Errors |
|------|-------------|---------------|
| 200 | OK | Successful request |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid request body, missing parameters |
| 401 | Unauthorized | Invalid or expired token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service degraded or down |

### Common Error Codes

**Authentication Errors:**
- `invalid_token` - Token is malformed or invalid
- `token_expired` - Token has expired
- `invalid_client` - Client authentication failed
- `insufficient_scope` - Token lacks required scopes

**Authorization Errors:**
- `permission_denied` - User lacks required permission
- `resource_not_found` - Resource does not exist
- `invalid_resource_type` - Unsupported resource type

**Rate Limiting Errors:**
- `rate_limit_exceeded` - Too many requests

**Server Errors:**
- `internal_error` - Internal server error
- `service_unavailable` - External service unavailable

---

## Rate Limiting

### Rate Limit Headers

All responses include rate limit information:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1735714800
```

### Rate Limit Response (429)

```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests",
  "limit": 100,
  "remaining": 0,
  "reset_at": "2025-01-01T12:00:00Z",
  "retry_after": 45
}
```

### Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/auth/*` | 100 requests | 60 seconds |
| `/api/authz/check` | 1000 requests | 60 seconds |
| `/api/authz/batch` | 100 requests | 60 seconds |
| `/api/authz/grant` | 50 requests | 60 seconds |
| `/health` | Unlimited | - |
| `/metrics` | Unlimited | - |

---

## Request & Response Examples

### Example: Complete Authentication Flow

**Step 1: Generate JWT Assertion**

```python
import jwt
from datetime import datetime, timedelta

private_key = """-----BEGIN RSA PRIVATE KEY-----..."""

assertion = jwt.encode(
    {
        "iss": "your_client_id",
        "sub": "your_client_id",
        "aud": "https://your-tenant.auth0.com/oauth/token",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=5)
    },
    private_key,
    algorithm="RS256"
)
```

**Step 2: Exchange Assertion for Token**

```bash
curl -X POST https://api.your-domain.com/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "'$assertion'",
    "scope": "openid profile email"
  }'
```

**Step 3: Use Token for API Calls**

```bash
curl -X POST https://api.your-domain.com/api/authz/check \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_123",
    "resource": {"type": "document", "id": "doc_456"},
    "action": "read"
  }'
```

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('wss://api.your-domain.com/ws');

// Send authentication
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your-jwt-token'
}));

// Receive auth confirmation
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'auth_success') {
    console.log('Authenticated:', data.user_id);
  }
};
```

### Message Format

**Client → Server:**

```json
{
  "type": "permission_check",
  "request_id": "req-123",
  "data": {
    "resource": {"type": "document", "id": "doc_456"},
    "action": "read"
  }
}
```

**Server → Client:**

```json
{
  "type": "permission_result",
  "request_id": "req-123",
  "data": {
    "allowed": true,
    "latency_ms": 2.3
  }
}
```

---

## SDK Examples

### Python SDK

```python
from subzero.client import SubzeroClient

# Initialize client
client = SubzeroClient(
    base_url="https://api.your-domain.com",
    client_id="your_client_id",
    private_key_path="path/to/private_key.pem"
)

# Authenticate
await client.authenticate()

# Check permission
result = await client.check_permission(
    user_id="user_123",
    resource={"type": "document", "id": "doc_456"},
    action="read"
)

print(f"Allowed: {result.allowed}")
```

### JavaScript SDK

```javascript
import { SubzeroClient } from '@subzero/client';

const client = new SubzeroClient({
  baseUrl: 'https://api.your-domain.com',
  clientId: 'your_client_id',
  privateKey: privateKeyPem
});

// Authenticate
await client.authenticate();

// Check permission
const result = await client.checkPermission({
  userId: 'user_123',
  resource: { type: 'document', id: 'doc_456' },
  action: 'read'
});

console.log('Allowed:', result.allowed);
```

---

## OpenAPI Specification

Full OpenAPI 3.0 specification available at:

```
GET /api/swagger.json
GET /api/swagger.yaml
```

Interactive Swagger UI:

```
GET /docs
```

---

## References

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Examples](examples.md)
- [Performance](performance.md)

---

**Last updated:** 2025-10-01
**API Version:** v1.0
