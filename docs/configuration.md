<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Configuration Guide

This guide covers all configuration options for Subzero Zero Trust API Gateway.

## Configuration Methods

Subzero supports multiple configuration methods (in order of precedence):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Default values** (lowest priority)

## Quick Start

### Minimal Configuration

```bash
export AUTH0_DOMAIN="your-tenant.auth0.com"
export AUTH0_CLIENT_ID="your_client_id"
export AUTH0_AUDIENCE="https://your-api"
export FGA_STORE_ID="your_fga_store_id"

python -m subzero
```

### Configuration File

Create `subzero_config.py`:

```python
c = get_config()

# Authentication
c.Settings.AUTH0_DOMAIN = "your-tenant.auth0.com"
c.Settings.AUTH0_CLIENT_ID = "your_client_id"
c.Settings.AUTH0_AUDIENCE = "https://your-api"

# Performance
c.Settings.CACHE_CAPACITY = 20000
c.Settings.MAX_CONNECTIONS = 2000

# Security
c.Settings.ENABLE_BOT_DETECTION = True
c.Settings.THREAT_DETECTION_ENABLED = True
```

Run with config:
```bash
python -m subzero --config=subzero_config.py
```

## Core Configuration

### Authentication Settings

#### AUTH0_DOMAIN
- **Type**: String
- **Required**: Yes
- **Environment**: `SUBZERO_AUTH0_DOMAIN` or `AUTH0_DOMAIN`
- **Description**: Auth0 tenant domain
- **Example**: `"your-tenant.auth0.com"`

#### AUTH0_CLIENT_ID
- **Type**: String
- **Required**: Yes
- **Environment**: `SUBZERO_AUTH0_CLIENT_ID` or `AUTH0_CLIENT_ID`
- **Description**: Auth0 client ID for the gateway application
- **Example**: `"abc123xyz"`

#### AUTH0_CLIENT_SECRET
- **Type**: String
- **Required**: No (for Private Key JWT)
- **Environment**: `SUBZERO_AUTH0_CLIENT_SECRET` or `AUTH0_CLIENT_SECRET`
- **Description**: Auth0 client secret (if using client credentials flow)
- **Security**: Never commit this value

#### AUTH0_AUDIENCE
- **Type**: String
- **Required**: Yes
- **Environment**: `SUBZERO_AUTH0_AUDIENCE` or `AUTH0_AUDIENCE`
- **Description**: API identifier (audience) for token validation
- **Example**: `"https://api.your-company.com"`

#### AUTH0_MANAGEMENT_API_TOKEN
- **Type**: String
- **Required**: No
- **Environment**: `AUTH0_MANAGEMENT_API_TOKEN`
- **Description**: Token for Auth0 Management API access
- **Use case**: Dynamic client registration, user management

### Authorization Settings

#### FGA_STORE_ID
- **Type**: String
- **Required**: Yes (if using FGA)
- **Environment**: `SUBZERO_FGA_STORE_ID` or `FGA_STORE_ID`
- **Description**: Auth0 FGA store identifier
- **Example**: `"01HXXX..."`

#### FGA_CLIENT_ID
- **Type**: String
- **Required**: Yes (if using FGA)
- **Environment**: `SUBZERO_FGA_CLIENT_ID` or `FGA_CLIENT_ID`
- **Description**: FGA client credentials

#### FGA_CLIENT_SECRET
- **Type**: String
- **Required**: Yes (if using FGA)
- **Environment**: `SUBZERO_FGA_CLIENT_SECRET` or `FGA_CLIENT_SECRET`
- **Description**: FGA client secret
- **Security**: Never commit this value

#### FGA_API_URL
- **Type**: String
- **Required**: No
- **Default**: `"https://api.us1.fga.dev"`
- **Environment**: `SUBZERO_FGA_API_URL` or `FGA_API_URL`
- **Description**: Auth0 FGA API endpoint
- **Options**:
  - `"https://api.us1.fga.dev"` (US)
  - `"https://api.eu1.fga.dev"` (EU)
  - `"https://api.au1.fga.dev"` (Australia)

## Performance Configuration

### CACHE_CAPACITY
- **Type**: Integer
- **Default**: `10000`
- **Environment**: `SUBZERO_CACHE_CAPACITY`
- **Description**: Maximum number of items in memory cache
- **Recommendation**:
  - Small: 5,000-10,000
  - Medium: 10,000-50,000
  - Large: 50,000-100,000

### MAX_CONNECTIONS
- **Type**: Integer
- **Default**: `1000`
- **Environment**: `SUBZERO_MAX_CONNECTIONS`
- **Description**: Maximum concurrent connections
- **Recommendation**: Set to expected concurrent users × 1.5

### ENABLE_MULTIPROCESSING
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_ENABLE_MULTIPROCESSING`
- **Description**: Enable multi-core utilization for CPU-bound tasks
- **Note**: Set to `False` if running in containers with CPU limits

### REQUEST_TIMEOUT
- **Type**: Float
- **Default**: `30.0`
- **Environment**: `SUBZERO_REQUEST_TIMEOUT`
- **Description**: Request timeout in seconds
- **Recommendation**: 5-30 seconds for APIs

## Redis Configuration

### REDIS_URL
- **Type**: String
- **Required**: No (in-memory cache used if not set)
- **Default**: `None`
- **Environment**: `SUBZERO_REDIS_URL` or `REDIS_URL`
- **Description**: Redis connection URL for distributed caching
- **Format**: `"redis://[user:password@]host:port/db"`
- **Examples**:
  - `"redis://localhost:6379/0"`
  - `"redis://user:pass@redis.example.com:6379/0"`
  - `"rediss://redis.example.com:6380/0"` (TLS)

### REDIS_PASSWORD
- **Type**: String
- **Required**: No
- **Environment**: `SUBZERO_REDIS_PASSWORD` or `REDIS_PASSWORD`
- **Description**: Redis authentication password
- **Security**: Use strong password, never commit

### REDIS_MAX_CONNECTIONS
- **Type**: Integer
- **Default**: `50`
- **Environment**: `SUBZERO_REDIS_MAX_CONNECTIONS`
- **Description**: Maximum Redis connection pool size

## Security Configuration

### ENABLE_BOT_DETECTION
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_ENABLE_BOT_DETECTION`
- **Description**: Enable ML-based bot detection

### THREAT_DETECTION_ENABLED
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_THREAT_DETECTION_ENABLED`
- **Description**: Enable advanced threat detection (fraud, ATO, etc.)

### XAA_ENABLED
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_XAA_ENABLED`
- **Description**: Enable XAA protocol for AI agent authentication

### XAA_MAX_DELEGATION_DEPTH
- **Type**: Integer
- **Default**: `5`
- **Environment**: `SUBZERO_XAA_MAX_DELEGATION_DEPTH`
- **Description**: Maximum token delegation chain depth

### RATE_LIMIT_ENABLED
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_RATE_LIMIT_ENABLED`
- **Description**: Enable rate limiting

### RATE_LIMIT_REQUESTS
- **Type**: Integer
- **Default**: `100`
- **Environment**: `SUBZERO_RATE_LIMIT_REQUESTS`
- **Description**: Requests per window per user

### RATE_LIMIT_WINDOW
- **Type**: Integer
- **Default**: `60`
- **Environment**: `SUBZERO_RATE_LIMIT_WINDOW`
- **Description**: Rate limit window in seconds

## Logging Configuration

### LOG_LEVEL
- **Type**: String
- **Default**: `"INFO"`
- **Environment**: `SUBZERO_LOG_LEVEL`
- **Description**: Logging level
- **Options**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

### LOG_FORMAT
- **Type**: String
- **Default**: `"json"`
- **Environment**: `SUBZERO_LOG_FORMAT`
- **Description**: Log output format
- **Options**:
  - `"json"` - Structured JSON (production)
  - `"text"` - Human-readable (development)

### AUDIT_LOG_FILE
- **Type**: String
- **Required**: No
- **Environment**: `SUBZERO_AUDIT_LOG_FILE`
- **Description**: Path to audit log file
- **Example**: `"/var/log/subzero/audit.log"`
- **Note**: Requires write permissions

## Monitoring Configuration

### PROMETHEUS_ENABLED
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_PROMETHEUS_ENABLED`
- **Description**: Enable Prometheus metrics endpoint

### PROMETHEUS_PORT
- **Type**: Integer
- **Default**: `9090`
- **Environment**: `SUBZERO_PROMETHEUS_PORT`
- **Description**: Prometheus metrics port

### OTEL_ENABLED
- **Type**: Boolean
- **Default**: `False`
- **Environment**: `SUBZERO_OTEL_ENABLED`
- **Description**: Enable OpenTelemetry tracing

### OTEL_ENDPOINT
- **Type**: String
- **Required**: If `OTEL_ENABLED=True`
- **Environment**: `SUBZERO_OTEL_ENDPOINT`
- **Description**: OpenTelemetry collector endpoint
- **Example**: `"http://otel-collector:4317"`

## HTTP Server Configuration

### HOST
- **Type**: String
- **Default**: `"0.0.0.0"`
- **Environment**: `SUBZERO_HOST`
- **Description**: Bind address for HTTP server
- **Production**: Use `"0.0.0.0"` to accept connections from any interface

### PORT
- **Type**: Integer
- **Default**: `8000`
- **Environment**: `SUBZERO_PORT`
- **Description**: HTTP server port

### WORKERS
- **Type**: Integer
- **Default**: CPU cores × 2
- **Environment**: `SUBZERO_WORKERS`
- **Description**: Number of worker processes (for production)

### ENABLE_CORS
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_ENABLE_CORS`
- **Description**: Enable CORS support

### ALLOWED_ORIGINS
- **Type**: String (comma-separated)
- **Default**: `"*"`
- **Environment**: `SUBZERO_ALLOWED_ORIGINS`
- **Description**: Allowed CORS origins
- **Production**: Set specific origins, not `"*"`
- **Example**: `"https://app.example.com,https://admin.example.com"`

## Feature Flags

### ENABLE_SWAGGER_UI
- **Type**: Boolean
- **Default**: `True` (dev), `False` (prod)
- **Environment**: `SUBZERO_ENABLE_SWAGGER_UI`
- **Description**: Enable Swagger UI at `/docs`

### ENABLE_HEALTH_CHECKS
- **Type**: Boolean
- **Default**: `True`
- **Environment**: `SUBZERO_ENABLE_HEALTH_CHECKS`
- **Description**: Enable health check endpoints (`/health`, `/ready`)

## Environment-Specific Configurations

### Development

```bash
# .env.development
AUTH0_DOMAIN=dev-tenant.auth0.com
LOG_LEVEL=DEBUG
LOG_FORMAT=text
ENABLE_SWAGGER_UI=True
CACHE_CAPACITY=1000
```

### Staging

```bash
# .env.staging
AUTH0_DOMAIN=staging-tenant.auth0.com
LOG_LEVEL=INFO
LOG_FORMAT=json
REDIS_URL=redis://staging-redis:6379/0
CACHE_CAPACITY=10000
```

### Production

```bash
# .env.production
AUTH0_DOMAIN=prod-tenant.auth0.com
LOG_LEVEL=WARNING
LOG_FORMAT=json
REDIS_URL=rediss://prod-redis:6380/0
CACHE_CAPACITY=50000
MAX_CONNECTIONS=5000
WORKERS=8
ALLOWED_ORIGINS=https://app.example.com
ENABLE_SWAGGER_UI=False
PROMETHEUS_ENABLED=True
OTEL_ENABLED=True
```

## Configuration Validation

Subzero validates configuration on startup:

```python
from subzero.config.defaults import Settings

# Load and validate configuration
settings = Settings()

# Check required fields
assert settings.AUTH0_DOMAIN, "AUTH0_DOMAIN is required"
assert settings.AUTH0_CLIENT_ID, "AUTH0_CLIENT_ID is required"
```

## Troubleshooting

### Common Issues

**Missing required configuration:**
```
ValidationError: AUTH0_DOMAIN: Field required
```
**Solution**: Set the `AUTH0_DOMAIN` environment variable or in config file.

**Redis connection failed:**
```
ConnectionRefusedError: [Errno 111] Connection refused
```
**Solution**:
- Check Redis is running
- Verify `REDIS_URL` is correct
- Check network connectivity

**Auth0 validation errors:**
```
JWTError: Unable to verify token
```
**Solution**:
- Verify `AUTH0_DOMAIN` is correct
- Check `AUTH0_AUDIENCE` matches token audience
- Ensure token is not expired

## Best Practices

1. **Use environment variables in production**
   - Never commit secrets to version control
   - Use secret management systems (Vault, AWS Secrets Manager)

2. **Enable structured logging**
   - Use `LOG_FORMAT=json` in production
   - Ship logs to centralized logging system

3. **Configure Redis for production**
   - Use Redis for distributed caching
   - Enable TLS (`rediss://`)
   - Set authentication password

4. **Tune performance settings**
   - Adjust `CACHE_CAPACITY` based on memory
   - Set `MAX_CONNECTIONS` to expected load
   - Enable multiprocessing for CPU-bound tasks

5. **Enable monitoring**
   - Use Prometheus for metrics
   - Enable OpenTelemetry tracing
   - Monitor cache hit ratios

## References

- [Architecture](architecture.md)
- [Deployment Guide](deployment.md)
- [Security Policy](../SECURITY.md)

---

**Last updated:** 2025-10-02
