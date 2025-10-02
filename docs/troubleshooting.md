<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Troubleshooting Guide

Common issues and solutions for Subzero Zero Trust API Gateway.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Errors](#configuration-errors)
- [Authentication Problems](#authentication-problems)
- [Authorization Issues](#authorization-issues)
- [Performance Problems](#performance-problems)
- [Docker & Deployment](#docker--deployment)
- [Redis & Caching](#redis--caching)
- [Integration Issues](#integration-issues)
- [Debugging & Logging](#debugging--logging)

---

## Installation Issues

### ModuleNotFoundError: No module named 'subzero'

**Problem:** Python cannot find the subzero module after installation.

**Solutions:**

1. **Verify installation:**
```bash
pip list | grep subzero
```

2. **Install in development mode:**
```bash
cd /path/to/subzero
pip install -e .
```

3. **Check Python path:**
```python
import sys
print(sys.path)
```

4. **Reinstall dependencies:**
```bash
pip uninstall subzero
pip install subzero
```

---

### Dependency Conflicts

**Problem:** Conflicting package versions during installation.

**Error Message:**
```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed.
```

**Solutions:**

1. **Use a clean virtual environment:**
```bash
python -m venv venv
source venv/bin/activate
pip install subzero
```

2. **Upgrade pip:**
```bash
pip install --upgrade pip setuptools wheel
```

3. **Install with constraints:**
```bash
pip install subzero --upgrade-strategy only-if-needed
```

4. **Check for conflicting packages:**
```bash
pip check
```

---

### Missing openfga-sdk

**Problem:** `ModuleNotFoundError: No module named 'openfga_sdk'`

**Solution:**

```bash
pip install openfga-sdk>=0.3.0
```

Or add to requirements.txt:
```
openfga-sdk>=0.3.0
```

---

### gRPC Build Errors

**Problem:** Compilation errors when installing grpcio.

**Solution:**

Install pre-built wheels:
```bash
pip install grpcio --no-binary :all: --ignore-installed
```

Or use system packages (Ubuntu/Debian):
```bash
sudo apt-get install build-essential python3-dev
pip install grpcio
```

macOS:
```bash
brew install grpc
pip install grpcio
```

---

## Configuration Errors

### Pydantic ValidationError

**Problem:** `ValidationError: 6 validation errors for Settings`

**Error Details:**
```
AUTH0_DOMAIN
  field required (type=value_error.missing)
AUTH0_CLIENT_ID
  field required (type=value_error.missing)
```

**Solutions:**

1. **Create .env file:**
```bash
cp .env.example .env
```

2. **Set required environment variables:**
```bash
export AUTH0_DOMAIN="your-tenant.auth0.com"
export AUTH0_CLIENT_ID="your_client_id"
export AUTH0_AUDIENCE="https://api.your-domain.com"
export FGA_STORE_ID="your_store_id"
export FGA_CLIENT_ID="your_fga_client_id"
export FGA_CLIENT_SECRET="your_fga_secret"
```

3. **Use configuration file:**
```python
from subzero.config.defaults import Settings

settings = Settings(
    AUTH0_DOMAIN="your-tenant.auth0.com",
    AUTH0_CLIENT_ID="your_client_id",
    # ... other settings
)
```

---

### Invalid Auth0 Configuration

**Problem:** Cannot connect to Auth0 tenant.

**Symptoms:**
- 401 Unauthorized responses
- "Invalid issuer" errors
- Token validation failures

**Solutions:**

1. **Verify Auth0 domain format:**
```python
# Correct format (no https://)
AUTH0_DOMAIN="your-tenant.auth0.com"

# Incorrect
AUTH0_DOMAIN="https://your-tenant.auth0.com"  # ❌
```

2. **Check audience:**
```bash
# Must match API identifier in Auth0 dashboard
AUTH0_AUDIENCE="https://api.your-domain.com"
```

3. **Verify client credentials:**
```bash
# Test Auth0 connection
curl -X POST "https://${AUTH0_DOMAIN}/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "'${AUTH0_CLIENT_ID}'",
    "client_secret": "'${AUTH0_CLIENT_SECRET}'",
    "audience": "'${AUTH0_AUDIENCE}'"
  }'
```

---

### FGA Configuration Errors

**Problem:** Cannot connect to Auth0 FGA service.

**Solutions:**

1. **Verify store ID:**
```bash
# Get store ID from Auth0 FGA dashboard
FGA_STORE_ID="01HXXXXXXXXXXXXXXXXXXXXX"
```

2. **Check FGA API credentials:**
```bash
# Test FGA connection
curl -X GET "https://api.us1.fga.dev/stores/${FGA_STORE_ID}" \
  -H "Authorization: Bearer ${FGA_API_TOKEN}"
```

3. **Validate authorization model:**
```python
from subzero.services.authorization.rebac import ReBAC

rebac = ReBAC()
model = await rebac.get_authorization_model()
print(model)
```

---

## Authentication Problems

### Token Validation Failures

**Problem:** Valid tokens rejected by gateway.

**Error Message:** `Token signature verification failed`

**Solutions:**

1. **Verify JWKS endpoint:**
```bash
curl "https://${AUTH0_DOMAIN}/.well-known/jwks.json"
```

2. **Check token expiration:**
```python
import jwt
token = "eyJ0eXAi..."
decoded = jwt.decode(token, options={"verify_signature": False})
print(f"Expires: {decoded['exp']}")
```

3. **Validate token claims:**
```python
# Required claims
assert decoded['aud'] == settings.AUTH0_AUDIENCE
assert decoded['iss'] == f"https://{settings.AUTH0_DOMAIN}/"
```

4. **Clear token cache:**
```python
from subzero.services.auth.manager import AuthManager

auth = AuthManager()
await auth.clear_cache()
```

---

### Private Key JWT Errors

**Problem:** Client assertion rejected by Auth0.

**Error Message:** `invalid_client: Client authentication failed`

**Solutions:**

1. **Verify private key format:**
```bash
# Key must be in PEM format
head -n 1 private_key.pem
# Should output: -----BEGIN RSA PRIVATE KEY-----
```

2. **Check JWT assertion structure:**
```python
import jwt

# Correct assertion format
assertion = jwt.encode(
    {
        "iss": client_id,  # Must match client_id
        "sub": client_id,  # Must match client_id
        "aud": f"https://{auth0_domain}/oauth/token",  # Exact match
        "iat": int(time.time()),
        "exp": int(time.time()) + 300  # 5 minutes
    },
    private_key,
    algorithm="RS256",
    headers={"kid": key_id}  # Optional but recommended
)
```

3. **Verify public key in Auth0:**
- Go to Auth0 Dashboard → Applications → [Your App] → Settings
- Scroll to "Application Credentials"
- Verify public key matches your private key

4. **Test assertion manually:**
```bash
curl -X POST "https://${AUTH0_DOMAIN}/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "'${ASSERTION}'",
    "scope": "openid profile email"
  }'
```

---

### Token Expiration Issues

**Problem:** Tokens expire too quickly or not being refreshed.

**Solutions:**

1. **Adjust token lifetime:**
```python
# In Auth0 Dashboard → APIs → [Your API] → Settings
# Access Token Expiration: 86400 seconds (24 hours)
```

2. **Implement token refresh:**
```python
from subzero.services.auth.resilient import ResilientAuthService

auth = ResilientAuthService()

# Auto-refresh before expiration
token = await auth.get_token(auto_refresh=True)
```

3. **Cache valid tokens:**
```python
# Tokens cached with TTL = exp - iat - 60 (1 minute buffer)
# Clear cache if experiencing issues
await auth.clear_cache()
```

---

## Authorization Issues

### Permission Denied Errors

**Problem:** Users cannot access resources they should have access to.

**Error:** `403 Forbidden: permission_denied`

**Solutions:**

1. **Verify relationship exists:**
```python
from subzero.services.authorization.rebac import ReBAC

rebac = ReBAC()

# Check specific relationship
result = await rebac.check(
    user_id="user_123",
    resource={"type": "document", "id": "doc_456"},
    relation="viewer"
)
print(f"Has permission: {result.allowed}")
```

2. **List user permissions:**
```python
permissions = await rebac.list_user_permissions("user_123")
for perm in permissions:
    print(f"{perm.resource} - {perm.relation}")
```

3. **Check authorization model:**
```python
model = await rebac.get_authorization_model()
print(model)
```

4. **Clear authorization cache:**
```python
await rebac.clear_cache()
```

---

### FGA API Rate Limiting

**Problem:** `429 Too Many Requests` from FGA API.

**Solutions:**

1. **Increase cache hit ratio:**
```python
# config/defaults.py
CACHE_CAPACITY = 50000  # Increase from 10000
CACHE_TTL = 3600  # 1 hour
```

2. **Use batch checks:**
```python
# Instead of individual checks
for resource in resources:
    await rebac.check(user_id, resource, action)

# Use batch API
results = await rebac.batch_check(
    user_id=user_id,
    checks=[
        {"resource": r, "action": action}
        for r in resources
    ]
)
```

3. **Implement backoff strategy:**
```python
from subzero.services.auth.resilient import with_retry

@with_retry(max_attempts=3, backoff_factor=2)
async def check_permission():
    return await rebac.check(...)
```

---

### Authorization Model Errors

**Problem:** Invalid authorization model definition.

**Error:** `Invalid model: relation 'owner' not defined`

**Solutions:**

1. **Validate model syntax:**
```yaml
# Example model (DSL format)
model
  schema 1.1

type document
  relations
    define owner: [user]
    define viewer: [user] or owner
    define can_read: viewer
    define can_write: owner
```

2. **Update model in FGA:**
```python
from subzero.services.authorization.rebac import ReBAC

rebac = ReBAC()
await rebac.update_authorization_model(model_dsl)
```

3. **Test model before deployment:**
```bash
# Use FGA CLI
fga model test --file model.fga
```

---

## Performance Problems

### High Latency

**Problem:** Requests taking longer than expected (>50ms).

**Solutions:**

1. **Enable performance profiling:**
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your code here
await gateway.authenticate(request)

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

2. **Check cache hit ratio:**
```python
from subzero.services.auth.manager import AuthManager

auth = AuthManager()
stats = auth.get_cache_stats()
print(f"Cache hit ratio: {stats['hit_ratio']:.2%}")

# Target: >95% hit ratio
# If low, increase cache capacity
```

3. **Optimize Redis connection:**
```python
# config/defaults.py
REDIS_MAX_CONNECTIONS = 100  # Increase pool size
REDIS_SOCKET_KEEPALIVE = True
REDIS_SOCKET_TIMEOUT = 5
```

4. **Enable JIT compilation:**
```python
# Verify Numba is working
import numba
print(numba.__version__)

# Set Numba optimization level
os.environ['NUMBA_OPT'] = '3'
```

5. **Use connection pooling:**
```python
# Reuse HTTP client
from subzero.services.auth.manager import AuthManager

auth = AuthManager(
    connection_pool_size=100,
    connection_pool_maxsize=100
)
```

---

### Memory Leaks

**Problem:** Memory usage increases over time.

**Solutions:**

1. **Monitor memory usage:**
```python
import psutil
import os

process = psutil.Process(os.getpid())
print(f"Memory: {process.memory_info().rss / 1024 / 1024:.2f} MB")
```

2. **Limit cache size:**
```python
# config/defaults.py
CACHE_CAPACITY = 10000  # Reduce if memory constrained
```

3. **Enable garbage collection:**
```python
import gc
gc.set_threshold(700, 10, 10)
gc.collect()
```

4. **Use object pooling:**
```python
from subzero.utils.object_pool import ObjectPool

# Reuse expensive objects
client_pool = ObjectPool(factory=create_fga_client, size=10)
```

---

### Low Throughput

**Problem:** Cannot achieve target RPS (requests per second).

**Solutions:**

1. **Increase worker processes:**
```bash
# Uvicorn
uvicorn main:app --workers 4 --worker-class uvloop

# Gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
```

2. **Optimize async operations:**
```python
# Use asyncio.gather for parallel operations
results = await asyncio.gather(
    auth.validate_token(token),
    rebac.check_permission(user_id, resource, action),
    return_exceptions=True
)
```

3. **Enable request coalescing:**
```python
# config/defaults.py
ENABLE_REQUEST_COALESCING = True
COALESCING_WINDOW_MS = 10
```

4. **Use faster JSON library:**
```python
# Install orjson
pip install orjson

# FastAPI will auto-detect and use it
```

---

## Docker & Deployment

### Docker Build Failures

**Problem:** Docker build fails with errors.

**Solutions:**

1. **Check Dockerfile syntax:**
```bash
docker build --no-cache -t subzero:test .
```

2. **Verify base image:**
```dockerfile
# Use specific Python version
FROM python:3.11-slim
```

3. **Clear Docker cache:**
```bash
docker builder prune -a
```

4. **Check .dockerignore:**
```
# Exclude unnecessary files
__pycache__
*.pyc
.git
.env
venv/
```

---

### Container Startup Issues

**Problem:** Container crashes on startup.

**Solutions:**

1. **Check container logs:**
```bash
docker logs subzero-container

# Or follow logs in real-time
docker logs -f subzero-container
```

2. **Verify environment variables:**
```bash
docker exec subzero-container env | grep AUTH0
```

3. **Test with interactive shell:**
```bash
docker run -it --entrypoint /bin/bash subzero:latest
python -c "from subzero.subzeroapp import UnifiedZeroTrustGateway; print('OK')"
```

4. **Check health endpoint:**
```bash
docker exec subzero-container curl http://localhost:8000/health
```

---

### Kubernetes Deployment Issues

**Problem:** Pods failing health checks or crashing.

**Solutions:**

1. **Check pod status:**
```bash
kubectl get pods -n subzero
kubectl describe pod subzero-xxx -n subzero
```

2. **View pod logs:**
```bash
kubectl logs subzero-xxx -n subzero

# Follow logs
kubectl logs -f subzero-xxx -n subzero
```

3. **Verify ConfigMap/Secrets:**
```bash
kubectl get configmap subzero-config -n subzero -o yaml
kubectl get secret subzero-secrets -n subzero -o yaml
```

4. **Check resource limits:**
```yaml
# deployment.yaml
resources:
  requests:
    memory: "256Mi"  # Increase if OOMKilled
    cpu: "500m"
  limits:
    memory: "512Mi"
    cpu: "1000m"
```

5. **Adjust health check timing:**
```yaml
livenessProbe:
  initialDelaySeconds: 30  # Increase if slow startup
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

---

## Redis & Caching

### Redis Connection Errors

**Problem:** Cannot connect to Redis server.

**Error:** `ConnectionError: Error connecting to Redis`

**Solutions:**

1. **Verify Redis is running:**
```bash
redis-cli ping
# Should output: PONG
```

2. **Check Redis configuration:**
```python
# config/defaults.py
REDIS_HOST = "localhost"  # Or Redis service hostname
REDIS_PORT = 6379
REDIS_PASSWORD = None  # Set if authentication enabled
REDIS_DB = 0
```

3. **Test connection manually:**
```bash
redis-cli -h localhost -p 6379 ping
```

4. **Check firewall rules:**
```bash
# Allow Redis port
sudo ufw allow 6379/tcp
```

5. **Use connection retry:**
```python
from subzero.services.cache import RedisCache

cache = RedisCache(
    max_retries=3,
    retry_on_timeout=True,
    socket_connect_timeout=5
)
```

---

### Cache Inconsistency

**Problem:** Stale data returned from cache.

**Solutions:**

1. **Force cache invalidation:**
```python
from subzero.services.cache import cache_manager

# Clear all caches
await cache_manager.clear_all()

# Clear specific key
await cache_manager.delete("auth:token:user_123")
```

2. **Reduce TTL:**
```python
# config/defaults.py
CACHE_TTL = 300  # 5 minutes instead of 1 hour
```

3. **Disable cache for testing:**
```python
# config/defaults.py
ENABLE_CACHING = False
```

4. **Implement cache versioning:**
```python
# Add version to cache keys
cache_key = f"auth:token:v2:{user_id}"
```

---

### Redis Memory Issues

**Problem:** Redis running out of memory.

**Solutions:**

1. **Check memory usage:**
```bash
redis-cli info memory
```

2. **Set maxmemory policy:**
```bash
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

3. **Monitor key count:**
```bash
redis-cli DBSIZE
```

4. **Set expiration on keys:**
```python
# All cache keys should have TTL
await cache.set(key, value, ttl=3600)
```

---

## Integration Issues

### Auth0 API Errors

**Problem:** Auth0 API returning errors.

**Solutions:**

1. **Check Auth0 status:**
```bash
# Visit https://status.auth0.com
```

2. **Verify API rate limits:**
```bash
# Check response headers
curl -I "https://${AUTH0_DOMAIN}/api/v2/users"
# Look for: X-RateLimit-Limit, X-RateLimit-Remaining
```

3. **Implement exponential backoff:**
```python
from subzero.services.auth.resilient import ResilientAuthService

auth = ResilientAuthService(
    max_retries=3,
    backoff_factor=2,
    circuit_breaker_threshold=5
)
```

---

### FGA Integration Problems

**Problem:** FGA API connectivity issues.

**Solutions:**

1. **Verify FGA endpoint:**
```bash
# US region
FGA_API_URL="https://api.us1.fga.dev"

# EU region
FGA_API_URL="https://api.eu1.fga.dev"
```

2. **Check store accessibility:**
```bash
curl -X GET \
  "https://api.us1.fga.dev/stores/${FGA_STORE_ID}" \
  -H "Authorization: Bearer ${FGA_API_TOKEN}"
```

3. **Test authorization check:**
```python
from subzero.services.authorization.rebac import ReBAC

rebac = ReBAC()
result = await rebac.check(
    user_id="user_123",
    resource={"type": "test", "id": "test_1"},
    relation="viewer"
)
```

---

### MCP Transport Errors

**Problem:** MCP server communication failures.

**Solutions:**

1. **Verify transport type:**
```python
# config/defaults.py
MCP_TRANSPORT_TYPE = "stdio"  # or "sse"
```

2. **Check MCP server process:**
```bash
ps aux | grep mcp-server
```

3. **Test MCP connection:**
```python
from subzero.services.mcp.transports import TransportFactory

transport = await TransportFactory.create_transport("stdio", {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
})
```

4. **Enable MCP debugging:**
```python
import logging
logging.getLogger("subzero.services.mcp").setLevel(logging.DEBUG)
```

---

## Debugging & Logging

### Enable Debug Logging

**Problem:** Need more detailed logs for troubleshooting.

**Solution:**

```python
import logging
from subzero.utils.structured_logging import setup_logging

# Enable debug logging
setup_logging(
    log_level="DEBUG",
    structured=True,
    audit_log_file="/var/log/subzero/audit.log"
)

# Or via environment
export SUBZERO_LOG_LEVEL=DEBUG
```

---

### Structured Logging

**Problem:** Logs difficult to parse in production.

**Solution:**

```python
from subzero.utils.structured_logging import get_logger, RequestLogger

logger = get_logger(__name__)

# Use structured logging
logger.info(
    "Authentication successful",
    extra={
        "user_id": "user_123",
        "request_id": "req_456",
        "latency_ms": 2.3
    }
)

# Use request context manager
async with RequestLogger(
    logger,
    request_id="req_456",
    user_id="user_123"
):
    # All logs in this context include request_id and user_id
    await process_request()
```

---

### Performance Profiling

**Problem:** Need to identify performance bottlenecks.

**Solutions:**

1. **Use cProfile:**
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Run code
await gateway.process_request(request)

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

2. **Use line_profiler:**
```bash
pip install line_profiler

# Add @profile decorator to functions
kernprof -l -v your_script.py
```

3. **Use py-spy:**
```bash
pip install py-spy

# Profile running process
py-spy top --pid 12345

# Generate flame graph
py-spy record -o profile.svg --pid 12345
```

---

### Request Tracing

**Problem:** Need to trace requests across services.

**Solution:**

```python
from opentelemetry import trace
from subzero.utils.tracing import init_tracing

# Initialize OpenTelemetry
init_tracing(
    service_name="subzero",
    jaeger_host="localhost",
    jaeger_port=6831
)

# Use tracer
tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("authenticate") as span:
    span.set_attribute("user_id", user_id)
    result = await auth.validate_token(token)
    span.set_attribute("latency_ms", result.latency)
```

---

## Getting Help

### Community Support

- **GitHub Issues**: https://github.com/subzero-dev/subzero/issues
- **Documentation**: https://subzero.readthedocs.io
- **Examples**: https://github.com/subzero-dev/subzero/tree/main/examples

### Reporting Bugs

When reporting issues, include:

1. **Environment details:**
```bash
python --version
pip list | grep subzero
uname -a
```

2. **Configuration (sanitized):**
```bash
# Remove sensitive values
env | grep SUBZERO
```

3. **Error logs:**
```bash
# Last 100 lines with timestamps
tail -n 100 /var/log/subzero/app.log
```

4. **Minimal reproduction:**
```python
# Simplest code that reproduces the issue
from subzero.services.auth.manager import AuthManager

auth = AuthManager()
result = await auth.validate_token(token)  # Fails here
```

---

## References

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [API Reference](api.md)
- [Performance](performance.md)
- [Examples](examples.md)

---

**Last updated:** 2025-10-01
