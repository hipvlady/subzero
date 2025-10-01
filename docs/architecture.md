# Subzero Architecture

## System Overview

Subzero is a high-performance Zero Trust API Gateway designed for AI-native applications. It provides enterprise-grade authentication, authorization, and security features with sub-10ms latency and support for 10,000+ requests per second.

## Architecture Principles

### 1. Zero Trust Security
- **Never trust, always verify**: Every request is authenticated and authorized
- **Secretless authentication**: Private Key JWT (RFC 7523) eliminates shared secrets
- **Fine-grained authorization**: Document-level permissions with ReBAC and ABAC
- **Continuous validation**: Real-time threat detection and anomaly analysis

### 2. High Performance
- **JIT Compilation**: Numba-optimized critical paths
- **Contiguous Memory**: NumPy arrays for cache efficiency
- **AsyncIO Pipeline**: Non-blocking I/O for concurrent requests
- **Multi-layer Caching**: In-memory, Redis, and Auth0 validation

### 3. AI-Native Design
- **MCP Protocol**: Model Context Protocol for AI agent communication
- **Token Vault**: Secure credential storage for AI agents
- **XAA Protocol**: Extended authentication for agent-to-agent flows
- **Prompt Injection Detection**: OWASP LLM Top 10 mitigations

## System Components

```
┌──────────────────────────────────────────────────────────────┐
│                  Subzero Zero Trust Gateway                   │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │           Functional Event Orchestrator                 │  │
│  │                                                         │  │
│  │  • Priority-based scheduling                           │  │
│  │  • Request coalescing                                  │  │
│  │  • Circuit breakers                                    │  │
│  │  • Adaptive rate limiting                              │  │
│  └────────────────────────────────────────────────────────┘  │
│                           ↓                                   │
│  ┌───────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ Auth      │  │ Authorization│  │ Security            │  │
│  │           │  │              │  │                     │  │
│  │ • PKI JWT │  │ • ReBAC      │  │ • Threat Detection  │  │
│  │ • OAuth2.1│  │ • ABAC       │  │ • Bot Detection     │  │
│  │ • XAA     │  │ • OPA        │  │ • ISPM              │  │
│  │ • Vault   │  │ • FGA        │  │ • Rate Limiting     │  │
│  └───────────┘  └──────────────┘  └─────────────────────┘  │
│                           ↓                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                 Resilience Layer                        │  │
│  │                                                         │  │
│  │  • Health monitoring                                   │  │
│  │  • Graceful degradation                                │  │
│  │  • Circuit breakers                                    │  │
│  │  • Fallback mechanisms                                 │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Core Modules

### Authentication Layer (`subzero.services.auth`)

#### Private Key JWT (`jwt.py`)
- **Purpose**: RFC 7523 compliant authentication
- **Performance**: JIT-compiled token validation
- **Caching**: Multi-layer token cache (LRU → Redis → Auth0)
- **Features**:
  - Asymmetric key cryptography
  - Token generation and validation
  - Automatic key rotation
  - Sub-10ms validation time

#### OAuth 2.1 + PKCE (`oauth.py`)
- **Purpose**: Secure authorization code flow
- **Standards**: OAuth 2.1 with PKCE (RFC 7636)
- **Features**:
  - Dynamic client registration
  - Metadata discovery
  - Token refresh
  - State validation

#### XAA Protocol (`xaa.py`)
- **Purpose**: Extended authentication for AI agents
- **Features**:
  - Agent-to-agent authentication
  - Token delegation chains
  - Scope inheritance
  - Delegation depth limits

#### Token Vault (`vault.py`)
- **Purpose**: Secure credential storage for AI agents
- **Features**:
  - Encrypted storage
  - Time-based access
  - Audit logging
  - Automatic rotation

### Authorization Layer (`subzero.services.authorization`)

#### ReBAC Engine (`rebac.py`)
- **Purpose**: Relationship-Based Access Control
- **Model**: Google Zanzibar-inspired
- **Features**:
  - Graph-based permissions
  - Transitive relationships
  - Hierarchical permissions
  - Real-time permission checks

#### ABAC Engine (`abac.py`)
- **Purpose**: Attribute-Based Access Control
- **Model**: XACML-compatible
- **Features**:
  - Policy-based decisions
  - Dynamic attributes
  - Context-aware rules
  - Temporal conditions

#### OPA Integration (`opa.py`)
- **Purpose**: Open Policy Agent integration
- **Features**:
  - Rego policy evaluation
  - Batch decision making
  - Policy compilation
  - Bundle management

#### FGA Manager (`manager.py`)
- **Purpose**: Auth0 Fine-Grained Authorization
- **Features**:
  - Store management
  - Tuple operations
  - Permission caching
  - Consistency guarantees

### Security Layer (`subzero.services.security`)

#### Threat Detection (`threat_detection.py`)
- **Purpose**: ML-powered threat analysis
- **Detectors**:
  - Signup fraud detection
  - Account takeover protection
  - MFA abuse detection
  - Anomaly detection
- **Features**:
  - Real-time scoring
  - Pattern recognition
  - Behavioral analysis
  - Automatic blocking

#### ISPM - Identity Security Posture Management (`ispm.py`)
- **Purpose**: Continuous identity security assessment
- **Features**:
  - Risk scoring
  - Compliance monitoring
  - Policy enforcement
  - Incident response

#### Rate Limiter (`rate_limiter.py`)
- **Purpose**: Distributed rate limiting
- **Algorithms**:
  - Token bucket
  - Sliding window
  - Fixed window
- **Features**:
  - Per-user limits
  - Per-endpoint limits
  - Burst handling
  - Redis-backed

#### Health Monitor (`health.py`)
- **Purpose**: Service health monitoring
- **Features**:
  - Endpoint health checks
  - Circuit breaker management
  - Degradation detection
  - Automatic recovery

### MCP Layer (`subzero.services.mcp`)

#### Capabilities (`capabilities.py`)
- **Purpose**: Dynamic capability discovery
- **Features**:
  - Capability registration
  - Dynamic loading
  - Version management
  - Dependency resolution

#### Transports (`transports.py`)
- **Purpose**: Multiple transport protocols
- **Supported**:
  - WebSocket (bi-directional)
  - Server-Sent Events (SSE)
  - HTTP Long Polling
  - gRPC
- **Features**:
  - Protocol negotiation
  - Connection pooling
  - Automatic reconnection
  - Compression support

### Orchestrator (`subzero.services.orchestrator`)

#### Event Loop (`event_loop.py`)
- **Purpose**: High-performance request orchestration
- **Features**:
  - Priority-based scheduling
  - Request coalescing
  - Circuit breakers
  - Load balancing
  - Performance metrics

#### Multiprocessing (`multiprocessing.py`)
- **Purpose**: CPU-bound task parallelization
- **Features**:
  - Process pool management
  - Task distribution
  - Result aggregation
  - Numba JIT optimization

## Data Flow

### Authentication Flow

```
1. Client Request
   ↓
2. JWT Extraction
   ↓
3. Cache Lookup (in-memory)
   ├─ Hit → Return cached result
   └─ Miss ↓
4. Cache Lookup (Redis)
   ├─ Hit → Return cached result
   └─ Miss ↓
5. Auth0 Validation
   ↓
6. Cache Store (Redis + Memory)
   ↓
7. Return validated claims
```

### Authorization Flow

```
1. Authenticated Request
   ↓
2. Extract user + resource
   ↓
3. Check permission cache
   ├─ Hit → Return decision
   └─ Miss ↓
4. Evaluate policies (ReBAC/ABAC/OPA)
   ↓
5. Check FGA store
   ↓
6. Cache decision
   ↓
7. Return allow/deny
```

### Request Processing Pipeline

```
1. Request arrives
   ↓
2. Rate limiting check
   ↓
3. Threat detection
   ↓
4. Authentication
   ↓
5. Authorization
   ↓
6. Request coalescing (if duplicate)
   ↓
7. Route to backend
   ↓
8. Response aggregation
   ↓
9. Audit logging
   ↓
10. Return response
```

## Performance Optimizations

### 1. JIT Compilation (Numba)
- Token validation functions
- Permission checking
- Threat scoring
- Cache operations

### 2. Contiguous Memory (NumPy)
- Token cache arrays
- Permission cache matrices
- Metrics buffers
- Request queues

### 3. Caching Strategy
- **L1**: In-memory LRU (100ms TTL)
- **L2**: Redis (5 minute TTL)
- **L3**: Auth0/FGA (authoritative)

### 4. AsyncIO
- Non-blocking I/O
- Concurrent request handling
- Event-driven architecture
- Connection pooling

## Deployment Architecture

### Standalone Mode
```
┌─────────────┐
│   Subzero   │
│   Gateway   │
└─────────────┘
      │
      ├─ Auth0 (authentication)
      ├─ Auth0 FGA (authorization)
      └─ Redis (caching)
```

### High Availability Mode
```
┌──────────────────────────────────┐
│        Load Balancer             │
└──────────────────────────────────┘
      │         │         │
   ┌──┴──┐   ┌──┴──┐   ┌──┴──┐
   │ SZ1 │   │ SZ2 │   │ SZ3 │
   └──┬──┘   └──┬──┘   └──┬──┘
      │         │         │
      └─────────┴─────────┘
            │
      ┌─────┴─────┐
      │   Redis   │
      │  Cluster  │
      └───────────┘
```

### Kubernetes Deployment
```
┌─────────────────────────────────────┐
│         Ingress Controller          │
└─────────────────────────────────────┘
                 │
┌─────────────────────────────────────┐
│      Subzero Deployment             │
│  (3 replicas, HPA enabled)          │
└─────────────────────────────────────┘
         │              │
    ┌────┴────┐    ┌───┴────┐
    │ Redis   │    │ Auth0  │
    │ Service │    │ Cloud  │
    └─────────┘    └────────┘
```

## Security Architecture

### Defense in Depth

1. **Network Layer**
   - TLS 1.2+ encryption
   - Certificate pinning
   - DDoS protection

2. **Transport Layer**
   - Rate limiting
   - IP filtering
   - Geographic restrictions

3. **Application Layer**
   - Input validation
   - Output encoding
   - CORS policies

4. **Authentication Layer**
   - Multi-factor authentication
   - Token rotation
   - Session management

5. **Authorization Layer**
   - Fine-grained permissions
   - Least privilege
   - Permission auditing

6. **Data Layer**
   - Encryption at rest
   - Encryption in transit
   - PII protection

## Monitoring and Observability

### Metrics (Prometheus)
- Request rate
- Latency (p50, p95, p99)
- Error rate
- Cache hit ratio
- Authentication success/failure
- Authorization decisions

### Logging (Structured JSON)
- Request logs
- Authentication events
- Authorization decisions
- Security events
- Error logs
- Audit trail

### Tracing (OpenTelemetry)
- Distributed tracing
- Service dependency mapping
- Latency analysis
- Error tracking

## Configuration

Configuration follows the 12-factor app methodology:
- Environment variables for runtime config
- Traitlets for advanced configuration
- Sensible secure defaults
- Validation on startup

See [configuration.md](configuration.md) for details.

## Scalability

### Horizontal Scaling
- Stateless design
- Shared Redis cache
- Load balancer distribution

### Vertical Scaling
- Multi-core utilization
- NumPy vectorization
- Numba JIT compilation

### Performance Targets
- **Throughput**: 10,000+ RPS per instance
- **Latency**: <10ms (cached), <50ms (uncached)
- **Concurrency**: 10,000+ connections
- **Cache hit ratio**: >95%

## References

- [Configuration Guide](configuration.md)
- [Deployment Guide](deployment.md)
- [Security Policy](../SECURITY.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
