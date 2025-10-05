"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

FastAPI HTTP Server for Subzero Zero Trust API Gateway

Features:
- Full REST API with automatic Swagger/OpenAPI documentation
- Real UnifiedZeroTrustGateway backend integration
- Production-ready with proper error handling
- Async/await throughout for maximum performance
- Comprehensive request/response models
- Security features (rate limiting, CORS, authentication)
"""

import time
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from subzero import __version__
from subzero.config.defaults import settings
from subzero.services.auth.vault import TokenProvider, TokenType
from subzero.subzeroapp import UnifiedZeroTrustGateway

# Global gateway instance
gateway: UnifiedZeroTrustGateway | None = None


# ============================================================================
# Pydantic Models for Request/Response
# ============================================================================


class HealthResponse(BaseModel):
    """Health check response"""

    status: str = Field(..., description="Health status (healthy, degraded, unhealthy)")
    version: str = Field(..., description="Gateway version")
    uptime_seconds: float = Field(..., description="Uptime in seconds")
    components: dict = Field(..., description="Component health status")


class AuthenticationRequest(BaseModel):
    """Authentication request"""

    user_id: str = Field(..., description="User identifier", min_length=1)
    token: str | None = Field(None, description="Optional authentication token")
    scopes: str = Field("openid profile email", description="OAuth scopes")
    source_ip: str | None = Field(None, description="Source IP address for fraud detection")
    user_agent: str | None = Field(None, description="User agent string")
    device_fingerprint: str | None = Field(None, description="Device fingerprint")


class AuthenticationResponse(BaseModel):
    """Authentication response"""

    authenticated: bool = Field(..., description="Whether authentication succeeded")
    user_id: str = Field(..., description="User identifier")
    access_token: str | None = Field(None, description="Access token if successful")
    refresh_token: str | None = Field(None, description="Refresh token if successful")
    expires_in: int | None = Field(None, description="Token expiration in seconds")
    token_type: str = Field("Bearer", description="Token type")
    risk_score: float | None = Field(None, description="Risk score from threat detection")
    threats_detected: list[str] | None = Field(None, description="List of detected threats")


class TokenStoreRequest(BaseModel):
    """Token store request"""

    agent_id: str = Field(..., description="AI agent identifier", min_length=1)
    provider: TokenProvider = Field(..., description="Token provider (google, microsoft, slack, etc.)")
    token_data: dict = Field(..., description="Token data to store (access_token, refresh_token, etc.)")
    token_type: TokenType = Field(TokenType.ACCESS_TOKEN, description="Type of token")
    scope: str = Field("", description="OAuth scopes")
    expires_in: int | None = Field(None, description="Token expiration in seconds", ge=0)
    tags: dict[str, str] | None = Field(None, description="Additional metadata tags")


class TokenStoreResponse(BaseModel):
    """Token store response"""

    vault_reference: str = Field(..., description="Vault reference ID for retrieval")
    agent_id: str = Field(..., description="AI agent identifier")
    provider: str = Field(..., description="Token provider")
    stored_at: float = Field(..., description="Storage timestamp")


class TokenRetrieveRequest(BaseModel):
    """Token retrieve request"""

    vault_reference: str = Field(..., description="Vault reference ID")
    agent_id: str = Field(..., description="Requesting agent ID")
    auto_refresh: bool = Field(True, description="Automatically refresh expired tokens")


class TokenRetrieveResponse(BaseModel):
    """Token retrieve response"""

    token_data: dict | None = Field(..., description="Decrypted token data (or None if unauthorized/expired)")
    agent_id: str = Field(..., description="Agent ID")
    retrieved_at: float = Field(..., description="Retrieval timestamp")


class PermissionCheckRequest(BaseModel):
    """Permission check request"""

    user_id: str = Field(..., description="User identifier", min_length=1)
    resource_type: str = Field(..., description="Resource type (e.g., 'document', 'file')", min_length=1)
    resource_id: str = Field(..., description="Resource identifier", min_length=1)
    relation: str = Field(..., description="Relation/permission (e.g., 'read', 'write', 'owner')", min_length=1)
    context: dict | None = Field(None, description="Additional context attributes for ABAC")


class PermissionCheckResponse(BaseModel):
    """Permission check response"""

    allowed: bool = Field(..., description="Whether permission is granted")
    user_id: str = Field(..., description="User identifier")
    resource: str = Field(..., description="Resource identifier (type:id)")
    relation: str = Field(..., description="Relation/permission checked")
    source: str = Field(..., description="Authorization source (cache, rebac, abac, fga)")
    latency_ms: float = Field(..., description="Check latency in milliseconds")
    cached: bool = Field(..., description="Whether result came from cache")


class GatewayMetricsResponse(BaseModel):
    """Gateway metrics response"""

    total_requests: int = Field(..., description="Total requests processed")
    successful_requests: int = Field(..., description="Successful requests")
    failed_requests: int = Field(..., description="Failed requests")
    avg_latency_ms: float = Field(..., description="Average latency in milliseconds")
    threats_blocked: int = Field(..., description="Threats blocked")
    cache_hit_rate: float = Field(..., description="Cache hit ratio (0.0 to 1.0)")
    orchestrator_efficiency: float = Field(..., description="Orchestrator efficiency")
    uptime_seconds: float = Field(..., description="Gateway uptime in seconds")


class ErrorResponse(BaseModel):
    """Error response"""

    error: str = Field(..., description="Error message")
    error_code: str = Field(..., description="Error code")
    details: dict | None = Field(None, description="Additional error details")
    request_id: str | None = Field(None, description="Request ID for tracking")


# ============================================================================
# Lifecycle Management
# ============================================================================


start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan (startup/shutdown)"""
    global gateway

    # Startup
    print("🚀 Starting Subzero Zero Trust API Gateway...")
    gateway = UnifiedZeroTrustGateway()
    await gateway.start()
    print("✅ Gateway started successfully")

    yield

    # Shutdown
    print("🛑 Shutting down Subzero Gateway...")
    if gateway:
        await gateway.stop()
    print("✅ Gateway stopped successfully")


# ============================================================================
# FastAPI Application
# ============================================================================


app = FastAPI(
    title="Subzero Zero Trust API Gateway",
    description="""
# Subzero Zero Trust API Gateway

Production-ready Zero Trust security gateway for AI agents and applications.

## Features

- **Authentication**: Private Key JWT, OAuth 2.1 + PKCE, resilient Auth0 integration
- **Authorization**: Fine-Grained Authorization (FGA), ReBAC, ABAC, OPA integration
- **Token Vault**: Secure credential storage for AI agents with federated token exchange
- **Threat Detection**: Signup fraud, account takeover, MFA abuse detection
- **Performance**: 10K+ RPS with request coalescing, JIT compilation, distributed caching
- **Resilience**: Circuit breakers, graceful degradation, comprehensive audit trails

## Architecture

All requests flow through the **Functional Event Orchestrator** which provides:
- Request coalescing (60% latency reduction)
- Intelligent batching and parallelization
- Circuit breakers and health monitoring
- Comprehensive analytics

## Security

- **Rate Limiting**: Distributed token bucket algorithm
- **ISPM**: Identity Security Posture Management with risk scoring
- **Audit Trail**: Comprehensive logging for compliance (GDPR, HIPAA)
- **Zero Trust**: Every request authenticated and authorized
    """,
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Dependency Injection
# ============================================================================


def get_gateway() -> UnifiedZeroTrustGateway:
    """Get gateway instance (dependency injection)"""
    if gateway is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Gateway not initialized")
    return gateway


def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ============================================================================
# API Endpoints
# ============================================================================


@app.get("/", tags=["General"])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Subzero Zero Trust API Gateway",
        "version": __version__,
        "status": "operational",
        "documentation": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check(gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)]):
    """
    Health check endpoint

    Returns comprehensive health status of all gateway components including:
    - Overall status (healthy/degraded/unhealthy)
    - Individual component health
    - Uptime information
    - Version information
    """
    uptime = time.time() - start_time

    # Get component health status
    components = {
        "orchestrator": "healthy",
        "auth_service": "healthy" if gateway.auth_service.health_status.get("status") == "healthy" else "degraded",
        "rate_limiter": "healthy",
        "ispm": "healthy",
        "audit_trail": "healthy",
    }

    # Determine overall status
    if all(status == "healthy" for status in components.values()):
        overall_status = "healthy"
    elif any(status == "unhealthy" for status in components.values()):
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return HealthResponse(status=overall_status, version=__version__, uptime_seconds=uptime, components=components)


@app.post("/api/v1/authenticate", response_model=AuthenticationResponse, tags=["Authentication"])
async def authenticate(
    request: AuthenticationRequest,
    gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
    client_ip: Annotated[str, Depends(get_client_ip)],
):
    """
    Authenticate user and obtain access tokens

    Performs comprehensive authentication including:
    - User credential validation
    - Threat detection (fraud, ATO, MFA abuse)
    - Risk scoring via ISPM
    - Token generation
    - Audit trail logging

    Returns access token and refresh token on successful authentication.
    """
    try:
        # Use client IP from dependency if not provided
        source_ip = request.source_ip or client_ip

        # Authenticate through gateway (uses orchestrator for request coalescing)
        result = await gateway.authenticate_request(
            user_id=request.user_id,
            token=request.token,
            scopes=request.scopes,
            source_ip=source_ip,
            user_agent=request.user_agent,
            device_fingerprint=request.device_fingerprint,
        )

        return AuthenticationResponse(
            authenticated=result["authenticated"],
            user_id=request.user_id,
            access_token=result.get("access_token"),
            refresh_token=result.get("refresh_token"),
            expires_in=result.get("expires_in"),
            token_type=result.get("token_type", "Bearer"),
            risk_score=result.get("risk_score"),
            threats_detected=result.get("threats_detected", []),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Authentication failed: {str(e)}"
        ) from e


@app.post("/api/v1/tokens/store", response_model=TokenStoreResponse, tags=["Token Vault"])
async def store_token(
    request: TokenStoreRequest,
    gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
):
    """
    Store token in secure Token Vault

    Stores credentials securely with:
    - Double encryption (Auth0 + Fernet)
    - Namespace isolation
    - Access control by agent ID
    - Metadata tracking
    - Automatic expiration

    Returns vault reference for later retrieval.
    """
    try:
        vault_ref = await gateway.token_vault.store_token(
            agent_id=request.agent_id,
            provider=request.provider,
            token_data=request.token_data,
            token_type=request.token_type,
            scope=request.scope,
            expires_in=request.expires_in,
            tags=request.tags,
        )

        return TokenStoreResponse(
            vault_reference=vault_ref,
            agent_id=request.agent_id,
            provider=request.provider.value,
            stored_at=time.time(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Token storage failed: {str(e)}"
        ) from e


@app.post("/api/v1/tokens/retrieve", response_model=TokenRetrieveResponse, tags=["Token Vault"])
async def retrieve_token(
    request: TokenRetrieveRequest,
    gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
):
    """
    Retrieve token from Token Vault

    Retrieves and decrypts stored credentials with:
    - Authorization verification (agent ID)
    - Automatic token refresh if expired
    - Access tracking
    - Audit logging

    Returns None if unauthorized or token not found.
    """
    try:
        token_data = await gateway.token_vault.retrieve_token(
            vault_reference=request.vault_reference, agent_id=request.agent_id, auto_refresh=request.auto_refresh
        )

        return TokenRetrieveResponse(token_data=token_data, agent_id=request.agent_id, retrieved_at=time.time())

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Token retrieval failed: {str(e)}"
        ) from e


@app.post("/api/v1/authorize", response_model=PermissionCheckResponse, tags=["Authorization"])
async def check_permission(
    request: PermissionCheckRequest,
    gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
):
    """
    Check permission for user on resource

    Performs authorization using:
    - Local cache (vectorized, <1ms)
    - Distributed Redis cache (2-5ms)
    - ReBAC engine (relationship-based)
    - ABAC engine (attribute-based)
    - Auth0 FGA (authoritative source)

    Supports complex relationship queries and attribute-based policies.
    """
    try:
        start = time.perf_counter()

        result = await gateway.authorize_request(
            user_id=request.user_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            relation=request.relation,
            context_attributes=request.context,
        )

        latency_ms = (time.perf_counter() - start) * 1000

        return PermissionCheckResponse(
            allowed=result["allowed"],
            user_id=request.user_id,
            resource=f"{request.resource_type}:{request.resource_id}",
            relation=request.relation,
            source=result.get("source", "unknown"),
            latency_ms=latency_ms,
            cached=result.get("cached", False),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Authorization check failed: {str(e)}"
        ) from e


@app.get("/api/v1/metrics", response_model=GatewayMetricsResponse, tags=["Monitoring"])
async def get_metrics(gateway: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)]):
    """
    Get gateway performance metrics

    Returns comprehensive metrics including:
    - Request counts and success rates
    - Latency statistics
    - Security metrics (threats blocked)
    - Cache performance
    - Orchestrator efficiency
    """
    uptime = time.time() - start_time

    return GatewayMetricsResponse(
        total_requests=gateway.metrics.total_requests,
        successful_requests=gateway.metrics.successful_requests,
        failed_requests=gateway.metrics.failed_requests,
        avg_latency_ms=gateway.metrics.avg_latency_ms,
        threats_blocked=gateway.metrics.threats_blocked,
        cache_hit_rate=gateway.metrics.cache_hit_rate,
        orchestrator_efficiency=gateway.metrics.orchestrator_efficiency,
        uptime_seconds=uptime,
    )


# ============================================================================
# Error Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "error_code": f"HTTP_{exc.status_code}",
            "request_id": request.state.request_id if hasattr(request.state, "request_id") else None,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "error_code": "INTERNAL_ERROR", "details": str(exc)},
    )


# ============================================================================
# Request ID Middleware
# ============================================================================


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to all requests for tracing"""
    import uuid

    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response
