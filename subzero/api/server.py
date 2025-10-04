"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

FastAPI HTTP Server for Subzero Zero Trust API Gateway

Features:
- Full REST API with automatic Swagger/OpenAPI documentation
- Real UnifiedZeroTrustGateway backend integration
- Orchestrator integration for all requests (request coalescing, batching)
- Compliance integration (audit trails, GDPR, HIPAA)
- Production-ready with proper error handling
"""

import time
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from subzero import __version__
from subzero.services.auth.vault import TokenProvider, TokenType
from subzero.services.orchestrator.event_loop import RequestContext, RequestPriority
from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity
from subzero.services.security.llm_security import LLMSecurityGuard
from subzero.subzeroapp import UnifiedZeroTrustGateway

# Global gateway instance
gateway: UnifiedZeroTrustGateway | None = None
llm_security: LLMSecurityGuard | None = None

# =================================================================
# Pydantic Models
# =================================================================


class GatewayInfoResponse(BaseModel):
    """Gateway information"""

    service: str
    version: str
    status: str
    features: list[str]
    documentation: str
    health_endpoint: str
    metrics_endpoint: str


class HealthResponse(BaseModel):
    """Health check response"""

    status: str
    version: str
    uptime_seconds: float
    components: dict


class MetricsResponse(BaseModel):
    """Live performance metrics"""

    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_latency_ms: float
    threats_blocked: int
    cache_hit_rate: float
    orchestrator_efficiency: float
    uptime_seconds: float
    components: dict


class AuthenticationRequest(BaseModel):
    """Authentication request"""

    user_id: str = Field(..., min_length=1)
    token: str | None = None
    scopes: str = "openid profile email"
    source_ip: str | None = None
    user_agent: str | None = None
    device_fingerprint: str | None = None


class AuthenticationResponse(BaseModel):
    """Authentication response"""

    authenticated: bool
    user_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = "Bearer"
    risk_score: float | None = None
    threats_detected: list[str] | None = None
    orchestrator_latency_ms: float | None = None


class PromptValidationRequest(BaseModel):
    """AI prompt validation request"""

    agent_id: str = Field(..., min_length=1)
    prompt: str = Field(..., min_length=1)
    context: dict | None = None


class PromptValidationResponse(BaseModel):
    """AI prompt validation response"""

    is_safe: bool
    sanitized_prompt: str
    violations: list[dict]
    risk_score: float
    threats: list[str]
    audit_logged: bool


class TokenStoreRequest(BaseModel):
    """Token store request"""

    agent_id: str = Field(..., min_length=1)
    provider: TokenProvider
    token_data: dict
    token_type: TokenType = TokenType.ACCESS_TOKEN
    scope: str = ""
    expires_in: int | None = None
    tags: dict[str, str] | None = None


class TokenStoreResponse(BaseModel):
    """Token store response"""

    vault_reference: str
    agent_id: str
    provider: str
    stored_at: float
    encrypted: bool = True
    audit_logged: bool


class PermissionCheckRequest(BaseModel):
    """Permission check request"""

    user_id: str = Field(..., min_length=1)
    resource_type: str = Field(..., min_length=1)
    resource_id: str = Field(..., min_length=1)
    relation: str = Field(..., min_length=1)
    context: dict | None = None


class PermissionCheckResponse(BaseModel):
    """Permission check response"""

    allowed: bool
    user_id: str
    resource: str
    relation: str
    source: str
    latency_ms: float
    cached: bool
    cache_layer: str | None = None


# =================================================================
# Lifecycle
# =================================================================

start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    global gateway, llm_security

    print("🚀 Starting Subzero Zero Trust API Gateway...")
    print("=" * 60)

    gateway = UnifiedZeroTrustGateway()
    await gateway.start()

    llm_security = LLMSecurityGuard(audit_service=gateway.audit_service)

    print("✅ Gateway started successfully")
    print("✅ LLM Security Guard initialized")
    print("✅ Orchestrator running (request coalescing enabled)")
    print("✅ Compliance features active (audit trails, GDPR, HIPAA)")
    print("=" * 60)

    yield

    print("🛑 Shutting down Subzero Gateway...")
    if gateway:
        await gateway.stop()
    print("✅ Gateway stopped successfully")


# =================================================================
# FastAPI App
# =================================================================

app = FastAPI(
    title="Subzero Zero Trust API Gateway",
    description="""
Production-ready Zero Trust security gateway for AI agents.

Features: Auth0 Private Key JWT, FGA Authorization, Token Vault,
OWASP LLM Top 10 Mitigations, Threat Detection, Request Orchestration.
    """,
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =================================================================
# Dependencies
# =================================================================


def get_gateway() -> UnifiedZeroTrustGateway:
    """Get gateway instance"""
    if gateway is None:
        raise HTTPException(status_code=503, detail="Gateway not initialized")
    return gateway


def get_llm_security() -> LLMSecurityGuard:
    """Get LLM security guard"""
    if llm_security is None:
        raise HTTPException(status_code=503, detail="LLM Security Guard not initialized")
    return llm_security


def get_client_ip(request: Request) -> str:
    """Extract client IP"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# =================================================================
# Endpoints
# =================================================================


@app.get("/", response_model=GatewayInfoResponse, tags=["General"])
async def root():
    """Gateway information"""
    return GatewayInfoResponse(
        service="Subzero Zero Trust API Gateway",
        version=__version__,
        status="operational",
        features=[
            "Auth0 Private Key JWT",
            "Triple-Layer Authorization",
            "Token Vault (Double Encryption)",
            "OWASP LLM Top 10",
            "Threat Detection",
            "Request Orchestration",
            "Compliance (GDPR/HIPAA)",
        ],
        documentation="/docs",
        health_endpoint="/health",
        metrics_endpoint="/metrics",
    )


@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
async def health(gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)]):
    """Real component health check"""
    uptime = time.time() - start_time

    # Use gateway's health_status property
    health_data = gw.health_status

    return HealthResponse(
        status=health_data["status"],
        version=__version__,
        uptime_seconds=uptime,
        components=health_data["components"],
    )


@app.get("/metrics", response_model=MetricsResponse, tags=["Monitoring"])
async def metrics(gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)]):
    """Live performance metrics"""
    uptime = time.time() - start_time

    # Get orchestrator metrics safely
    if hasattr(gw.orchestrator, "get_metrics"):
        orch_metrics = gw.orchestrator.get_metrics()
    elif hasattr(gw.orchestrator, "get_performance_metrics"):
        orch_metrics = gw.orchestrator.get_performance_metrics()
    else:
        orch_metrics = {}

    rebac_stats = gw.rebac_engine.get_stats()
    abac_stats = gw.abac_engine.get_stats()

    total_checks = rebac_stats["cache_hits"] + rebac_stats["cache_misses"] + abac_stats["cache_hits"] + abac_stats["cache_misses"]
    total_hits = rebac_stats["cache_hits"] + abac_stats["cache_hits"]
    cache_hit_rate = total_hits / total_checks if total_checks > 0 else 0.0

    return MetricsResponse(
        total_requests=gw.metrics.total_requests,
        successful_requests=gw.metrics.successful_requests,
        failed_requests=gw.metrics.failed_requests,
        avg_latency_ms=gw.metrics.avg_latency_ms,
        threats_blocked=gw.metrics.threats_blocked,
        cache_hit_rate=cache_hit_rate,
        orchestrator_efficiency=orch_metrics.get("coalescing_efficiency", 0.0),
        uptime_seconds=uptime,
        components={
            "orchestrator": orch_metrics,
            "rebac_cache": rebac_stats,
            "abac_cache": abac_stats,
        },
    )


@app.post("/auth/authenticate", response_model=AuthenticationResponse, tags=["Authentication"])
async def authenticate(
    req: AuthenticationRequest,
    gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
    client_ip: Annotated[str, Depends(get_client_ip)],
):
    """Auth0 Private Key JWT authentication with orchestrator integration"""
    try:
        start = time.perf_counter()
        source_ip = req.source_ip or client_ip

        # Call gateway authenticate_request (orchestrator integration built-in)
        result = await gw.authenticate_request(
            user_id=req.user_id,
            token=req.token,
            scopes=req.scopes,
            source_ip=source_ip,
            priority=RequestPriority.HIGH,
        )
        orch_latency = (time.perf_counter() - start) * 1000

        # Extract token data
        token_data = result.get("token_data", {})
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        return AuthenticationResponse(
            authenticated=result.get("success", False),
            user_id=req.user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
            risk_score=None,  # Gateway doesn't return risk_score directly
            threats_detected=[],
            orchestrator_latency_ms=orch_latency,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}") from e


@app.post("/ai/validate-prompt", response_model=PromptValidationResponse, tags=["AI Security"])
async def validate_prompt(
    req: PromptValidationRequest,
    gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
    llm_sec: Annotated[LLMSecurityGuard, Depends(get_llm_security)],
):
    """AI prompt injection detection (OWASP LLM01 & LLM06)"""
    try:
        result = llm_sec.validate_input(agent_id=req.agent_id, user_input=req.prompt, context=req.context)
        threat_types = [v.threat_type.value for v in result.violations]

        audit_logged = False
        if not result.is_safe and result.violations:
            await gw.audit_service.log_event(
                AuditEvent(
                    event_type=AuditEventType.SECURITY_VIOLATION,
                    severity=AuditSeverity.HIGH,
                    user_id=req.agent_id,
                    details={"violation_type": "LLM_PROMPT_INJECTION", "threats": threat_types},
                )
            )
            audit_logged = True

        violations_dict = [
            {
                "threat_type": v.threat_type.value,
                "risk_level": v.risk_level.value,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in result.violations
        ]

        return PromptValidationResponse(
            is_safe=result.is_safe,
            sanitized_prompt=result.sanitized_input,
            violations=violations_dict,
            risk_score=result.risk_score,
            threats=threat_types,
            audit_logged=audit_logged,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prompt validation failed: {str(e)}") from e


@app.post("/vault/store", response_model=TokenStoreResponse, tags=["Token Vault"])
async def store_token(
    req: TokenStoreRequest,
    gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
):
    """Token vault storage with double encryption"""
    try:
        vault_ref = await gw.token_vault.store_token(
            agent_id=req.agent_id,
            provider=req.provider,
            token_data=req.token_data,
            token_type=req.token_type,
            scope=req.scope,
            expires_in=req.expires_in,
            tags=req.tags,
        )

        await gw.audit_service.log_event(
            AuditEvent(
                event_type=AuditEventType.TOKEN_ISSUED,
                severity=AuditSeverity.INFO,
                user_id=req.agent_id,
                details={"vault_reference": vault_ref, "provider": req.provider.value},
            )
        )

        return TokenStoreResponse(
            vault_reference=vault_ref,
            agent_id=req.agent_id,
            provider=req.provider.value,
            stored_at=time.time(),
            audit_logged=True,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token storage failed: {str(e)}") from e


@app.post("/authz/check", response_model=PermissionCheckResponse, tags=["Authorization"])
async def check_permission(
    req: PermissionCheckRequest,
    gw: Annotated[UnifiedZeroTrustGateway, Depends(get_gateway)],
):
    """Triple-layer authorization (Local Cache → Redis → ReBAC/ABAC → FGA)"""
    try:
        start = time.perf_counter()

        # Call gateway authorize_request (orchestrator integration built-in)
        result = await gw.authorize_request(
            user_id=req.user_id,
            resource_type=req.resource_type,
            resource_id=req.resource_id,
            relation=req.relation,
            context_data=req.context,
            priority=RequestPriority.HIGH,
        )
        latency_ms = (time.perf_counter() - start) * 1000

        # Determine cache layer based on latency
        cache_layer = "local_vectorized" if latency_ms < 1 else "redis" if latency_ms < 5 else "none"

        return PermissionCheckResponse(
            allowed=result.get("allowed", False),
            user_id=req.user_id,
            resource=f"{req.resource_type}:{req.resource_id}",
            relation=req.relation,
            source=result.get("source", "unknown"),
            latency_ms=latency_ms,
            cached=latency_ms < 5,  # Assume cached if fast
            cache_layer=cache_layer,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authorization failed: {str(e)}") from e


# =================================================================
# Middleware & Error Handlers
# =================================================================


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID for tracing"""
    import uuid

    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "error_code": f"HTTP_{exc.status_code}",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=500, content={"error": "Internal server error", "error_code": "INTERNAL_ERROR", "details": str(exc)}
    )
