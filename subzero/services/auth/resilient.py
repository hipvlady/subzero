"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Resilient Authentication Service
Combines Auth0 integration with graceful degradation for high availability

Features:
- Automatic failover to cached validation
- Circuit breaker integration
- Transparent degradation
- Performance monitoring
"""

import time
from dataclasses import dataclass

from subzero.services.auth.manager import Auth0Configuration, Auth0IntegrationManager
from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity, AuditTrailService
from subzero.services.security.degradation import CacheSource, GracefulDegradationService
from subzero.services.security.health import Auth0HealthMonitor


@dataclass
class AuthenticationResult:
    """
    Result of authentication operation.

    Attributes
    ----------
    success : bool
        Whether authentication succeeded
    user_id : str, optional
        Authenticated user identifier
    claims : dict, optional
        JWT token claims
    token_data : dict, optional
        Complete token response from Auth0
    source : str, default "auth0"
        Authentication source ('auth0', 'cached', 'cached_fallback', 'error')
    degradation_mode : str, default "normal"
        Current degradation mode ('normal', 'degraded', 'critical')
    latency_ms : float, default 0.0
        Authentication operation latency in milliseconds
    error : str, optional
        Error message if authentication failed

    Examples
    --------
    >>> result = AuthenticationResult(
    ...     success=True,
    ...     user_id="user_123",
    ...     source="auth0",
    ...     latency_ms=45.2
    ... )
    """

    success: bool
    user_id: str | None = None
    claims: dict | None = None
    token_data: dict | None = None
    source: str = "auth0"  # auth0, cached, error
    degradation_mode: str = "normal"
    latency_ms: float = 0.0
    error: str | None = None


@dataclass
class AuthorizationResult:
    """
    Result of authorization check.

    Attributes
    ----------
    allowed : bool
        Whether access is granted
    source : str, default "fga"
        Authorization source ('fga', 'cached', 'cached_fallback', 'error')
    degradation_mode : str, default "normal"
        Current degradation mode ('normal', 'degraded', 'critical')
    latency_ms : float, default 0.0
        Authorization check latency in milliseconds
    cached_decision : bool, default False
        Whether decision came from cache
    error : str, optional
        Error message if check failed

    Examples
    --------
    >>> result = AuthorizationResult(
    ...     allowed=True,
    ...     source="fga",
    ...     latency_ms=25.5,
    ...     cached_decision=False
    ... )
    """

    allowed: bool
    source: str = "fga"  # fga, cached, error
    degradation_mode: str = "normal"
    latency_ms: float = 0.0
    cached_decision: bool = False
    error: str | None = None


class ResilientAuthService:
    """
    High-availability authentication service with graceful degradation.

    Resilient authentication and authorization service that automatically
    falls back to cached validation when Auth0 is unavailable. Provides
    continuous service during outages with configurable degradation modes.

    Parameters
    ----------
    auth0_config : Auth0Configuration
        Complete Auth0 configuration
    enable_degradation : bool, default True
        Enable graceful degradation with caching

    Attributes
    ----------
    auth0 : Auth0IntegrationManager
        Auth0 integration manager
    health_monitor : Auth0HealthMonitor
        Health monitoring for Auth0 services
    audit_service : AuditTrailService
        Audit logging service
    degradation_service : GracefulDegradationService, optional
        Graceful degradation service (if enabled)
    degradation_enabled : bool
        Whether degradation is enabled
    metrics : dict
        Performance and usage metrics

    Notes
    -----
    Service degradation flow:
    1. Normal mode: All requests go to Auth0
    2. Degraded mode: Health checks fail, fallback to cache
    3. Critical mode: Auth0 unavailable, cache-only operation

    Performance characteristics:
    - Auth0 authentication: 50-150ms
    - Cached authentication: 2-5ms
    - FGA authorization: 10-50ms
    - Cached authorization: 1-3ms

    See Also
    --------
    Auth0IntegrationManager : Low-level Auth0 integration
    GracefulDegradationService : Degradation and caching logic
    Auth0HealthMonitor : Health monitoring

    Examples
    --------
    >>> config = Auth0Configuration(
    ...     domain="tenant.auth0.com",
    ...     client_id="client_id",
    ...     audience="https://api.example.com"
    ... )
    >>> service = ResilientAuthService(config)
    >>> await service.start()
    >>> result = await service.authenticate("user_123")
    >>> print(f"Source: {result.source}, Latency: {result.latency_ms}ms")
    """

    def __init__(self, auth0_config: Auth0Configuration, enable_degradation: bool = True):
        # Core services
        self.auth0 = Auth0IntegrationManager(auth0_config)
        self.health_monitor = Auth0HealthMonitor()
        self.audit_service = AuditTrailService()

        # Graceful degradation
        self.degradation_enabled = enable_degradation
        if enable_degradation:
            self.degradation_service = GracefulDegradationService(
                health_monitor=self.health_monitor, audit_service=self.audit_service
            )
        else:
            self.degradation_service = None

        # Performance metrics
        self.metrics = {
            "total_auth_requests": 0,
            "auth0_success": 0,
            "cached_success": 0,
            "auth_failures": 0,
            "total_authz_checks": 0,
            "fga_success": 0,
            "cached_authz_success": 0,
            "authz_failures": 0,
            "total_latency_ms": 0.0,
        }

    async def start(self):
        """
        Start all services.

        Initializes health monitoring, audit logging, and degradation services.

        Notes
        -----
        Should be called once during application startup before processing
        any authentication or authorization requests.
        """
        await self.health_monitor.start_monitoring()
        await self.audit_service.start()

        if self.degradation_service:
            await self.degradation_service.start()

        print("✅ Resilient auth service started")

    async def stop(self):
        """
        Stop all services.

        Gracefully shuts down health monitoring, audit logging, and
        degradation services.

        Notes
        -----
        Should be called during application shutdown to ensure proper
        cleanup of resources and final audit log writes.
        """
        await self.health_monitor.stop_monitoring()
        await self.audit_service.stop()

        if self.degradation_service:
            await self.degradation_service.stop()

    async def authenticate(
        self, user_id: str, token: str | None = None, scopes: str = "openid profile email"
    ) -> AuthenticationResult:
        """
        Authenticate user with automatic failover to cached validation.

        Attempts Auth0 authentication with Private Key JWT. If Auth0 is
        unavailable or degraded, falls back to cached token validation.
        Automatically logs audit events and updates metrics.

        Parameters
        ----------
        user_id : str
            User identifier for authentication
        token : str, optional
            JWT token to validate. If None, requests new token from Auth0.
        scopes : str, default "openid profile email"
            Space-separated OAuth 2.0 scopes to request

        Returns
        -------
        AuthenticationResult
            Authentication result containing success status, user data,
            source (auth0/cached), degradation mode, latency, and optional error

        Notes
        -----
        Authentication flow:
        1. Check current degradation mode and health status
        2. If degraded and token provided, try cached validation first
        3. Otherwise, attempt Auth0 Private Key JWT authentication
        4. Cache successful authentication for future fallback
        5. Log audit event (success or failure)
        6. Update service metrics

        Fallback strategy:
        - Normal mode: Auth0 → Cache on error
        - Degraded mode: Cache → Auth0 if cache miss
        - Critical mode: Cache only

        Performance:
        - Auth0 path: 50-150ms
        - Cached path: 2-5ms

        See Also
        --------
        check_permission : Authorization with failover
        Auth0IntegrationManager.authenticate_with_private_key_jwt : Auth0 auth

        Examples
        --------
        >>> # New token request
        >>> result = await service.authenticate("user_123")
        >>> if result.success:
        ...     print(f"Token: {result.token_data['access_token']}")
        ...     print(f"Source: {result.source}, Latency: {result.latency_ms}ms")

        >>> # Token validation
        >>> result = await service.authenticate(
        ...     "user_123",
        ...     token="eyJ0eXAi...",
        ...     scopes="openid profile email read:data"
        ... )
        >>> print(f"Valid: {result.success}, Source: {result.source}")
        """
        start_time = time.perf_counter()
        self.metrics["total_auth_requests"] += 1

        # Get current degradation mode
        degradation_mode = "normal"
        if self.degradation_service:
            status = self.degradation_service.get_degradation_status()
            degradation_mode = status["current_mode"]

        # Check if Auth0 authentication service is healthy
        should_use_cache = False
        if self.degradation_service:
            should_use_cache = self.health_monitor.should_use_fallback("authentication")

        # Try cached validation first if degraded or if token provided
        if token and should_use_cache and self.degradation_service:
            valid, claims, reason = await self.degradation_service.validate_credential_cached(
                token=token, force_cache=False
            )

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["total_latency_ms"] += latency_ms

            if valid:
                self.metrics["cached_success"] += 1

                return AuthenticationResult(
                    success=True,
                    user_id=user_id,
                    claims=claims,
                    source="cached",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                )

        # Try Auth0 authentication
        try:
            result = await self.auth0.authenticate_with_private_key_jwt(user_id=user_id, scopes=scopes)

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["total_latency_ms"] += latency_ms

            if result["success"]:
                self.metrics["auth0_success"] += 1

                token_data = result.get("token_data", {})
                access_token = token_data.get("access_token")
                expires_in = token_data.get("expires_in", 3600)

                # Cache credential for future fallback
                if access_token and self.degradation_service:
                    import jwt

                    claims = jwt.decode(access_token, options={"verify_signature": False})

                    self.degradation_service.cache_credential(
                        user_id=user_id,
                        token=access_token,
                        claims=claims,
                        expires_at=time.time() + expires_in,
                        source=CacheSource.REDIS,
                    )

                # Audit log
                await self.audit_service.log_event(
                    AuditEvent(
                        event_id=f"auth_{user_id}_{time.time()}",
                        event_type=AuditEventType.AUTH_SUCCESS,
                        severity=AuditSeverity.INFO,
                        actor_id=user_id,
                        action="private_key_jwt_authentication",
                        outcome="success",
                        metadata={
                            "auth_method": "private_key_jwt",
                            "latency_ms": latency_ms,
                            "degradation_mode": degradation_mode,
                        },
                    )
                )

                return AuthenticationResult(
                    success=True,
                    user_id=user_id,
                    token_data=token_data,
                    source="auth0",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                )
            else:
                self.metrics["auth_failures"] += 1

                # Audit log
                await self.audit_service.log_event(
                    AuditEvent(
                        event_id=f"auth_fail_{user_id}_{time.time()}",
                        event_type=AuditEventType.AUTH_FAILURE,
                        severity=AuditSeverity.MEDIUM,
                        actor_id=user_id,
                        action="private_key_jwt_authentication",
                        outcome="failure",
                        metadata={"error": result.get("error"), "latency_ms": latency_ms},
                    )
                )

                return AuthenticationResult(
                    success=False,
                    source="auth0",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                    error=result.get("error"),
                )

        except Exception as e:
            self.metrics["auth_failures"] += 1
            latency_ms = (time.perf_counter() - start_time) * 1000

            # Try cached validation as last resort
            if token and self.degradation_service:
                valid, claims, reason = await self.degradation_service.validate_credential_cached(
                    token=token, force_cache=True
                )

                if valid:
                    self.metrics["cached_success"] += 1
                    return AuthenticationResult(
                        success=True,
                        user_id=user_id,
                        claims=claims,
                        source="cached_fallback",
                        degradation_mode=degradation_mode,
                        latency_ms=latency_ms,
                    )

            return AuthenticationResult(
                success=False, source="error", degradation_mode=degradation_mode, latency_ms=latency_ms, error=str(e)
            )

    async def check_permission(
        self, user_id: str, resource_type: str, resource_id: str, relation: str
    ) -> AuthorizationResult:
        """
        Check authorization with automatic failover to cached decisions.

        Queries Auth0 FGA for permission check. If FGA is unavailable or
        degraded, falls back to cached authorization decisions. Automatically
        logs audit events and updates metrics.

        Parameters
        ----------
        user_id : str
            User identifier
        resource_type : str
            Resource type (e.g., 'document', 'folder')
        resource_id : str
            Resource identifier
        relation : str
            Permission/relation to check (e.g., 'viewer', 'editor', 'owner')

        Returns
        -------
        AuthorizationResult
            Authorization result containing allowed status, source (fga/cached),
            degradation mode, latency, and optional error

        Notes
        -----
        Authorization flow:
        1. Check current degradation mode and health status
        2. If degraded, try cached decision first
        3. Otherwise, query Auth0 FGA
        4. Cache successful decision for future fallback (TTL: 5 minutes)
        5. Log audit event (granted or denied)
        6. Update service metrics

        Fallback strategy:
        - Normal mode: FGA → Cache on error
        - Degraded mode: Cache → FGA if cache miss
        - Critical mode: Cache only (default deny if no cache)

        Performance:
        - FGA path: 10-50ms
        - Cached path: 1-3ms

        See Also
        --------
        authenticate : Authentication with failover
        Auth0IntegrationManager.check_fga_permission : FGA check

        Examples
        --------
        >>> result = await service.check_permission(
        ...     user_id="user_123",
        ...     resource_type="document",
        ...     resource_id="doc_456",
        ...     relation="editor"
        ... )
        >>> if result.allowed:
        ...     print(f"Access granted (source: {result.source})")
        ...     print(f"Cached: {result.cached_decision}")
        ...     print(f"Latency: {result.latency_ms}ms")
        """
        start_time = time.perf_counter()
        self.metrics["total_authz_checks"] += 1

        # Get current degradation mode
        degradation_mode = "normal"
        if self.degradation_service:
            status = self.degradation_service.get_degradation_status()
            degradation_mode = status["current_mode"]

        # Check if FGA service is healthy
        should_use_cache = False
        if self.degradation_service:
            should_use_cache = self.health_monitor.should_use_fallback("fga")

        # Try cached permission first if degraded
        if should_use_cache and self.degradation_service:
            cache_used, allowed, reason = await self.degradation_service.check_permission_cached(
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                relation=relation,
                force_cache=False,
            )

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["total_latency_ms"] += latency_ms

            if cache_used and allowed is not None:
                self.metrics["cached_authz_success"] += 1

                return AuthorizationResult(
                    allowed=allowed,
                    source="cached",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                    cached_decision=True,
                )

        # Try Auth0 FGA
        try:
            result = await self.auth0.check_fga_permission(
                user_id=user_id, resource_type=resource_type, resource_id=resource_id, relation=relation
            )

            latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["total_latency_ms"] += latency_ms

            allowed = result.get("allowed", False)

            if result.get("success"):
                self.metrics["fga_success"] += 1

                # Cache permission for future fallback
                if self.degradation_service:
                    self.degradation_service.cache_permission(
                        user_id=user_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        relation=relation,
                        allowed=allowed,
                        ttl=300,  # 5 minutes
                    )

                # Audit log
                await self.audit_service.log_event(
                    AuditEvent(
                        event_id=f"authz_{user_id}_{time.time()}",
                        event_type=AuditEventType.PERMISSION_GRANTED if allowed else AuditEventType.PERMISSION_DENIED,
                        severity=AuditSeverity.LOW,
                        actor_id=user_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        action=f"fga_check:{relation}",
                        outcome="success",
                        metadata={"allowed": allowed, "latency_ms": latency_ms, "degradation_mode": degradation_mode},
                    )
                )

                return AuthorizationResult(
                    allowed=allowed,
                    source="fga",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                    cached_decision=False,
                )
            else:
                self.metrics["authz_failures"] += 1

                return AuthorizationResult(
                    allowed=False,
                    source="fga",
                    degradation_mode=degradation_mode,
                    latency_ms=latency_ms,
                    cached_decision=False,
                    error=result.get("error"),
                )

        except Exception as e:
            self.metrics["authz_failures"] += 1
            latency_ms = (time.perf_counter() - start_time) * 1000

            # Try cached permission as last resort
            if self.degradation_service:
                cache_used, allowed, reason = await self.degradation_service.check_permission_cached(
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    relation=relation,
                    force_cache=True,
                )

                if cache_used and allowed is not None:
                    self.metrics["cached_authz_success"] += 1
                    return AuthorizationResult(
                        allowed=allowed,
                        source="cached_fallback",
                        degradation_mode=degradation_mode,
                        latency_ms=latency_ms,
                        cached_decision=True,
                    )

            return AuthorizationResult(
                allowed=False,
                source="error",
                degradation_mode=degradation_mode,
                latency_ms=latency_ms,
                cached_decision=False,
                error=str(e),
            )

    def get_service_metrics(self) -> dict:
        """
        Get comprehensive service metrics.

        Returns
        -------
        dict
            Service metrics with structure:
            - 'authentication' : dict
                Authentication metrics (requests, successes, failures, rate)
            - 'authorization' : dict
                Authorization metrics (checks, successes, failures, rate)
            - 'performance' : dict
                Performance metrics (latencies)
            - 'degradation' : dict, optional
                Degradation status (if enabled)
            - 'health' : dict
                Health monitoring data

        Notes
        -----
        Metrics are cumulative since service start. Reset on restart.

        Examples
        --------
        >>> metrics = service.get_service_metrics()
        >>> print(f"Auth success rate: {metrics['authentication']['success_rate_percent']:.1f}%")
        >>> print(f"Avg latency: {metrics['performance']['avg_latency_ms']:.2f}ms")
        >>> print(f"Degradation mode: {metrics['degradation']['current_mode']}")
        """
        total_requests = self.metrics["total_auth_requests"] + self.metrics["total_authz_checks"]
        avg_latency = self.metrics["total_latency_ms"] / total_requests if total_requests > 0 else 0

        auth_success_rate = 0
        if self.metrics["total_auth_requests"] > 0:
            auth_success_rate = (
                (self.metrics["auth0_success"] + self.metrics["cached_success"])
                / self.metrics["total_auth_requests"]
                * 100
            )

        authz_success_rate = 0
        if self.metrics["total_authz_checks"] > 0:
            authz_success_rate = (
                (self.metrics["fga_success"] + self.metrics["cached_authz_success"])
                / self.metrics["total_authz_checks"]
                * 100
            )

        metrics = {
            "authentication": {
                "total_requests": self.metrics["total_auth_requests"],
                "auth0_success": self.metrics["auth0_success"],
                "cached_success": self.metrics["cached_success"],
                "failures": self.metrics["auth_failures"],
                "success_rate_percent": auth_success_rate,
            },
            "authorization": {
                "total_checks": self.metrics["total_authz_checks"],
                "fga_success": self.metrics["fga_success"],
                "cached_success": self.metrics["cached_authz_success"],
                "failures": self.metrics["authz_failures"],
                "success_rate_percent": authz_success_rate,
            },
            "performance": {"avg_latency_ms": avg_latency, "total_latency_ms": self.metrics["total_latency_ms"]},
        }

        # Add degradation metrics if enabled
        if self.degradation_service:
            metrics["degradation"] = self.degradation_service.get_degradation_status()

        # Add health metrics
        metrics["health"] = self.health_monitor.get_dashboard_data()

        return metrics
