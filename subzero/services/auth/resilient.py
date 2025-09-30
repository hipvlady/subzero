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
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass

from subzero.services.auth.manager import Auth0IntegrationManager, Auth0Configuration
from subzero.services.security.health import Auth0HealthMonitor
from subzero.services.security.degradation import GracefulDegradationService, DegradedMode, CacheSource
from subzero.services.security.audit import AuditTrailService, AuditEvent, AuditEventType, AuditSeverity


@dataclass
class AuthenticationResult:
    """Result of authentication operation"""

    success: bool
    user_id: Optional[str] = None
    claims: Optional[Dict] = None
    token_data: Optional[Dict] = None
    source: str = "auth0"  # auth0, cached, error
    degradation_mode: str = "normal"
    latency_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class AuthorizationResult:
    """Result of authorization check"""

    allowed: bool
    source: str = "fga"  # fga, cached, error
    degradation_mode: str = "normal"
    latency_ms: float = 0.0
    cached_decision: bool = False
    error: Optional[str] = None


class ResilientAuthService:
    """
    High-availability authentication service with graceful degradation
    Automatically falls back to cached validation when Auth0 is unavailable
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
        """Start all services"""
        await self.health_monitor.start_monitoring()
        await self.audit_service.start()

        if self.degradation_service:
            await self.degradation_service.start()

        print("✅ Resilient auth service started")

    async def stop(self):
        """Stop all services"""
        await self.health_monitor.stop_monitoring()
        await self.audit_service.stop()

        if self.degradation_service:
            await self.degradation_service.stop()

    async def authenticate(
        self, user_id: str, token: Optional[str] = None, scopes: str = "openid profile email"
    ) -> AuthenticationResult:
        """
        Authenticate user with automatic failover to cached validation

        Args:
            user_id: User identifier
            token: Optional JWT token to validate
            scopes: Requested scopes (if issuing new token)

        Returns:
            AuthenticationResult with success status and metadata
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
        Check authorization with automatic failover to cached decisions

        Args:
            user_id: User identifier
            resource_type: Resource type
            resource_id: Resource identifier
            relation: Relation to check

        Returns:
            AuthorizationResult with decision and metadata
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

    def get_service_metrics(self) -> Dict:
        """Get comprehensive service metrics"""
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
