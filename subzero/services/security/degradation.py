"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Graceful Degradation Service
Provides fallback functionality when Auth0 services are unavailable

Features:
- Cached credential validation
- Local permission evaluation
- Degraded mode configuration
- Automatic service recovery
- Audit logging of degraded operations
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum

import jwt

from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity, AuditTrailService
from subzero.services.security.health import Auth0HealthMonitor, ServiceStatus


class DegradedMode(str, Enum):
    """Degradation modes"""

    NORMAL = "normal"  # All services available
    PARTIAL = "partial"  # Some services degraded
    FULL = "full"  # All Auth0 services unavailable
    EMERGENCY = "emergency"  # Critical failures, minimal operations only


class CacheSource(str, Enum):
    """Source of cached data"""

    REDIS = "redis"
    MEMORY = "memory"
    DATABASE = "database"


@dataclass
class CachedCredential:
    """Cached authentication credential"""

    user_id: str
    token_hash: str
    claims: dict
    scopes: set[str]
    expires_at: float
    cached_at: float = field(default_factory=time.time)
    source: CacheSource = CacheSource.REDIS


@dataclass
class CachedPermission:
    """Cached authorization decision"""

    user_id: str
    resource_type: str
    resource_id: str
    relation: str
    allowed: bool
    cached_at: float = field(default_factory=time.time)
    ttl: int = 300  # 5 minutes default


@dataclass
class DegradationMetrics:
    """Metrics for degraded operations"""

    degraded_mode: DegradedMode
    started_at: float
    total_auth_attempts: int = 0
    cached_auth_success: int = 0
    cached_auth_failures: int = 0
    total_authz_checks: int = 0
    cached_authz_success: int = 0
    cached_authz_failures: int = 0
    operations_blocked: int = 0


class GracefulDegradationService:
    """
    Provides graceful degradation when Auth0 services are unavailable
    Implements multiple fallback strategies
    """

    def __init__(self, health_monitor: Auth0HealthMonitor, audit_service: AuditTrailService | None = None):
        self.health_monitor = health_monitor
        self.audit_service = audit_service or AuditTrailService()

        # Degradation state
        self.current_mode = DegradedMode.NORMAL
        self.degradation_started: float | None = None
        self.metrics = DegradationMetrics(degraded_mode=DegradedMode.NORMAL, started_at=time.time())

        # Cached credentials (in-memory fallback)
        self.credential_cache: dict[str, CachedCredential] = {}

        # Cached permissions (in-memory fallback)
        self.permission_cache: dict[str, CachedPermission] = {}

        # Degraded mode configuration
        self.config = {
            "allow_cached_auth": True,
            "allow_cached_authz": True,
            "max_degradation_time": 3600,  # 1 hour max
            "credential_cache_ttl": 1800,  # 30 minutes
            "permission_cache_ttl": 300,  # 5 minutes
            "emergency_mode_threshold": 600,  # 10 minutes
        }

        # Background monitoring
        self._monitor_task: asyncio.Task | None = None

    async def start(self):
        """Start degradation monitoring"""
        if not self._monitor_task:
            self._monitor_task = asyncio.create_task(self._monitor_health())
            print("🛡️  Graceful degradation service started")

    async def stop(self):
        """Stop degradation monitoring"""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    async def _monitor_health(self):
        """Monitor Auth0 service health and adjust degradation mode"""
        while True:
            try:
                # Check service health
                health_status = await self._assess_overall_health()

                # Update degradation mode
                new_mode = self._calculate_degradation_mode(health_status)

                if new_mode != self.current_mode:
                    await self._transition_mode(new_mode)

                # Check if we've been degraded too long
                if self.degradation_started:
                    degraded_duration = time.time() - self.degradation_started

                    if degraded_duration > self.config["max_degradation_time"]:
                        print("⚠️  Maximum degradation time exceeded - entering emergency mode")
                        await self._transition_mode(DegradedMode.EMERGENCY)

                await asyncio.sleep(10)  # Check every 10 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Health monitoring error: {e}")
                await asyncio.sleep(10)

    async def _assess_overall_health(self) -> dict[str, ServiceStatus]:
        """Assess health of all critical services"""
        health_checks = await self.health_monitor.check_all_services()

        return {service: check.status for service, check in health_checks.items()}

    def _calculate_degradation_mode(self, health_status: dict[str, ServiceStatus]) -> DegradedMode:
        """Calculate appropriate degradation mode based on service health"""
        unhealthy_services = [service for service, status in health_status.items() if status == ServiceStatus.UNHEALTHY]

        degraded_services = [service for service, status in health_status.items() if status == ServiceStatus.DEGRADED]

        # Check for emergency mode (long degradation)
        if self.degradation_started:
            degraded_duration = time.time() - self.degradation_started
            if degraded_duration > self.config["emergency_mode_threshold"]:
                return DegradedMode.EMERGENCY

        # All critical services healthy
        if not unhealthy_services and not degraded_services:
            return DegradedMode.NORMAL

        # Authentication service down
        if "authentication" in unhealthy_services:
            return DegradedMode.FULL

        # Multiple services down
        if len(unhealthy_services) >= 2:
            return DegradedMode.FULL

        # Some services degraded
        if unhealthy_services or degraded_services:
            return DegradedMode.PARTIAL

        return DegradedMode.NORMAL

    async def _transition_mode(self, new_mode: DegradedMode):
        """Transition to new degradation mode"""
        old_mode = self.current_mode
        self.current_mode = new_mode

        # Track degradation start time
        if new_mode != DegradedMode.NORMAL and not self.degradation_started:
            self.degradation_started = time.time()
            self.metrics = DegradationMetrics(degraded_mode=new_mode, started_at=self.degradation_started)
        elif new_mode == DegradedMode.NORMAL:
            self.degradation_started = None

        print(f"🔄 Degradation mode transition: {old_mode.value} → {new_mode.value}")

        # Audit log
        if self.audit_service:
            await self.audit_service.log_event(
                AuditEvent(
                    event_id=f"degradation_{time.time()}",
                    event_type=AuditEventType.CONFIG_CHANGED,
                    severity=AuditSeverity.HIGH if new_mode != DegradedMode.NORMAL else AuditSeverity.INFO,
                    actor_type="system",
                    action="degradation_mode_change",
                    metadata={
                        "old_mode": old_mode.value,
                        "new_mode": new_mode.value,
                        "degradation_duration": (
                            time.time() - self.degradation_started if self.degradation_started else 0
                        ),
                    },
                )
            )

    async def validate_credential_cached(self, token: str, force_cache: bool = False) -> tuple[bool, dict | None, str]:
        """
        Validate credential using cached data when Auth0 unavailable

        Args:
            token: JWT token to validate
            force_cache: Force cached validation even if Auth0 is available

        Returns:
            Tuple of (valid, claims, reason)
        """
        self.metrics.total_auth_attempts += 1

        # Check if we should use cache
        should_use_cache = force_cache or self.current_mode in [
            DegradedMode.PARTIAL,
            DegradedMode.FULL,
            DegradedMode.EMERGENCY,
        ]

        if not should_use_cache or not self.config["allow_cached_auth"]:
            return False, None, "cache_disabled"

        try:
            # Decode token without verification (just to get claims)
            unverified_claims = jwt.decode(token, options={"verify_signature": False})

            user_id = unverified_claims.get("sub")
            if not user_id:
                self.metrics.cached_auth_failures += 1
                return False, None, "no_user_id"

            # Compute token hash for cache lookup
            token_hash = self._hash_token(token)

            # Check credential cache
            cached = self.credential_cache.get(user_id)

            if not cached:
                self.metrics.cached_auth_failures += 1
                return False, None, "no_cached_credential"

            # Verify token hash matches
            if cached.token_hash != token_hash:
                self.metrics.cached_auth_failures += 1
                return False, None, "token_mismatch"

            # Check expiration
            if time.time() > cached.expires_at:
                self.metrics.cached_auth_failures += 1
                return False, None, "token_expired"

            # Check cache freshness
            cache_age = time.time() - cached.cached_at
            if cache_age > self.config["credential_cache_ttl"]:
                self.metrics.cached_auth_failures += 1
                return False, None, "cache_stale"

            # Successful cached validation
            self.metrics.cached_auth_success += 1

            # Audit log
            if self.audit_service:
                await self.audit_service.log_event(
                    AuditEvent(
                        event_id=f"cached_auth_{time.time()}",
                        event_type=AuditEventType.AUTH_SUCCESS,
                        severity=AuditSeverity.MEDIUM,
                        actor_id=user_id,
                        action="cached_credential_validation",
                        outcome="success",
                        metadata={
                            "degradation_mode": self.current_mode.value,
                            "cache_age_seconds": cache_age,
                            "cache_source": cached.source.value,
                        },
                    )
                )

            return True, cached.claims, "cached_success"

        except Exception as e:
            self.metrics.cached_auth_failures += 1
            return False, None, f"validation_error: {str(e)}"

    async def check_permission_cached(
        self, user_id: str, resource_type: str, resource_id: str, relation: str, force_cache: bool = False
    ) -> tuple[bool, bool | None, str]:
        """
        Check permission using cached decisions when Auth0 FGA unavailable

        Args:
            user_id: User identifier
            resource_type: Resource type
            resource_id: Resource identifier
            relation: Relation to check
            force_cache: Force cached check even if FGA is available

        Returns:
            Tuple of (cache_used, allowed, reason)
        """
        self.metrics.total_authz_checks += 1

        # Check if we should use cache
        should_use_cache = force_cache or self.current_mode in [
            DegradedMode.PARTIAL,
            DegradedMode.FULL,
            DegradedMode.EMERGENCY,
        ]

        if not should_use_cache or not self.config["allow_cached_authz"]:
            return False, None, "cache_disabled"

        # Generate cache key
        cache_key = f"{user_id}:{resource_type}:{resource_id}:{relation}"

        # Check permission cache
        cached = self.permission_cache.get(cache_key)

        if not cached:
            self.metrics.cached_authz_failures += 1
            return True, None, "no_cached_permission"

        # Check cache freshness
        cache_age = time.time() - cached.cached_at
        if cache_age > self.config["permission_cache_ttl"]:
            self.metrics.cached_authz_failures += 1
            return True, None, "cache_stale"

        # Successful cached permission check
        self.metrics.cached_authz_success += 1

        # Audit log
        if self.audit_service:
            await self.audit_service.log_event(
                AuditEvent(
                    event_id=f"cached_authz_{time.time()}",
                    event_type=(
                        AuditEventType.PERMISSION_GRANTED if cached.allowed else AuditEventType.PERMISSION_DENIED
                    ),
                    severity=AuditSeverity.LOW,
                    actor_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=f"cached_permission_check:{relation}",
                    outcome="success",
                    metadata={
                        "degradation_mode": self.current_mode.value,
                        "cache_age_seconds": cache_age,
                        "allowed": cached.allowed,
                    },
                )
            )

        return True, cached.allowed, "cached_success"

    def cache_credential(
        self, user_id: str, token: str, claims: dict, expires_at: float, source: CacheSource = CacheSource.REDIS
    ):
        """Cache credential for fallback validation"""
        token_hash = self._hash_token(token)

        scopes = set(claims.get("scope", "").split())

        self.credential_cache[user_id] = CachedCredential(
            user_id=user_id,
            token_hash=token_hash,
            claims=claims,
            scopes=scopes,
            expires_at=expires_at,
            cached_at=time.time(),
            source=source,
        )

    def cache_permission(
        self, user_id: str, resource_type: str, resource_id: str, relation: str, allowed: bool, ttl: int = 300
    ):
        """Cache permission decision for fallback checks"""
        cache_key = f"{user_id}:{resource_type}:{resource_id}:{relation}"

        self.permission_cache[cache_key] = CachedPermission(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            relation=relation,
            allowed=allowed,
            cached_at=time.time(),
            ttl=ttl,
        )

    def _hash_token(self, token: str) -> str:
        """Generate hash of token for cache lookup"""
        import hashlib

        return hashlib.sha256(token.encode()).hexdigest()

    async def should_block_operation(self, operation_type: str) -> tuple[bool, str]:
        """
        Check if operation should be blocked in current degradation mode

        Args:
            operation_type: Type of operation (e.g., 'write', 'delete', 'admin')

        Returns:
            Tuple of (should_block, reason)
        """
        if self.current_mode == DegradedMode.NORMAL:
            return False, "normal_mode"

        if self.current_mode == DegradedMode.EMERGENCY:
            # Block all write operations in emergency mode
            if operation_type in ["write", "delete", "admin", "create"]:
                self.metrics.operations_blocked += 1
                return True, "emergency_mode"

        if self.current_mode == DegradedMode.FULL:
            # Block sensitive operations in full degradation
            if operation_type in ["delete", "admin"]:
                self.metrics.operations_blocked += 1
                return True, "full_degradation"

        return False, "allowed"

    def get_degradation_status(self) -> dict:
        """Get current degradation status and metrics"""
        degradation_duration = 0
        if self.degradation_started:
            degradation_duration = time.time() - self.degradation_started

        cache_hit_rate_auth = 0
        if self.metrics.total_auth_attempts > 0:
            cache_hit_rate_auth = self.metrics.cached_auth_success / self.metrics.total_auth_attempts * 100

        cache_hit_rate_authz = 0
        if self.metrics.total_authz_checks > 0:
            cache_hit_rate_authz = self.metrics.cached_authz_success / self.metrics.total_authz_checks * 100

        return {
            "current_mode": self.current_mode.value,
            "degradation_duration_seconds": degradation_duration,
            "cached_credentials": len(self.credential_cache),
            "cached_permissions": len(self.permission_cache),
            "metrics": {
                "authentication": {
                    "total_attempts": self.metrics.total_auth_attempts,
                    "cached_success": self.metrics.cached_auth_success,
                    "cached_failures": self.metrics.cached_auth_failures,
                    "cache_hit_rate_percent": cache_hit_rate_auth,
                },
                "authorization": {
                    "total_checks": self.metrics.total_authz_checks,
                    "cached_success": self.metrics.cached_authz_success,
                    "cached_failures": self.metrics.cached_authz_failures,
                    "cache_hit_rate_percent": cache_hit_rate_authz,
                },
                "operations_blocked": self.metrics.operations_blocked,
            },
            "configuration": self.config,
        }

    async def cleanup_stale_cache(self):
        """Remove stale entries from cache"""
        current_time = time.time()

        # Clean credential cache
        stale_credentials = [
            user_id
            for user_id, cached in self.credential_cache.items()
            if (
                current_time - cached.cached_at > self.config["credential_cache_ttl"]
                or current_time > cached.expires_at
            )
        ]

        for user_id in stale_credentials:
            del self.credential_cache[user_id]

        # Clean permission cache
        stale_permissions = [
            key for key, cached in self.permission_cache.items() if current_time - cached.cached_at > cached.ttl
        ]

        for key in stale_permissions:
            del self.permission_cache[key]

        if stale_credentials or stale_permissions:
            print(f"🧹 Cleaned {len(stale_credentials)} stale credentials, {len(stale_permissions)} stale permissions")
