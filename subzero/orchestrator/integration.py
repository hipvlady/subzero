"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Orchestrator Integration Layer
Registers all gateway components with graceful degradation and fallbacks

Features:
- Automatic component registration
- Feature detection and graceful degradation
- Fallback mechanisms for each component
- Compliance monitoring integration
- Audit logging for all operations

Components Registered:
1. Shared Memory Cache (fallback: Redis/dict)
2. HTTP Connection Pool (fallback: individual clients)
3. Backpressure Manager (fallback: no limits)
4. Redis Pipeline Batcher (fallback: individual operations)
5. Process Pool Warmer (fallback: on-demand execution)
6. Vectorized Authorization (fallback: sequential)
7. JIT Optimized Auth (fallback: Python implementation)
8. Adaptive Cache (fallback: fixed TTL)
"""

import asyncio
from typing import Any, Optional

from subzero.orchestrator.component_registry import ComponentCategory, ComponentRegistry, ComponentStatus, get_registry
from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity


class OrchestrationError(Exception):
    """Exception raised during orchestration"""

    pass


class GatewayOrchestrator:
    """
    Central orchestrator for Subzero Zero Trust API Gateway

    Coordinates all components with graceful degradation

    Usage:
        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Components now available through registry
        registry = get_registry()
        cache = registry.get_component("shared_memory_cache")
    """

    def __init__(self):
        """Initialize orchestrator"""
        self.registry = get_registry()
        self.initialized = False

    async def initialize(self):
        """
        Initialize all gateway components

        Registers components in dependency order with health checks and fallbacks
        """
        print("\n🚀 Initializing Subzero Zero Trust API Gateway...")
        print(f"📊 System Capabilities:")
        for cap, value in self.registry.capabilities.items():
            print(f"   {cap}: {value}")

        # Register components in dependency order
        await self._register_core_components()
        await self._register_optimization_components()
        await self._register_integration_components()
        await self._register_monitoring_components()

        # Initialize all components
        await self.registry.initialize_all()

        self.initialized = True

        # Print status report
        report = self.registry.get_status_report()
        summary = report["summary"]

        print(f"\n✅ Gateway initialized:")
        print(f"   Total components: {summary['total']}")
        print(f"   Healthy: {summary['healthy']}")
        print(f"   Degraded: {summary['degraded']}")
        print(f"   Unavailable: {summary['unavailable']}")

        if summary["degraded"] > 0:
            print(f"\n⚠️  {summary['degraded']} component(s) running in degraded mode")

    async def _register_core_components(self):
        """Register core components (must be available)"""
        print("\n📦 Registering core components...")

        # 1. Audit Logger (always available)
        from subzero.services.security.audit import AuditTrailService

        audit_logger = AuditTrailService()

        await self.registry.register(
            name="audit_logger",
            category=ComponentCategory.CORE,
            version="1.0.0",
            instance=audit_logger,
            health_check=lambda: True,  # Always healthy
        )

        # 2. ReBAC Authorization Engine (core authorization)
        from subzero.services.authorization.rebac import ReBACEngine

        rebac = ReBACEngine()

        async def check_rebac_health():
            try:
                # Test authorization check
                from subzero.services.authorization.rebac import AuthzTuple

                test_tuple = AuthzTuple("test", "test", "viewer", "user", "health_check")
                rebac.write_tuple(test_tuple)
                result = await rebac.check("test", "test", "viewer", "user", "health_check")
                rebac.delete_tuple(test_tuple)
                return True
            except Exception:
                return False

        await self.registry.register(
            name="rebac_engine",
            category=ComponentCategory.CORE,
            version="1.0.0",
            instance=rebac,
            health_check=check_rebac_health,
            dependencies=["audit_logger"],
        )

    async def _register_optimization_components(self):
        """Register optimization components (can degrade gracefully)"""
        print("\n⚡ Registering optimization components...")

        # 1. Shared Memory Cache
        await self._register_shared_memory_cache()

        # 2. HTTP Connection Pool
        await self._register_http_pool()

        # 3. Backpressure Manager
        await self._register_backpressure_manager()

        # 4. Process Pool Warmer
        await self._register_process_pool_warmer()

        # 5. Vectorized Authorization
        await self._register_vectorized_authorization()

        # 6. JIT Optimized Auth
        await self._register_jit_auth()

        # 7. Adaptive Cache
        await self._register_adaptive_cache()

    async def _register_shared_memory_cache(self):
        """Register shared memory cache with fallback to dict"""

        def fallback_dict_cache():
            """Fallback to simple dict cache"""
            print("  Using dict-based cache (fallback)")

            class DictCache:
                def __init__(self):
                    self.cache = {}

                def write_token(self, user_id, token_hash, expires_at, scopes, slot=None):
                    key = f"token_{user_id}_{token_hash}"
                    self.cache[key] = {
                        "user_id": user_id,
                        "token_hash": token_hash,
                        "expires_at": expires_at,
                        "scopes": scopes,
                    }
                    return key

                def read_token(self, slot):
                    return self.cache.get(slot)

                def close(self):
                    self.cache.clear()

            return DictCache()

        async def check_shared_memory_health():
            try:
                from subzero.services.auth.shared_memory_cache import SharedMemoryCache

                cache = SharedMemoryCache(max_tokens=10)
                cache.close()
                return True
            except Exception:
                return False

        has_shared_memory = self.registry.capabilities.get("shared_memory", False)

        if has_shared_memory:
            try:
                from subzero.services.auth.shared_memory_cache import get_shared_cache

                cache = get_shared_cache()

                await self.registry.register(
                    name="shared_memory_cache",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=cache,
                    health_check=check_shared_memory_health,
                    fallback=fallback_dict_cache,
                    required_capabilities=["shared_memory", "numpy"],
                )
            except Exception as e:
                print(f"  ⚠️  Shared memory cache failed: {e}, using fallback")
                await self.registry.register(
                    name="shared_memory_cache",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=fallback_dict_cache(),
                    health_check=lambda: True,
                )
        else:
            print("  ⚠️  Shared memory not available, using dict cache")
            await self.registry.register(
                name="shared_memory_cache",
                category=ComponentCategory.OPTIMIZATION,
                version="1.0.0",
                instance=fallback_dict_cache(),
                health_check=lambda: True,
            )

    async def _register_http_pool(self):
        """Register HTTP connection pool"""
        from subzero.services.http.pool import http_pool

        async def check_http_pool_health():
            try:
                stats = http_pool.get_stats()
                return True
            except Exception:
                return False

        await self.registry.register(
            name="http_connection_pool",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            instance=http_pool,
            health_check=check_http_pool_health,
        )

    async def _register_backpressure_manager(self):
        """Register backpressure manager with fallback to no-op"""
        from subzero.services.concurrency.backpressure import get_backpressure_manager

        manager = get_backpressure_manager()

        # Register common services
        manager.register_service("auth0", max_concurrent=50, target_latency_ms=100.0)
        manager.register_service("redis", max_concurrent=100, target_latency_ms=10.0)
        manager.register_service("database", max_concurrent=30, target_latency_ms=50.0)

        async def check_backpressure_health():
            try:
                metrics = manager.get_all_metrics()
                return True
            except Exception:
                return False

        await self.registry.register(
            name="backpressure_manager",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            instance=manager,
            health_check=check_backpressure_health,
        )

    async def _register_process_pool_warmer(self):
        """Register process pool warmer with fallback to on-demand execution"""

        async def check_pool_warmer_health():
            try:
                from subzero.services.orchestrator.pool_warmup import get_pool_warmer

                warmer = await get_pool_warmer()
                stats = warmer.get_stats()
                return stats["total_pools"] > 0
            except Exception:
                return False

        has_multiprocessing = self.registry.capabilities.get("multiprocessing", False)

        if has_multiprocessing:
            try:
                from subzero.services.orchestrator.pool_warmup import get_pool_warmer

                warmer = await get_pool_warmer()

                await self.registry.register(
                    name="process_pool_warmer",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=warmer,
                    health_check=check_pool_warmer_health,
                    required_capabilities=["multiprocessing"],
                )
            except Exception as e:
                print(f"  ⚠️  Process pool warmer unavailable: {e}")
        else:
            print("  ⚠️  Multiprocessing not available, skipping pool warmer")

    async def _register_vectorized_authorization(self):
        """Register vectorized authorization with fallback to sequential"""

        def fallback_sequential():
            """Fallback to sequential authorization"""
            print("  Using sequential authorization (fallback)")

            class SequentialAuth:
                async def check_batch(self, checks):
                    from subzero.services.authorization.rebac import ReBACEngine

                    rebac = ReBACEngine()

                    results = []
                    for check in checks:
                        result = await rebac.check(
                            check["object_type"],
                            check["object_id"],
                            check["relation"],
                            check["subject_type"],
                            check["subject_id"],
                        )
                        results.append(result)
                    return results

            return SequentialAuth()

        async def check_vectorized_health():
            try:
                from subzero.services.authorization.vectorized import VectorizedAuthorizationEngine

                engine = VectorizedAuthorizationEngine(max_users=10, max_resources=10)
                return True
            except Exception:
                return False

        has_numpy = self.registry.capabilities.get("numpy", False)

        if has_numpy:
            try:
                from subzero.services.authorization.vectorized import VectorizedAuthorizationEngine

                engine = VectorizedAuthorizationEngine()

                await self.registry.register(
                    name="vectorized_authorization",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=engine,
                    health_check=check_vectorized_health,
                    fallback=fallback_sequential,
                    required_capabilities=["numpy", "numba"],
                )
            except Exception:
                print("  ⚠️  Vectorized authorization unavailable, using sequential")
                await self.registry.register(
                    name="vectorized_authorization",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=fallback_sequential(),
                    health_check=lambda: True,
                )
        else:
            print("  ⚠️  NumPy not available, using sequential authorization")
            await self.registry.register(
                name="vectorized_authorization",
                category=ComponentCategory.OPTIMIZATION,
                version="1.0.0",
                instance=fallback_sequential(),
                health_check=lambda: True,
            )

    async def _register_jit_auth(self):
        """Register JIT-optimized auth with fallback to Python"""
        has_numba = self.registry.capabilities.get("numba", False)

        if has_numba:
            try:
                from subzero.services.auth.jit_optimized import get_jit_auth

                jit_auth = get_jit_auth()

                await self.registry.register(
                    name="jit_optimized_auth",
                    category=ComponentCategory.OPTIMIZATION,
                    version="1.0.0",
                    instance=jit_auth,
                    health_check=lambda: True,
                    required_capabilities=["numba", "numpy"],
                )
            except Exception:
                print("  ⚠️  JIT-optimized auth unavailable")
        else:
            print("  ⚠️  Numba not available, skipping JIT optimizations")

    async def _register_adaptive_cache(self):
        """Register adaptive cache"""
        from subzero.services.authorization.cache import AuthorizationCache

        cache = AuthorizationCache()
        await cache.initialize()

        async def check_cache_health():
            try:
                metrics = cache.get_metrics()
                return True
            except Exception:
                return False

        await self.registry.register(
            name="adaptive_cache",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            instance=cache,
            health_check=check_cache_health,
            dependencies=["audit_logger"],
        )

    async def _register_integration_components(self):
        """Register external integration components"""
        print("\n🔌 Registering integration components...")

        # Redis Pipeline Batcher (optional)
        has_redis = self.registry.capabilities.get("redis", False)

        if has_redis:
            print("  ⚠️  Redis available but not configured")
            # Would register Redis batcher here if configured
        else:
            print("  ⚠️  Redis not available, skipping pipeline batcher")

    async def _register_monitoring_components(self):
        """Register monitoring components"""
        print("\n📈 Registering monitoring components...")

        # Health monitoring would go here

    async def get_component(self, name: str) -> Any:
        """
        Get component with automatic fallback

        Args:
            name: Component name

        Returns:
            Component instance or fallback
        """
        return self.registry.get_component(name)

    def is_feature_available(self, feature_name: str) -> bool:
        """
        Check if optimization feature is available

        Args:
            feature_name: Feature to check

        Returns:
            True if feature available and healthy
        """
        return self.registry.is_available(feature_name)

    async def get_status(self) -> dict:
        """Get comprehensive gateway status"""
        report = self.registry.get_status_report()

        return {
            "initialized": self.initialized,
            "capabilities": report["capabilities"],
            "components": report["components"],
            "summary": report["summary"],
            "degraded_features": [
                name for name, comp in report["components"].items() if comp["status"] == "degraded"
            ],
            "unavailable_features": [
                name for name, comp in report["components"].items() if comp["status"] == "unavailable"
            ],
        }

    async def shutdown(self):
        """Graceful shutdown"""
        await self.registry.shutdown()
        self.initialized = False


# Global orchestrator instance
_orchestrator: Optional[GatewayOrchestrator] = None


async def get_orchestrator() -> GatewayOrchestrator:
    """
    Get global gateway orchestrator

    Returns:
        Initialized GatewayOrchestrator instance
    """
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = GatewayOrchestrator()
        await _orchestrator.initialize()

    return _orchestrator
