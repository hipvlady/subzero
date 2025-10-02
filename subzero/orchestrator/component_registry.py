"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Component Registry with Graceful Degradation
Centralized registry for all gateway components with health checks and fallbacks

Features:
- Component registration and lifecycle management
- Health checks with automatic degradation
- Fallback mechanisms for unavailable features
- Audit logging integration
- Compliance monitoring
- Graceful shutdown coordination

Architecture:
- Registry pattern for component discovery
- Health check polling with circuit breakers
- Automatic feature detection (SIMD, Numba, Redis, etc.)
- Fallback chain for missing dependencies
"""

import asyncio
import platform
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity, AuditTrailService


class ComponentStatus(str, Enum):
    """Component health status"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STARTING = "starting"
    STOPPING = "stopping"


class ComponentCategory(str, Enum):
    """Component categories for organization"""

    CORE = "core"  # Essential components (must be available)
    OPTIMIZATION = "optimization"  # Performance optimizations (can degrade)
    INTEGRATION = "integration"  # External integrations (can fail)
    MONITORING = "monitoring"  # Observability components


@dataclass
class ComponentMetadata:
    """Metadata for registered component"""

    name: str
    category: ComponentCategory
    version: str
    status: ComponentStatus = ComponentStatus.STARTING
    dependencies: list[str] = field(default_factory=list)
    health_check: Optional[Callable] = None
    fallback: Optional[Callable] = None
    last_check: float = 0.0
    check_interval: float = 60.0  # Check every 60 seconds
    error_count: int = 0
    max_errors: int = 3  # Degrade after 3 consecutive errors
    features: dict[str, bool] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)


class ComponentRegistry:
    """
    Central registry for all gateway components

    Features:
    - Component registration with metadata
    - Automatic health checking
    - Graceful degradation for failures
    - Fallback mechanism coordination
    - Audit logging for all state changes
    - Compliance reporting

    Usage:
        registry = ComponentRegistry()

        # Register component
        await registry.register(
            name="shared_memory_cache",
            category=ComponentCategory.OPTIMIZATION,
            health_check=check_shared_memory,
            fallback=use_redis_cache
        )

        # Check if available
        if registry.is_available("shared_memory_cache"):
            cache = registry.get_component("shared_memory_cache")
    """

    def __init__(self):
        """Initialize component registry"""
        self.components: dict[str, ComponentMetadata] = {}
        self.instances: dict[str, Any] = {}

        # Health check task
        self.health_check_task: Optional[asyncio.Task] = None
        self.is_running = False

        # Audit logger
        self.audit_logger = AuditTrailService()

        # System capabilities detection
        self.capabilities = self._detect_capabilities()

    def _detect_capabilities(self) -> dict[str, bool]:
        """
        Detect available system capabilities

        Returns:
            Dictionary of capability flags
        """
        capabilities = {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "platform": platform.system(),
            "architecture": platform.machine(),
        }

        # Check for optional dependencies
        try:
            import numba

            capabilities["numba"] = True
            capabilities["numba_version"] = numba.__version__
        except ImportError:
            capabilities["numba"] = False

        try:
            import numpy

            capabilities["numpy"] = True
            capabilities["numpy_version"] = numpy.__version__
        except ImportError:
            capabilities["numpy"] = False

        try:
            import redis

            capabilities["redis"] = True
        except ImportError:
            capabilities["redis"] = False

        try:
            import multiprocessing

            capabilities["multiprocessing"] = True
            capabilities["cpu_count"] = multiprocessing.cpu_count()
        except Exception:
            capabilities["multiprocessing"] = False

        try:
            from multiprocessing import shared_memory

            capabilities["shared_memory"] = True
        except ImportError:
            capabilities["shared_memory"] = False

        # Check SIMD capabilities (approximate)
        try:
            import numpy as np

            # Try vectorized operation
            arr = np.array([1, 2, 3, 4])
            _ = arr * 2
            capabilities["simd"] = True
        except Exception:
            capabilities["simd"] = False

        return capabilities

    async def register(
        self,
        name: str,
        category: ComponentCategory,
        version: str = "1.0.0",
        instance: Any = None,
        dependencies: Optional[list[str]] = None,
        health_check: Optional[Callable] = None,
        fallback: Optional[Callable] = None,
        check_interval: float = 60.0,
        required_capabilities: Optional[list[str]] = None,
    ) -> bool:
        """
        Register component with registry

        Args:
            name: Component identifier
            category: Component category
            version: Component version
            instance: Component instance (optional)
            dependencies: List of required component names
            health_check: Async function to check component health
            fallback: Async function to use as fallback
            check_interval: Health check interval in seconds
            required_capabilities: List of required system capabilities

        Returns:
            True if registration successful
        """
        # Check required capabilities
        if required_capabilities:
            missing = [cap for cap in required_capabilities if not self.capabilities.get(cap, False)]
            if missing:
                await self._log_audit(
                    f"Component '{name}' registration failed: missing capabilities {missing}",
                    AuditEventType.SYSTEM_ERROR,
                    AuditSeverity.MEDIUM,
                )

                if category == ComponentCategory.CORE:
                    raise RuntimeError(f"Core component '{name}' requires capabilities: {missing}")

                # Non-core component can degrade
                print(f"⚠️  Component '{name}' degraded: missing {missing}")
                return False

        metadata = ComponentMetadata(
            name=name,
            category=category,
            version=version,
            dependencies=dependencies or [],
            health_check=health_check,
            fallback=fallback,
            check_interval=check_interval,
            status=ComponentStatus.HEALTHY,
        )

        self.components[name] = metadata

        if instance is not None:
            self.instances[name] = instance

        await self._log_audit(
            f"Component '{name}' registered (v{version}, {category.value})",
            AuditEventType.SYSTEM_ERROR,
            AuditSeverity.INFO,
        )

        print(f"✅ Registered component: {name} (v{version}, {category.value})")

        return True

    async def initialize_all(self):
        """
        Initialize all registered components

        Starts health checking and initializes components in dependency order
        """
        # Sort by dependencies (topological sort)
        sorted_components = self._topological_sort()

        for component_name in sorted_components:
            metadata = self.components[component_name]

            # Check dependencies
            for dep in metadata.dependencies:
                if dep not in self.components:
                    await self._log_audit(
                        f"Component '{component_name}' missing dependency '{dep}'",
                        AuditEventType.SYSTEM_ERROR,
                        AuditSeverity.HIGH,
                    )

                    if metadata.category == ComponentCategory.CORE:
                        raise RuntimeError(f"Core component '{component_name}' missing required dependency '{dep}'")

                    metadata.status = ComponentStatus.DEGRADED
                    continue

                dep_status = self.components[dep].status
                if dep_status != ComponentStatus.HEALTHY:
                    await self._log_audit(
                        f"Component '{component_name}' dependency '{dep}' is {dep_status.value}",
                        AuditEventType.SYSTEM_ERROR,
                        AuditSeverity.MEDIUM,
                    )

                    if metadata.category == ComponentCategory.CORE:
                        raise RuntimeError(f"Core component '{component_name}' requires healthy dependency '{dep}'")

                    metadata.status = ComponentStatus.DEGRADED

            # Run initial health check
            if metadata.health_check:
                try:
                    # Handle both async and sync health checks
                    if asyncio.iscoroutinefunction(metadata.health_check):
                        is_healthy = await metadata.health_check()
                    else:
                        is_healthy = metadata.health_check()
                    metadata.status = ComponentStatus.HEALTHY if is_healthy else ComponentStatus.DEGRADED
                except Exception as e:
                    await self._log_audit(
                        f"Component '{component_name}' health check failed: {e}",
                        AuditEventType.SYSTEM_ERROR,
                        AuditSeverity.HIGH,
                    )
                    metadata.status = ComponentStatus.DEGRADED

        # Start health check loop
        if not self.is_running:
            self.is_running = True
            self.health_check_task = asyncio.create_task(self._health_check_loop())

        await self._log_audit("All components initialized", AuditEventType.SYSTEM_ERROR, AuditSeverity.INFO)

        print(f"✅ Initialized {len(self.components)} components")

    def _topological_sort(self) -> list[str]:
        """Sort components by dependencies"""
        # Simple topological sort (Kahn's algorithm)
        in_degree = {name: 0 for name in self.components}

        for name, metadata in self.components.items():
            for dep in metadata.dependencies:
                if dep in in_degree:
                    in_degree[name] += 1

        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            node = queue.pop(0)
            result.append(node)

            for name, metadata in self.components.items():
                if node in metadata.dependencies:
                    in_degree[name] -= 1
                    if in_degree[name] == 0:
                        queue.append(name)

        return result

    async def _health_check_loop(self):
        """Background loop for periodic health checks"""
        while self.is_running:
            try:
                for name, metadata in self.components.items():
                    if metadata.health_check is None:
                        continue

                    # Check if time for health check
                    if time.time() - metadata.last_check < metadata.check_interval:
                        continue

                    metadata.last_check = time.time()

                    try:
                        # Handle both async and sync health checks
                        if asyncio.iscoroutinefunction(metadata.health_check):
                            is_healthy = await metadata.health_check()
                        else:
                            is_healthy = metadata.health_check()

                        if is_healthy:
                            if metadata.status == ComponentStatus.DEGRADED:
                                # Recovery
                                metadata.status = ComponentStatus.HEALTHY
                                metadata.error_count = 0

                                await self._log_audit(
                                    f"Component '{name}' recovered",
                                    AuditEventType.SYSTEM_ERROR,
                                    AuditSeverity.INFO,
                                )
                                print(f"✅ Component '{name}' recovered")
                        else:
                            metadata.error_count += 1

                            if metadata.error_count >= metadata.max_errors:
                                if metadata.status != ComponentStatus.DEGRADED:
                                    metadata.status = ComponentStatus.DEGRADED

                                    await self._log_audit(
                                        f"Component '{name}' degraded after {metadata.error_count} errors",
                                        AuditEventType.SYSTEM_ERROR,
                                        AuditSeverity.MEDIUM,
                                    )
                                    print(f"⚠️  Component '{name}' degraded")

                    except Exception as e:
                        metadata.error_count += 1
                        await self._log_audit(
                            f"Health check error for '{name}': {e}",
                            AuditEventType.SYSTEM_ERROR,
                            AuditSeverity.HIGH,
                        )

                await asyncio.sleep(10)  # Check every 10 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                await self._log_audit(f"Health check loop error: {e}", AuditEventType.SYSTEM_ERROR, AuditSeverity.HIGH)

    def is_available(self, component_name: str) -> bool:
        """
        Check if component is available for use

        Args:
            component_name: Component to check

        Returns:
            True if component is healthy or degraded (still usable)
        """
        if component_name not in self.components:
            return False

        status = self.components[component_name].status
        return status in [ComponentStatus.HEALTHY, ComponentStatus.DEGRADED]

    def get_component(self, component_name: str) -> Any:
        """
        Get component instance with fallback

        Args:
            component_name: Component to get

        Returns:
            Component instance or fallback

        Raises:
            RuntimeError if component not available and no fallback
        """
        if not self.is_available(component_name):
            # Try fallback
            metadata = self.components.get(component_name)
            if metadata and metadata.fallback:
                print(f"⚠️  Using fallback for '{component_name}'")
                return metadata.fallback()

            raise RuntimeError(f"Component '{component_name}' unavailable and no fallback")

        return self.instances.get(component_name)

    def get_status_report(self) -> dict:
        """
        Get comprehensive status report

        Returns:
            Status report with all components
        """
        return {
            "timestamp": time.time(),
            "capabilities": self.capabilities,
            "components": {
                name: {
                    "status": metadata.status.value,
                    "category": metadata.category.value,
                    "version": metadata.version,
                    "dependencies": metadata.dependencies,
                    "error_count": metadata.error_count,
                    "last_check": metadata.last_check,
                    "features": metadata.features,
                    "metrics": metadata.metrics,
                }
                for name, metadata in self.components.items()
            },
            "summary": {
                "total": len(self.components),
                "healthy": sum(1 for m in self.components.values() if m.status == ComponentStatus.HEALTHY),
                "degraded": sum(1 for m in self.components.values() if m.status == ComponentStatus.DEGRADED),
                "unavailable": sum(1 for m in self.components.values() if m.status == ComponentStatus.UNAVAILABLE),
            },
        }

    async def _log_audit(self, message: str, event_type: AuditEventType, severity: AuditSeverity):
        """Log audit event"""
        import hashlib
        import time

        # Generate event ID
        event_id = hashlib.sha256(f"{message}:{time.time()}".encode()).hexdigest()[:16]

        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            actor_id="system",
            actor_type="system",
            resource_type="component_registry",
            resource_id="registry",
            action=message,
            ip_address="127.0.0.1",
            user_agent="orchestrator",
            metadata={"component": "registry"},
        )

        await self.audit_logger.log_event(event)

    async def shutdown(self):
        """Graceful shutdown of all components"""
        await self._log_audit("Starting graceful shutdown", AuditEventType.SYSTEM_ERROR, AuditSeverity.INFO)

        print("\n🛑 Shutting down components...")

        # Stop health checking
        self.is_running = False
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass

        # Mark all as stopping
        for metadata in self.components.values():
            metadata.status = ComponentStatus.STOPPING

        # Shutdown in reverse dependency order
        sorted_components = self._topological_sort()

        for component_name in reversed(sorted_components):
            instance = self.instances.get(component_name)

            if instance and hasattr(instance, "close"):
                try:
                    if asyncio.iscoroutinefunction(instance.close):
                        await instance.close()
                    else:
                        instance.close()

                    print(f"  ✅ Closed {component_name}")
                except Exception as e:
                    print(f"  ⚠️  Error closing {component_name}: {e}")

            self.components[component_name].status = ComponentStatus.UNAVAILABLE

        await self._log_audit("Graceful shutdown complete", AuditEventType.SYSTEM_ERROR, AuditSeverity.INFO)

        print("✅ All components shut down")


# Global registry instance
_registry: Optional[ComponentRegistry] = None


def get_registry() -> ComponentRegistry:
    """
    Get global component registry

    Returns:
        Shared ComponentRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = ComponentRegistry()
    return _registry
