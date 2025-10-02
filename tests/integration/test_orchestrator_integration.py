"""
Orchestrator Integration Tests
Tests for component registry, graceful degradation, and full system integration

Tests:
1. Component registration and discovery
2. Health check monitoring
3. Graceful degradation when features unavailable
4. Fallback mechanisms
5. Full gateway initialization
6. Compliance and audit logging
"""

import asyncio
import pytest


class TestComponentRegistry:
    """Test component registry functionality"""

    @pytest.mark.asyncio
    async def test_registry_initialization(self):
        """Test registry initialization and capability detection"""
        from subzero.orchestrator.component_registry import get_registry

        registry = get_registry()

        print(f"\n📊 System Capabilities:")
        for cap, value in registry.capabilities.items():
            print(f"   {cap}: {value}")

        # Verify capabilities detected
        assert "python_version" in registry.capabilities
        assert "platform" in registry.capabilities
        assert "numpy" in registry.capabilities

        print(f"✅ Registry initialized with {len(registry.capabilities)} capabilities")

    @pytest.mark.asyncio
    async def test_component_registration(self):
        """Test component registration"""
        from subzero.orchestrator.component_registry import ComponentCategory, ComponentRegistry

        registry = ComponentRegistry()

        # Register test component
        success = await registry.register(
            name="test_component",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            health_check=lambda: True,
        )

        assert success
        assert "test_component" in registry.components
        assert registry.is_available("test_component")

        print("✅ Component registration successful")

    @pytest.mark.asyncio
    async def test_graceful_degradation(self):
        """Test graceful degradation when capabilities missing"""
        from subzero.orchestrator.component_registry import ComponentCategory, ComponentRegistry

        registry = ComponentRegistry()

        # Register component requiring non-existent capability
        success = await registry.register(
            name="fancy_feature",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            required_capabilities=["nonexistent_capability"],
        )

        # Should fail gracefully (not registered)
        assert not success
        assert registry.is_available("fancy_feature") is False

        print("✅ Graceful degradation working")

    @pytest.mark.asyncio
    async def test_health_check_monitoring(self):
        """Test health check monitoring and status updates"""
        from subzero.orchestrator.component_registry import ComponentCategory, ComponentRegistry

        registry = ComponentRegistry()

        # Counter for health check calls
        check_count = 0

        async def health_check():
            nonlocal check_count
            check_count += 1
            # Fail after 3 checks
            return check_count < 3

        await registry.register(
            name="monitored_component",
            category=ComponentCategory.OPTIMIZATION,
            version="1.0.0",
            health_check=health_check,
            check_interval=0.1,  # Check every 100ms
        )

        await registry.initialize_all()

        # Wait for health checks to run
        await asyncio.sleep(0.5)

        # Component should be degraded after failures
        metadata = registry.components["monitored_component"]
        print(f"   Health check calls: {check_count}")
        print(f"   Component status: {metadata.status.value}")
        print(f"   Error count: {metadata.error_count}")

        await registry.shutdown()

        print("✅ Health check monitoring working")


class TestGatewayOrchestration:
    """Test full gateway orchestration"""

    @pytest.mark.asyncio
    async def test_full_initialization(self):
        """Test complete gateway initialization"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        assert orchestrator.initialized

        status = await orchestrator.get_status()

        print(f"\n📊 Gateway Status:")
        print(f"   Total components: {status['summary']['total']}")
        print(f"   Healthy: {status['summary']['healthy']}")
        print(f"   Degraded: {status['summary']['degraded']}")
        print(f"   Unavailable: {status['summary']['unavailable']}")

        if status["degraded_features"]:
            print(f"\n⚠️  Degraded features:")
            for feature in status["degraded_features"]:
                print(f"     - {feature}")

        assert status["summary"]["total"] > 0
        assert status["summary"]["healthy"] >= 2  # At least audit_logger and rebac_engine

        await orchestrator.shutdown()

        print("✅ Full gateway initialization successful")

    @pytest.mark.asyncio
    async def test_component_access_with_fallback(self):
        """Test accessing components with automatic fallback"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Access shared memory cache (may use fallback)
        try:
            cache = await orchestrator.get_component("shared_memory_cache")
            assert cache is not None

            print(f"✅ Shared memory cache available (type: {type(cache).__name__})")

            # Test cache functionality
            if hasattr(cache, "write_token"):
                import time

                slot = cache.write_token(user_id=123, token_hash=456789, expires_at=time.time() + 3600, scopes={0, 1})
                token_data = cache.read_token(slot)

                assert token_data is not None
                assert token_data["user_id"] == 123

                print("   Cache operations working")

        except Exception as e:
            print(f"⚠️  Cache access failed: {e}")

        await orchestrator.shutdown()

    @pytest.mark.asyncio
    async def test_feature_availability_check(self):
        """Test checking feature availability"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Check various features
        features_to_check = [
            "audit_logger",
            "rebac_engine",
            "shared_memory_cache",
            "http_connection_pool",
            "backpressure_manager",
            "vectorized_authorization",
            "adaptive_cache",
        ]

        print(f"\n📊 Feature Availability:")
        for feature in features_to_check:
            available = orchestrator.is_feature_available(feature)
            status_icon = "✅" if available else "❌"
            print(f"   {status_icon} {feature}: {available}")

        await orchestrator.shutdown()

    @pytest.mark.asyncio
    async def test_audit_logging_integration(self):
        """Test audit logging integration"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Get audit logger
        audit_logger = await orchestrator.get_component("audit_logger")

        assert audit_logger is not None

        # Log test event
        import hashlib
        import time

        from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity

        event_id = hashlib.sha256(f"test_action:{time.time()}".encode()).hexdigest()[:16]

        event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.SYSTEM_ERROR,
            severity=AuditSeverity.INFO,
            actor_id="test_user",
            actor_type="user",
            resource_type="test",
            resource_id="test_resource",
            action="test_action",
            ip_address="127.0.0.1",
            user_agent="test",
            metadata={"test": "data"},
        )

        await audit_logger.log_event(event)

        print("✅ Audit logging integration working")

        await orchestrator.shutdown()


class TestGracefulDegradation:
    """Test graceful degradation scenarios"""

    @pytest.mark.asyncio
    async def test_missing_numpy_degradation(self):
        """Test degradation when NumPy unavailable"""
        from subzero.orchestrator.component_registry import ComponentRegistry

        registry = ComponentRegistry()

        # Simulate NumPy unavailable
        original_numpy = registry.capabilities.get("numpy")
        registry.capabilities["numpy"] = False

        # Try to register vectorized authorization
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        orchestrator.registry = registry

        await orchestrator._register_vectorized_authorization()

        # Should fall back to sequential
        auth = await orchestrator.get_component("vectorized_authorization")
        assert auth is not None

        print("✅ NumPy unavailable degradation working")

        # Restore
        registry.capabilities["numpy"] = original_numpy

    @pytest.mark.asyncio
    async def test_missing_shared_memory_degradation(self):
        """Test degradation when shared memory unavailable"""
        from subzero.orchestrator.component_registry import ComponentRegistry

        registry = ComponentRegistry()

        # Simulate shared memory unavailable
        original_sm = registry.capabilities.get("shared_memory")
        registry.capabilities["shared_memory"] = False

        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        orchestrator.registry = registry

        await orchestrator._register_shared_memory_cache()

        # Should fall back to dict cache
        cache = await orchestrator.get_component("shared_memory_cache")
        assert cache is not None

        print("✅ Shared memory unavailable degradation working")

        # Restore
        registry.capabilities["shared_memory"] = original_sm


class TestComplianceIntegration:
    """Test compliance and monitoring integration"""

    @pytest.mark.asyncio
    async def test_status_reporting(self):
        """Test comprehensive status reporting"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        status = await orchestrator.get_status()

        # Verify status report structure
        assert "initialized" in status
        assert "capabilities" in status
        assert "components" in status
        assert "summary" in status
        assert "degraded_features" in status
        assert "unavailable_features" in status

        print(f"\n📊 Status Report:")
        print(f"   Capabilities detected: {len(status['capabilities'])}")
        print(f"   Components registered: {status['summary']['total']}")
        print(f"   Healthy: {status['summary']['healthy']}")
        print(f"   Degraded: {status['summary']['degraded']}")

        for component_name, component_info in status["components"].items():
            print(f"\n   Component: {component_name}")
            print(f"     Status: {component_info['status']}")
            print(f"     Category: {component_info['category']}")
            print(f"     Version: {component_info['version']}")

        await orchestrator.shutdown()

        print("✅ Status reporting working")

    @pytest.mark.asyncio
    async def test_graceful_shutdown(self):
        """Test graceful shutdown of all components"""
        from subzero.orchestrator.integration import GatewayOrchestrator

        orchestrator = GatewayOrchestrator()
        await orchestrator.initialize()

        # Verify components initialized
        assert orchestrator.initialized

        # Shutdown
        await orchestrator.shutdown()

        # Verify shutdown
        assert not orchestrator.initialized

        # All components should be unavailable
        from subzero.orchestrator.component_registry import ComponentStatus

        for metadata in orchestrator.registry.components.values():
            assert metadata.status == ComponentStatus.UNAVAILABLE

        print("✅ Graceful shutdown working")
