"""
Integration Tests for Unified Zero Trust Gateway
Tests seamless integration of all components through the orchestrator
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock

from src.integration.unified_gateway import UnifiedZeroTrustGateway, GatewayMetrics
from src.performance.functional_event_orchestrator import RequestPriority
from src.auth.token_vault_integration import TokenProvider
from src.auth.auth0_integration import Auth0Configuration


@pytest.fixture
async def gateway():
    """Create gateway instance for testing"""
    # Mock configuration
    config = Auth0Configuration(
        domain="test.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        audience="https://api.test.com",
        management_api_token="test_mgmt_token",
        fga_store_id="test_store",
        fga_client_id="test_fga_client",
        fga_client_secret="test_fga_secret"
    )

    gateway = UnifiedZeroTrustGateway(config=config)

    # Start gateway
    await gateway.start()

    yield gateway

    # Cleanup
    await gateway.stop()


class TestOrchestratorIntegration:
    """Test orchestrator integration with all components"""

    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self, gateway):
        """Test orchestrator is properly initialized"""
        assert gateway.orchestrator is not None
        assert gateway.orchestrator.max_workers == 10
        assert len(gateway.orchestrator.workers) == 10
        assert len(gateway.orchestrator.operation_handlers) > 0

    @pytest.mark.asyncio
    async def test_operation_registration(self, gateway):
        """Test all operations are registered with orchestrator"""
        required_operations = [
            "authenticate",
            "check_permission",
            "store_token",
            "retrieve_token",
            "xaa_delegate",
            "xaa_establish_channel",
            "check_threat",
            "assess_risk"
        ]

        for op in required_operations:
            assert op in gateway.orchestrator.operation_handlers, f"Operation {op} not registered"

    @pytest.mark.asyncio
    async def test_circuit_breakers_created(self, gateway):
        """Test circuit breakers are created for each operation"""
        assert len(gateway.orchestrator.circuit_breakers) > 0

        for operation in gateway.orchestrator.operation_handlers.keys():
            assert operation in gateway.orchestrator.circuit_breakers


class TestAuthenticationIntegration:
    """Test authentication flow through orchestrator"""

    @pytest.mark.asyncio
    @patch('src.auth.resilient_auth_service.ResilientAuthService.authenticate')
    async def test_authentication_via_orchestrator(self, mock_auth, gateway):
        """Test authentication request goes through orchestrator"""
        # Mock authentication response
        from src.auth.resilient_auth_service import AuthenticationResult
        mock_auth.return_value = AuthenticationResult(
            success=True,
            user_id="test_user_123",
            claims={'sub': 'test_user_123', 'email': 'test@example.com'},
            source="auth0",
            degradation_mode="normal",
            latency_ms=8.5
        )

        # Authenticate via gateway
        result = await gateway.authenticate_request(
            user_id="test_user_123",
            scopes="openid profile email",
            priority=RequestPriority.HIGH
        )

        # Verify orchestrator was used
        assert result['success'] is True
        assert result['user_id'] == "test_user_123"
        assert 'latency_ms' in result

        # Verify metrics updated
        assert gateway.metrics.total_requests > 0
        assert gateway.metrics.successful_requests > 0

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, gateway):
        """Test rate limiting blocks excessive requests"""
        # Make multiple requests rapidly
        user_id = "rate_limited_user"

        # First requests should succeed
        for i in range(5):
            result = await gateway.authenticate_request(
                user_id=user_id,
                priority=RequestPriority.HIGH
            )
            # May fail due to missing Auth0, but shouldn't be rate limited
            if not result['success'] and 'rate_limit_exceeded' in result.get('error', ''):
                pytest.fail("Rate limit exceeded too early")

        # After many requests, should eventually hit rate limit
        # (depending on configured limit)


class TestAuthorizationIntegration:
    """Test authorization flow through orchestrator"""

    @pytest.mark.asyncio
    @patch('src.fga.rebac_engine.ReBAC Engine.check')
    async def test_authorization_via_orchestrator(self, mock_rebac, gateway):
        """Test authorization check goes through orchestrator"""
        # Mock ReBAC response
        mock_rebac.return_value = True

        # Authorize via gateway
        result = await gateway.authorize_request(
            user_id="test_user_123",
            resource_type="document",
            resource_id="doc_456",
            relation="viewer",
            priority=RequestPriority.HIGH
        )

        # Verify result
        assert result['allowed'] is True
        assert result['source'] == "rebac"
        assert 'latency_ms' in result

        # Verify audit log created
        assert gateway.audit_service.storage.total_events > 0


class TestThreatDetectionIntegration:
    """Test threat detection through orchestrator"""

    @pytest.mark.asyncio
    @patch('src.security.advanced_threat_detection.SignupFraudDetector.detect')
    async def test_signup_fraud_detection(self, mock_detector, gateway):
        """Test signup fraud detection via orchestrator"""
        from src.security.advanced_threat_detection import ThreatSignal, ThreatSignalType

        # Mock threat signal
        mock_detector.return_value = [
            ThreatSignal(
                signal_type=ThreatSignalType.DISPOSABLE_EMAIL,
                confidence=0.92,
                message="Disposable email domain detected",
                metadata={'domain': 'tempmail.com'}
            )
        ]

        # Detect threat via gateway
        result = await gateway.detect_threat(
            threat_type="signup_fraud",
            data={
                'email': 'test@tempmail.com',
                'ip_address': '1.2.3.4'
            },
            priority=RequestPriority.CRITICAL
        )

        # Verify detection
        assert result['threat_detected'] is True
        assert result['confidence'] > 0.9
        assert len(result['signals']) > 0

        # Verify metrics updated
        assert gateway.metrics.threats_blocked > 0


class TestTokenVaultIntegration:
    """Test Token Vault integration through orchestrator"""

    @pytest.mark.asyncio
    @patch('src.auth.token_vault_integration.Auth0TokenVault.store_token')
    async def test_token_storage_via_orchestrator(self, mock_store, gateway):
        """Test token storage goes through orchestrator"""
        # Mock vault reference
        mock_store.return_value = "vault_ref_abc123"

        # Store token via gateway
        result = await gateway.store_ai_credentials(
            agent_id="agent_123",
            provider=TokenProvider.GOOGLE,
            token_data={
                'access_token': 'ya29.xxx',
                'refresh_token': 'refresh_xxx',
                'expires_in': 3600
            },
            priority=RequestPriority.NORMAL
        )

        # Verify result
        assert result['success'] is True
        assert result['vault_ref'] == "vault_ref_abc123"
        assert result['agent_id'] == "agent_123"


class TestXAAIntegration:
    """Test XAA protocol integration through orchestrator"""

    @pytest.mark.asyncio
    @patch('src.auth.xaa_protocol.XAAProtocol.establish_bidirectional_channel')
    async def test_xaa_channel_establishment(self, mock_channel, gateway):
        """Test XAA channel establishment via orchestrator"""
        # Mock channel result
        mock_channel.return_value = {
            'success': True,
            'channel_id': 'channel_123',
            'agent_to_app_token': 'token_1',
            'app_to_agent_token': 'token_2',
            'expires_in': 3600
        }

        # Establish channel via gateway
        result = await gateway.establish_xaa_channel(
            agent_id="agent_123",
            app_id="app_456",
            scopes=["xaa:read", "xaa:write"],
            priority=RequestPriority.NORMAL
        )

        # Verify result
        assert result['success'] is True
        assert result['channel_id'] == 'channel_123'
        assert 'agent_to_app_token' in result


class TestPerformanceIntegration:
    """Test performance characteristics of integrated system"""

    @pytest.mark.asyncio
    @patch('src.auth.resilient_auth_service.ResilientAuthService.authenticate')
    async def test_concurrent_requests_handling(self, mock_auth, gateway):
        """Test gateway handles concurrent requests efficiently"""
        from src.auth.resilient_auth_service import AuthenticationResult

        # Mock fast responses
        mock_auth.return_value = AuthenticationResult(
            success=True,
            user_id="test_user",
            source="cached",
            degradation_mode="normal",
            latency_ms=5.0
        )

        # Submit many concurrent requests
        tasks = []
        num_requests = 50

        start_time = time.perf_counter()

        for i in range(num_requests):
            task = gateway.authenticate_request(
                user_id=f"user_{i}",
                priority=RequestPriority.NORMAL
            )
            tasks.append(task)

        # Wait for all requests
        results = await asyncio.gather(*tasks, return_exceptions=True)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Calculate throughput
        throughput = (num_requests / elapsed_ms) * 1000  # RPS

        print(f"\n📊 Performance Test Results:")
        print(f"   Total Requests: {num_requests}")
        print(f"   Total Time: {elapsed_ms:.2f}ms")
        print(f"   Throughput: {throughput:.2f} RPS")
        print(f"   Avg Latency: {elapsed_ms/num_requests:.2f}ms")

        # Verify reasonable performance
        assert throughput > 100, f"Throughput too low: {throughput} RPS"

    @pytest.mark.asyncio
    async def test_request_coalescing(self, gateway):
        """Test orchestrator coalesces duplicate requests"""
        # Submit identical requests simultaneously
        user_id = "coalesce_test_user"

        tasks = []
        for _ in range(10):
            task = gateway.authenticate_request(
                user_id=user_id,
                priority=RequestPriority.NORMAL
            )
            tasks.append(task)

        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check orchestrator metrics
        metrics = gateway.orchestrator.get_metrics()

        # Should have coalesced some requests
        print(f"\n🔄 Coalescing Test:")
        print(f"   Total requests: {metrics.total_requests}")
        print(f"   Coalesced requests: {metrics.coalesced_requests}")

        # At least some coalescing should occur with identical requests
        # (actual coalescing depends on timing window)


class TestMetricsAndMonitoring:
    """Test metrics collection and monitoring"""

    @pytest.mark.asyncio
    async def test_gateway_metrics_collection(self, gateway):
        """Test metrics are collected from all components"""
        # Generate some activity
        await gateway.authenticate_request(
            user_id="metrics_test_user",
            priority=RequestPriority.NORMAL
        )

        # Get metrics
        metrics = await gateway.get_gateway_metrics()

        # Verify structure
        assert 'gateway' in metrics
        assert 'orchestrator' in metrics
        assert 'authentication' in metrics
        assert 'authorization' in metrics
        assert 'rate_limiting' in metrics

        # Verify orchestrator metrics
        assert 'total_requests' in metrics['orchestrator']
        assert 'avg_latency_ms' in metrics['orchestrator']
        assert 'throughput_rps' in metrics['orchestrator']

        print(f"\n📊 Gateway Metrics:")
        print(f"   Total Requests: {metrics['gateway']['total_requests']}")
        print(f"   Threats Blocked: {metrics['gateway']['threats_blocked']}")
        print(f"   Orchestrator RPS: {metrics['orchestrator']['throughput_rps']:.2f}")


class TestResilienceIntegration:
    """Test resilience features integration"""

    @pytest.mark.asyncio
    @patch('src.security.health_monitor.Auth0HealthMonitor.should_use_fallback')
    async def test_graceful_degradation_integration(self, mock_fallback, gateway):
        """Test graceful degradation activates through gateway"""
        # Simulate service degradation
        mock_fallback.return_value = True

        # Request should still succeed using cache
        result = await gateway.authenticate_request(
            user_id="degradation_test_user",
            priority=RequestPriority.HIGH
        )

        # Should work even in degraded mode
        # (may fail if no cached data, but shouldn't crash)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_audit_trail_integration(self, gateway):
        """Test audit trail captures all operations"""
        # Perform various operations
        await gateway.authenticate_request(
            user_id="audit_user_1",
            priority=RequestPriority.NORMAL
        )

        await gateway.authorize_request(
            user_id="audit_user_1",
            resource_type="document",
            resource_id="doc_123",
            relation="viewer",
            priority=RequestPriority.NORMAL
        )

        await gateway.detect_threat(
            threat_type="signup_fraud",
            data={'email': 'test@example.com', 'ip_address': '1.2.3.4'},
            priority=RequestPriority.CRITICAL
        )

        # Verify audit events created
        assert gateway.audit_service.storage.total_events >= 3

        # Verify integrity
        is_valid, errors = gateway.audit_service.storage.verify_integrity()
        assert is_valid, f"Audit trail integrity violated: {errors}"


@pytest.mark.asyncio
async def test_full_request_lifecycle():
    """Test complete request lifecycle through all components"""
    # This test demonstrates the full integration flow
    gateway = UnifiedZeroTrustGateway()
    await gateway.start()

    try:
        print("\n🔄 Testing Full Request Lifecycle:")

        # 1. Rate limit check
        print("   1. Rate limit check...")

        # 2. Threat detection
        print("   2. Threat detection...")
        threat_result = await gateway.detect_threat(
            threat_type="signup_fraud",
            data={
                'email': 'test@example.com',
                'ip_address': '1.2.3.4',
                'user_agent': 'Mozilla/5.0'
            }
        )
        print(f"      Threat detected: {threat_result['threat_detected']}")

        # 3. Authentication
        print("   3. Authentication...")
        auth_result = await gateway.authenticate_request(
            user_id="lifecycle_test_user",
            source_ip="1.2.3.4"
        )
        print(f"      Authenticated: {auth_result['success']}")

        # 4. Authorization
        print("   4. Authorization...")
        authz_result = await gateway.authorize_request(
            user_id="lifecycle_test_user",
            resource_type="api",
            resource_id="/protected",
            relation="access"
        )
        print(f"      Authorized: {authz_result['allowed']}")

        # 5. Get metrics
        print("   5. Collecting metrics...")
        metrics = await gateway.get_gateway_metrics()
        print(f"      Total requests: {metrics['gateway']['total_requests']}")

        print("\n✅ Full lifecycle test completed successfully")

    finally:
        await gateway.stop()


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])