"""
Test suite for refactored Zero Trust AI Gateway
Validates that consolidated architecture maintains performance and functionality
"""

import asyncio
import pytest
import time
import sys
import os
from typing import Dict, Any

# Add parent directory to path for testing
current_dir = os.path.dirname(os.path.abspath(__file__))
gateway_dir = os.path.dirname(current_dir)
parent_dir = os.path.dirname(gateway_dir)
sys.path.insert(0, parent_dir)

from ..core.gateway import ZeroTrustAIGateway, GatewayConfig
from ..core.adapters import ComponentFactory, AuthAdapter, FGAAdapter
from ..aigatewayapp import ZeroTrustGatewayApp

class TestRefactoredArchitecture:
    """Test consolidated architecture with parent components"""

    @pytest.fixture
    def gateway_config(self):
        """Create test gateway configuration"""
        return GatewayConfig(
            auth0_domain="test-tenant.auth0.com",
            client_id="test_client_id",
            private_key="test_private_key",
            fga_api_url="https://api.fga.dev",
            fga_store_id="test_store_id",
            cache_capacity=1000,
            batch_size=100,
            connection_pool_size=10,
            enable_bot_detection=True,
            rate_limit_per_minute=100,
            max_agents_per_user=5
        )

    @pytest.fixture
    def gateway(self, gateway_config, event_loop):
        """Create and setup test gateway"""
        gateway = ZeroTrustAIGateway(gateway_config)
        event_loop.run_until_complete(gateway.setup())
        return gateway

    @pytest.mark.asyncio
    async def test_gateway_initialization(self, gateway_config):
        """Test that consolidated gateway initializes correctly"""
        gateway = ZeroTrustAIGateway(gateway_config)

        # Verify components are initialized
        assert gateway.config == gateway_config
        assert hasattr(gateway, 'bot_detector')
        assert hasattr(gateway, 'agent_manager')

        # Verify metrics tracking
        assert hasattr(gateway, 'metrics')
        assert gateway.metrics['total_requests'] == 0

    @pytest.mark.asyncio
    async def test_parent_component_integration(self, gateway):
        """Test that parent components are properly integrated"""

        # Test authentication integration
        auth_result = await gateway.authenticate_request(
            user_id="test_user",
            scopes="openid profile"
        )

        assert isinstance(auth_result, dict)
        assert 'authenticated' in auth_result
        assert 'total_latency_ms' in auth_result
        assert 'threat_checked' in auth_result

    @pytest.mark.asyncio
    async def test_authorization_integration(self, gateway):
        """Test FGA engine integration"""

        authz_result = await gateway.authorize_request(
            user_id="demo_user",
            resource_type="ai_model",
            resource_id="gpt-3.5-turbo",
            permission="read"
        )

        assert isinstance(authz_result, dict)
        assert 'allowed' in authz_result
        assert 'latency_ms' in authz_result

    @pytest.mark.asyncio
    async def test_ai_agent_invocation(self, gateway):
        """Test AI agent invocation with consolidated components"""

        result = await gateway.invoke_ai_agent(
            user_id="test_user",
            agent_id="test_agent",
            prompt="Hello, world!",
            model="mock-model"
        )

        assert isinstance(result, dict)
        assert 'success' in result
        assert 'latency_ms' in result

    @pytest.mark.asyncio
    async def test_batch_processing(self, gateway):
        """Test batch processing using parent components"""

        requests = [
            {'user_id': f'user_{i}', 'timestamp': time.time()}
            for i in range(10)
        ]

        results = await gateway.batch_process_requests(requests)

        assert len(results) == len(requests)
        assert all(isinstance(result, dict) for result in results)

    @pytest.mark.asyncio
    async def test_performance_metrics(self, gateway):
        """Test comprehensive performance metrics"""

        # Perform some operations
        await gateway.authenticate_request("test_user")
        await gateway.authorize_request("test_user", "ai_model", "gpt-3.5-turbo", "read")

        metrics = await gateway.get_performance_metrics()

        assert isinstance(metrics, dict)
        assert 'gateway_metrics' in metrics
        assert gateway.metrics['total_requests'] > 0

    @pytest.mark.asyncio
    async def test_health_check(self, gateway):
        """Test consolidated health check"""

        health_status = await gateway.health_check()

        assert isinstance(health_status, dict)
        assert 'overall_status' in health_status
        assert 'components' in health_status

class TestAdapterFunctionality:
    """Test adapter classes for component integration"""

    def test_component_factory(self):
        """Test component factory auto-detection"""

        # Mock component with authentication methods
        class MockAuthComponent:
            async def authenticate(self, user_id: str, scopes: str = "openid"):
                return {'authenticated': True, 'user_id': user_id}

            def get_performance_metrics(self):
                return {'total_requests': 100}

        component = MockAuthComponent()
        factory = ComponentFactory()

        capabilities = factory.auto_detect_adapters(component)

        assert capabilities['authentication'] == True
        assert 'authenticate' in capabilities['methods']

    @pytest.mark.asyncio
    async def test_auth_adapter(self):
        """Test authentication adapter functionality"""

        class MockAuthComponent:
            async def authenticate(self, user_id: str, scopes: str = "openid"):
                return {
                    'authenticated': True,
                    'user_id': user_id,
                    'access_token': 'mock_token',
                    'expires_in': 3600
                }

        component = MockAuthComponent()
        adapter = AuthAdapter(component)

        result = await adapter.authenticate_user("test_user")

        assert result['authenticated'] == True
        assert result['user_id'] == "test_user"
        assert result['source_component'] == 'MockAuthComponent'

    @pytest.mark.asyncio
    async def test_fga_adapter(self):
        """Test FGA adapter functionality"""

        class MockFGAComponent:
            async def check_permission(self, user_id: str, resource_type: str,
                                     resource_id: str, permission: str):
                return {
                    'allowed': user_id == 'demo_user',
                    'source': 'mock_fga',
                    'latency_ms': 1.0
                }

        component = MockFGAComponent()
        adapter = FGAAdapter(component)

        result = await adapter.check_permission(
            "demo_user", "ai_model", "gpt-3.5-turbo", "read"
        )

        assert result['allowed'] == True
        assert result['component_type'] == 'MockFGAComponent'

class TestApplicationIntegration:
    """Test refactored FastAPI application"""

    @pytest.fixture
    def app(self):
        """Create test application"""
        return ZeroTrustGatewayApp()

    @pytest.mark.asyncio
    async def test_app_initialization(self, app):
        """Test application initialization with consolidated components"""

        # Verify app has consolidated gateway
        assert hasattr(app, 'gateway')
        assert hasattr(app, 'gateway_config')

        # Verify FastAPI app is created
        assert hasattr(app, 'app')
        assert app.app.title == "Zero Trust AI Gateway (Refactored)"

    @pytest.mark.asyncio
    async def test_app_setup(self, app):
        """Test application setup process"""

        # This should not raise any exceptions
        await app.setup()

        # Verify gateway is properly initialized
        assert app.gateway is not None

class TestPerformanceRegression:
    """Test that refactoring maintains performance targets"""

    @pytest.fixture
    def gateway_config(self):
        """Create test gateway configuration"""
        return GatewayConfig(
            auth0_domain="test-tenant.auth0.com",
            client_id="test_client_id",
            private_key="test_private_key",
            fga_api_url="https://api.fga.dev",
            fga_store_id="test_store_id",
            cache_capacity=1000,
            batch_size=100,
            connection_pool_size=10,
            enable_bot_detection=True,
            rate_limit_per_minute=100,
            max_agents_per_user=5
        )

    @pytest.mark.asyncio
    async def test_authentication_latency(self, gateway_config):
        """Test authentication latency targets"""

        gateway = ZeroTrustAIGateway(gateway_config)
        await gateway.setup()

        # Measure authentication latency
        latencies = []
        for _ in range(100):
            start_time = time.perf_counter()
            result = await gateway.authenticate_request("test_user")
            end_time = time.perf_counter()

            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)

        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

        # Performance targets
        assert avg_latency < 50.0, f"Average latency too high: {avg_latency:.2f}ms"
        assert p95_latency < 100.0, f"P95 latency too high: {p95_latency:.2f}ms"

    @pytest.mark.asyncio
    async def test_batch_throughput(self, gateway_config):
        """Test batch processing throughput"""

        gateway = ZeroTrustAIGateway(gateway_config)
        await gateway.setup()

        # Test batch processing performance
        batch_size = 1000
        requests = [
            {'user_id': f'user_{i}', 'timestamp': time.time()}
            for i in range(batch_size)
        ]

        start_time = time.perf_counter()
        results = await gateway.batch_process_requests(requests)
        end_time = time.perf_counter()

        duration = end_time - start_time
        ops_per_second = batch_size / duration

        # Performance target: >1000 ops/sec for batch processing
        assert ops_per_second > 1000, f"Batch throughput too low: {ops_per_second:.0f} ops/sec"
        assert len(results) == batch_size

def run_refactoring_tests():
    """Run all refactoring validation tests"""

    print("🧪 Running Refactored Zero Trust AI Gateway Tests")
    print("=" * 60)

    # Run pytest with verbose output
    pytest.main([__file__, "-v", "-s"])

if __name__ == "__main__":
    run_refactoring_tests()