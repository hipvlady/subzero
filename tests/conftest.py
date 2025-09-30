# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Pytest configuration and fixtures for Subzero tests.

This module provides shared fixtures, configuration, and utilities for all test files.
"""

import pytest
import asyncio
import os
from typing import Dict, Optional
from unittest.mock import Mock, AsyncMock

# Set test environment variables
os.environ.setdefault("AUTH0_DOMAIN", "test.auth0.com")
os.environ.setdefault("AUTH0_CLIENT_ID", "test_client_id")
os.environ.setdefault("AUTH0_CLIENT_SECRET", "test_client_secret")
os.environ.setdefault("AUTH0_AUDIENCE", "https://api.test.com")
os.environ.setdefault("AUTH0_MANAGEMENT_API_TOKEN", "test_management_token")
os.environ.setdefault("FGA_STORE_ID", "test_store_id")
os.environ.setdefault("FGA_CLIENT_ID", "test_fga_client")
os.environ.setdefault("FGA_CLIENT_SECRET", "test_fga_secret")
os.environ.setdefault("FGA_API_URL", "https://api.test.fga.dev")

from subzero.services.auth.manager import Auth0Configuration
from subzero.subzeroapp import UnifiedZeroTrustGateway


# ========================================
# Event Loop Configuration
# ========================================

@pytest.fixture(scope="session")
def event_loop():
    """
    Create an event loop for async tests.

    Returns
    -------
    asyncio.AbstractEventLoop
        Event loop for async operations
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ========================================
# Configuration Fixtures
# ========================================

@pytest.fixture
def auth0_config():
    """
    Provide Auth0 configuration for testing.

    Returns
    -------
    Auth0Configuration
        Test configuration object
    """
    return Auth0Configuration(
        domain="test.auth0.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        audience="https://api.test.com",
        management_api_token="test_management_token",
        fga_store_id="test_store_id",
        fga_client_id="test_fga_client",
        fga_client_secret="test_fga_secret",
        fga_api_url="https://api.test.fga.dev",
    )


@pytest.fixture
def test_config() -> Dict:
    """
    Provide general test configuration.

    Returns
    -------
    dict
        Test configuration dictionary
    """
    return {
        "environment": "test",
        "debug": True,
        "cache_enabled": False,
        "redis_enabled": False,
    }


# ========================================
# Gateway Fixtures
# ========================================

@pytest.fixture
async def gateway(auth0_config):
    """
    Provide initialized Subzero gateway for testing.

    Parameters
    ----------
    auth0_config : Auth0Configuration
        Auth0 configuration fixture

    Yields
    ------
    UnifiedZeroTrustGateway
        Initialized gateway instance

    Notes
    -----
    This fixture automatically starts and stops the gateway,
    ensuring clean state between tests.
    """
    gateway = UnifiedZeroTrustGateway(config=auth0_config)
    await gateway.start()
    yield gateway
    await gateway.stop()


@pytest.fixture
def mock_gateway():
    """
    Provide mocked gateway for unit tests.

    Returns
    -------
    Mock
        Mocked gateway instance
    """
    gateway = Mock(spec=UnifiedZeroTrustGateway)
    gateway.authenticate_request = AsyncMock()
    gateway.authorize_request = AsyncMock()
    gateway.detect_threat = AsyncMock()
    return gateway


# ========================================
# Authentication Fixtures
# ========================================

@pytest.fixture
def valid_jwt_token() -> str:
    """
    Provide a valid JWT token for testing.

    Returns
    -------
    str
        JWT token string
    """
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJhdWQiOiJodHRwczovL2FwaS50ZXN0LmNvbSIsImlhdCI6MTYxNjIzOTAyMiwiZXhwIjoxNjE2MjQyNjIyfQ.signature"


@pytest.fixture
def expired_jwt_token() -> str:
    """
    Provide an expired JWT token for testing.

    Returns
    -------
    str
        Expired JWT token string
    """
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJhdWQiOiJodHRwczovL2FwaS50ZXN0LmNvbSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyfQ.signature"


@pytest.fixture
def test_user_claims() -> Dict:
    """
    Provide test user claims.

    Returns
    -------
    dict
        User claims dictionary
    """
    return {
        "sub": "test_user_123",
        "email": "test@example.com",
        "email_verified": True,
        "name": "Test User",
        "roles": ["user", "admin"],
        "permissions": ["read:data", "write:data"],
    }


# ========================================
# Authorization Fixtures
# ========================================

@pytest.fixture
def test_permissions():
    """
    Provide test permissions data.

    Returns
    -------
    list of dict
        Permission tuples
    """
    return [
        {
            "user": "user:test_user",
            "relation": "viewer",
            "object": "document:doc123",
        },
        {
            "user": "user:test_user",
            "relation": "editor",
            "object": "document:doc456",
        },
    ]


# ========================================
# Security Fixtures
# ========================================

@pytest.fixture
def test_threat_data():
    """
    Provide test threat detection data.

    Returns
    -------
    dict
        Threat data for testing
    """
    return {
        "signup_fraud": {
            "email": "suspicious@example.com",
            "ip_address": "192.168.1.100",
            "user_agent": "suspicious-bot/1.0",
        },
        "ato": {
            "user_id": "user123",
            "ip_address": "192.168.1.200",
            "device_fingerprint": "unusual_device",
            "location": "unusual_location",
        },
        "mfa_abuse": {
            "user_id": "user456",
            "mfa_method": "sms",
            "timestamp": 1234567890,
        },
    }


# ========================================
# Performance Fixtures
# ========================================

@pytest.fixture
def performance_config():
    """
    Provide performance test configuration.

    Returns
    -------
    dict
        Performance test parameters
    """
    return {
        "num_requests": 1000,
        "concurrency": 100,
        "target_latency_ms": 10,
        "target_throughput_rps": 10000,
    }


# ========================================
# Mock External Services
# ========================================

@pytest.fixture
def mock_auth0_client():
    """
    Provide mocked Auth0 client.

    Returns
    -------
    Mock
        Mocked Auth0 client
    """
    client = Mock()
    client.get_user = AsyncMock(return_value={"user_id": "test_user", "email": "test@example.com"})
    client.verify_token = AsyncMock(return_value={"sub": "test_user", "valid": True})
    return client


@pytest.fixture
def mock_fga_client():
    """
    Provide mocked FGA client.

    Returns
    -------
    Mock
        Mocked FGA client
    """
    client = Mock()
    client.check = AsyncMock(return_value={"allowed": True})
    client.batch_check = AsyncMock(return_value=[{"allowed": True}, {"allowed": False}])
    return client


@pytest.fixture
def mock_redis_client():
    """
    Provide mocked Redis client.

    Returns
    -------
    Mock
        Mocked Redis client
    """
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=1)
    client.exists = AsyncMock(return_value=False)
    return client


# ========================================
# Test Data Generators
# ========================================

@pytest.fixture
def generate_test_users():
    """
    Provide a function to generate test user data.

    Returns
    -------
    callable
        Function that generates test users
    """
    def _generate(count: int = 10):
        return [
            {
                "user_id": f"user_{i}",
                "email": f"user{i}@example.com",
                "name": f"Test User {i}",
            }
            for i in range(count)
        ]

    return _generate


@pytest.fixture
def generate_test_tokens():
    """
    Provide a function to generate test JWT tokens.

    Returns
    -------
    callable
        Function that generates test tokens
    """
    def _generate(count: int = 10):
        return [f"token_{i}" for i in range(count)]

    return _generate


# ========================================
# Cleanup Fixtures
# ========================================

@pytest.fixture(autouse=True)
async def cleanup_after_test():
    """
    Automatic cleanup after each test.

    This fixture runs after every test to ensure clean state.
    """
    yield
    # Cleanup code here
    # Clear caches, close connections, etc.
    pass


# ========================================
# Markers
# ========================================

def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "security: marks tests as security tests")


# ========================================
# Logging Configuration
# ========================================

@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    """Configure logging for tests."""
    import logging

    logging.basicConfig(
        level=logging.CRITICAL,  # Suppress logs during tests
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


# ========================================
# Benchmark Fixtures
# ========================================

@pytest.fixture
def benchmark_config(request):
    """
    Provide benchmark configuration.

    Parameters
    ----------
    request : pytest.FixtureRequest
        Pytest request object

    Returns
    -------
    dict
        Benchmark configuration
    """
    return {
        "rounds": getattr(request.config.option, "benchmark_rounds", 100),
        "warmup": getattr(request.config.option, "benchmark_warmup", True),
    }