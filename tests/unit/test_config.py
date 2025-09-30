"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Unit tests for configuration settings.
"""

from subzero.config.defaults import Settings


def test_settings_default_values():
    """Test that Settings loads without errors and has required fields."""
    settings = Settings()

    # Test that required fields are populated (either from env or defaults)
    assert settings.AUTH0_DOMAIN
    assert settings.AUTH0_CLIENT_ID
    assert settings.AUTH0_AUDIENCE

    # Test FGA fields are populated
    assert settings.FGA_STORE_ID
    assert settings.FGA_CLIENT_ID
    assert settings.FGA_CLIENT_SECRET
    assert settings.FGA_API_URL


def test_settings_can_override_from_env(monkeypatch):
    """Test that environment variables override default settings."""
    monkeypatch.setenv("AUTH0_DOMAIN", "custom.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "custom_client_id")
    monkeypatch.setenv("AUTH0_AUDIENCE", "https://api.custom.com")
    monkeypatch.setenv("FGA_STORE_ID", "custom_store_id")
    monkeypatch.setenv("FGA_CLIENT_ID", "custom_fga_client")
    monkeypatch.setenv("FGA_CLIENT_SECRET", "custom_fga_secret")

    settings = Settings()

    assert settings.AUTH0_DOMAIN == "custom.auth0.com"
    assert settings.AUTH0_CLIENT_ID == "custom_client_id"
    assert settings.AUTH0_AUDIENCE == "https://api.custom.com"
    assert settings.FGA_STORE_ID == "custom_store_id"


def test_settings_performance_defaults():
    """Test performance-related settings have reasonable defaults."""
    settings = Settings()

    assert settings.CACHE_CAPACITY == 10000
    assert settings.MAX_CONNECTIONS == 1000
    assert settings.CONNECTION_POOL_SIZE == 100


def test_settings_multiprocessing_defaults():
    """Test multiprocessing settings have valid defaults."""
    settings = Settings()

    assert settings.ENABLE_MULTIPROCESSING is True
    assert settings.JWT_PROCESSOR_WORKERS == 4
    assert settings.HASH_PROCESSOR_WORKERS == 2
    assert settings.VERIFICATION_WORKERS == 2
    assert settings.SHARED_MEMORY_SIZE == 10_000_000


def test_settings_feature_flags():
    """Test feature flag defaults."""
    settings = Settings()

    assert settings.XAA_ENABLED is True
    assert settings.ISPM_ENABLED is True
    assert settings.THREAT_DETECTION_ENABLED is True
    assert settings.AGENT_DIRECTORY_ENABLED is True
