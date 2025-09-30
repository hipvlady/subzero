"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Basic performance benchmarks for configuration loading.
"""

import pytest

from subzero.config.defaults import Settings


def test_settings_instantiation(benchmark):
    """Benchmark Settings instantiation time."""

    def create_settings():
        return Settings()

    result = benchmark(create_settings)
    assert result is not None
    assert result.AUTH0_DOMAIN


def test_settings_attribute_access(benchmark):
    """Benchmark Settings attribute access speed."""
    settings = Settings()

    def access_attributes():
        return (
            settings.AUTH0_DOMAIN,
            settings.FGA_STORE_ID,
            settings.CACHE_CAPACITY,
            settings.ENABLE_MULTIPROCESSING,
        )

    result = benchmark(access_attributes)
    assert len(result) == 4


@pytest.mark.benchmark(group="settings")
def test_settings_override_performance(benchmark, monkeypatch):
    """Benchmark Settings creation with environment overrides."""
    monkeypatch.setenv("AUTH0_DOMAIN", "perf.auth0.com")
    monkeypatch.setenv("FGA_STORE_ID", "perf_store_id")

    def create_with_env():
        return Settings()

    result = benchmark(create_with_env)
    assert result.AUTH0_DOMAIN == "perf.auth0.com"
