"""
Performance test utilities for CI-aware thresholds.

This module provides helper functions to adjust performance expectations
based on the execution environment (CI vs local development).

CI environments typically have:
- Shared/limited CPU resources
- Variable performance due to noisy neighbors
- Different hardware characteristics

Therefore, performance thresholds are relaxed in CI to prevent flaky failures
while maintaining strict standards for local development.
"""

import os


def is_ci() -> bool:
    """
    Detect if running in CI environment.

    Returns
    -------
    bool
        True if running in CI, False otherwise
    """
    # GitHub Actions sets CI=true
    # Also check for common CI environment variables
    return os.getenv("CI", "").lower() == "true" or os.getenv("GITHUB_ACTIONS") == "true"


def get_threshold(local_value: float, ci_multiplier: float = 3.0) -> float:
    """
    Get CI-aware performance threshold.

    In CI, thresholds are relaxed by the multiplier to account for:
    - Shared resources (CPU/memory)
    - Virtualized environments
    - Variable performance

    Parameters
    ----------
    local_value : float
        Strict threshold for local development
    ci_multiplier : float, optional
        Multiplier for CI threshold (default: 3.0)

    Returns
    -------
    float
        Adjusted threshold value

    Examples
    --------
    >>> # Local: <1ms, CI: <3ms
    >>> threshold = get_threshold(1.0, ci_multiplier=3.0)
    >>> assert latency_ms < threshold
    """
    if is_ci():
        return local_value * ci_multiplier
    return local_value


def get_rps_threshold(local_rps: int, ci_reduction: float = 0.5) -> int:
    """
    Get CI-aware RPS (requests per second) threshold.

    In CI, RPS expectations are reduced due to limited resources.

    Parameters
    ----------
    local_rps : int
        Expected RPS for local development
    ci_reduction : float, optional
        Reduction factor for CI (default: 0.5 = 50% of local)

    Returns
    -------
    int
        Adjusted RPS threshold

    Examples
    --------
    >>> # Local: 10,000 RPS, CI: 5,000 RPS
    >>> threshold = get_rps_threshold(10000, ci_reduction=0.5)
    >>> assert measured_rps >= threshold
    """
    if is_ci():
        return int(local_rps * ci_reduction)
    return local_rps


def skip_if_ci_slow(reason: str = "Too slow for CI environment"):
    """
    Decorator to skip tests that are too slow for CI.

    Use this for tests that:
    - Take >1 minute to run
    - Require specific hardware (GPUs, etc.)
    - Are not critical for CI validation

    Parameters
    ----------
    reason : str, optional
        Reason for skipping in CI

    Examples
    --------
    @skip_if_ci_slow("Requires 8+ CPU cores")
    def test_heavy_multiprocessing():
        ...
    """
    import pytest

    return pytest.mark.skipif(is_ci(), reason=reason)


def print_threshold_info(metric_name: str, local_value: float, ci_value: float, unit: str = "ms"):
    """
    Print threshold information for debugging.

    Parameters
    ----------
    metric_name : str
        Name of the metric (e.g., "EdDSA signing latency")
    local_value : float
        Local threshold value
    ci_value : float
        CI threshold value
    unit : str, optional
        Unit of measurement (default: "ms")
    """
    env = "CI" if is_ci() else "Local"
    current_threshold = ci_value if is_ci() else local_value
    print(f"📊 {metric_name} threshold ({env}): <{current_threshold}{unit}")
    if is_ci():
        print(f"   (Local threshold: <{local_value}{unit}, CI relaxed by {ci_value/local_value:.1f}x)")
