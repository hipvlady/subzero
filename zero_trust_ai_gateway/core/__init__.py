"""Core integration layer for Zero Trust AI Gateway.

This module provides the integration layer that combines parent directory
components with gateway-specific functionality.
"""

from .gateway import ZeroTrustAIGateway, GatewayConfig
from .adapters import AuthAdapter, FGAAdapter, PerformanceAdapter

__all__ = [
    'ZeroTrustAIGateway',
    'GatewayConfig',
    'AuthAdapter',
    'FGAAdapter',
    'PerformanceAdapter'
]