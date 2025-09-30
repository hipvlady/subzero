"""
Copyright (c) 2025 Subzero Contributors
Licensed under the MIT License

Subzero - Zero Trust API Gateway
=================================

High-performance authentication and authorization gateway for AI-native applications.

Features:
- Secretless authentication (Private Key JWT)
- Fine-grained authorization (ReBAC, ABAC, OPA)
- AI agent security (MCP protocol, XAA)
- Advanced threat detection
- Performance orchestration (10K+ RPS)
"""

from subzero._version import __version__, version_info

__all__ = [
    "__version__",
    "version_info",
]
