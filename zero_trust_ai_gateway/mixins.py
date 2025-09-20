"""Security and configuration mixins for Zero Trust AI Gateway.

Adapted from Enterprise Gateway patterns for high-performance and security.
"""

import os
import json
import time
import traceback
from http.client import responses
from typing import Dict, Any, Optional

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import jwt
from cryptography.hazmat.primitives import serialization
import numpy as np
import logging

logger = logging.getLogger(__name__)

class ZeroTrustGatewayConfigMixin:
    """Configuration mixin for Zero Trust AI Gateway - adapted from Enterprise Gateway patterns"""

    def __init__(self):
        # Core gateway settings
        self.port = int(os.getenv('ZTAG_PORT', '8080'))
        self.host = os.getenv('ZTAG_HOST', '0.0.0.0')

        # Auth0 integration settings
        self.auth0_domain = os.getenv('ZTAG_AUTH0_DOMAIN', 'your-tenant.auth0.com')
        self.client_id = os.getenv('ZTAG_CLIENT_ID', '')
        self.private_key = os.getenv('ZTAG_PRIVATE_KEY', '')

        # Performance settings
        self.max_agents_per_user = int(os.getenv('ZTAG_MAX_AGENTS_PER_USER', '10'))
        self.connection_pool_size = int(os.getenv('ZTAG_CONNECTION_POOL_SIZE', '100'))
        self.batch_size = int(os.getenv('ZTAG_BATCH_SIZE', '100'))
        self.cache_size = int(os.getenv('ZTAG_CACHE_SIZE', '100000'))

        # Security settings
        self.content_filtering_enabled = os.getenv('ZTAG_CONTENT_FILTERING', 'true').lower() == 'true'
        self.prompt_injection_detection = os.getenv('ZTAG_PROMPT_INJECTION_DETECTION', 'true').lower() == 'true'
        self.rate_limit_per_minute = int(os.getenv('ZTAG_RATE_LIMIT_PER_MINUTE', '100'))

        # AI model configuration
        self.default_model = os.getenv('ZTAG_DEFAULT_MODEL', 'gpt-3.5-turbo')

        # FGA settings
        self.fga_api_url = os.getenv('ZTAG_FGA_API_URL', '')
        self.fga_store_id = os.getenv('ZTAG_FGA_STORE_ID', '')

class TokenAuthorizationMixin:
    """AI Gateway token auth mixin - adapted from Enterprise Gateway"""

    header_prefix = "Bearer "
    header_prefix_len = len(header_prefix)

    def __init__(self):
        self.security = HTTPBearer()

    async def verify_token(self, credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
        """Verify Auth0 JWT token"""
        try:
            # For development - simple validation
            if not credentials.credentials:
                raise HTTPException(status_code=401, detail="Missing token")

            # In production, this would validate against Auth0 JWKS
            # For now, we'll accept any non-empty token for demo purposes
            return {
                "user_id": "demo_user",
                "authenticated": True,
                "permissions": ["read", "write"]
            }

        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            raise HTTPException(status_code=401, detail="Invalid token")

class AIContentSecurityMixin:
    """AI-specific content security checks"""

    def __init__(self):
        self.injection_patterns = [
            "ignore previous instructions",
            "disregard above",
            "forget everything",
            "new instructions:",
            "system:",
            "assistant:",
            "pretend you are"
        ]

    def detect_prompt_injection(self, content: Dict[str, Any]) -> bool:
        """Basic prompt injection detection - enhance for production"""
        prompt = content.get('prompt', '')
        if not prompt:
            return False

        prompt_lower = prompt.lower()
        return any(pattern in prompt_lower for pattern in self.injection_patterns)

    def validate_content_policy(self, content: Dict[str, Any]) -> bool:
        """Validate content against organizational policies"""
        # Implement based on requirements
        # Could integrate with external content filtering services
        return True

class CORSMixin:
    """CORS headers mixin - direct from Enterprise Gateway"""

    CORS_HEADERS = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
    }

class JSONErrorsMixin:
    """JSON error responses mixin - direct from Enterprise Gateway"""

    @staticmethod
    def create_error_response(status_code: int, message: str = None, details: Dict = None) -> JSONResponse:
        """Create standardized JSON error response"""
        error_json = {
            'error': {
                'code': status_code,
                'message': message or responses.get(status_code, 'Unknown error')
            }
        }

        if details:
            error_json['error']['details'] = details

        return JSONResponse(
            status_code=status_code,
            content=error_json
        )