"""
OAuth 2.1 / OpenID Connect Metadata Discovery
Implements RFC 8414 (OAuth 2.0 Authorization Server Metadata)
and OpenID Connect Discovery 1.0

Provides /.well-known/openid-configuration endpoint for automatic
configuration discovery by MCP clients and other OAuth 2.1 clients
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class ResponseType(str, Enum):
    """Supported OAuth 2.1 response types"""
    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


class GrantType(str, Enum):
    """Supported OAuth 2.1 grant types"""
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class CodeChallengeMethod(str, Enum):
    """PKCE code challenge methods"""
    S256 = "S256"  # SHA-256 (required by OAuth 2.1)
    PLAIN = "plain"  # Deprecated, but listed for compatibility


class TokenEndpointAuthMethod(str, Enum):
    """Token endpoint authentication methods"""
    CLIENT_SECRET_POST = "client_secret_post"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_JWT = "client_secret_jwt"
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"  # For public clients


class OIDCMetadata(BaseModel):
    """
    OpenID Connect Discovery 1.0 Metadata
    Compliant with RFC 8414 and OIDC Discovery spec
    """

    # Required fields
    issuer: str = Field(
        ...,
        description="Authorization server's issuer identifier URL"
    )
    authorization_endpoint: str = Field(
        ...,
        description="URL of the authorization endpoint"
    )
    token_endpoint: str = Field(
        ...,
        description="URL of the token endpoint"
    )
    jwks_uri: str = Field(
        ...,
        description="URL of the JSON Web Key Set document"
    )
    response_types_supported: List[str] = Field(
        default=["code"],
        description="OAuth 2.0 response_type values supported"
    )
    subject_types_supported: List[str] = Field(
        default=["public"],
        description="Subject identifier types supported"
    )
    id_token_signing_alg_values_supported: List[str] = Field(
        default=["RS256"],
        description="JWS signing algorithms supported for ID Token"
    )

    # OAuth 2.1 recommended fields
    grant_types_supported: List[str] = Field(
        default=["authorization_code", "refresh_token"],
        description="OAuth 2.0 grant types supported"
    )
    token_endpoint_auth_methods_supported: List[str] = Field(
        default=["client_secret_post", "client_secret_basic", "private_key_jwt"],
        description="Authentication methods supported by token endpoint"
    )

    # PKCE support (required by OAuth 2.1)
    code_challenge_methods_supported: List[str] = Field(
        default=["S256"],
        description="PKCE code challenge methods supported"
    )

    # Additional endpoints
    userinfo_endpoint: Optional[str] = Field(
        None,
        description="URL of the UserInfo endpoint"
    )
    revocation_endpoint: Optional[str] = Field(
        None,
        description="URL of the token revocation endpoint"
    )
    introspection_endpoint: Optional[str] = Field(
        None,
        description="URL of the token introspection endpoint"
    )
    registration_endpoint: Optional[str] = Field(
        None,
        description="URL of the dynamic client registration endpoint"
    )
    end_session_endpoint: Optional[str] = Field(
        None,
        description="URL of the logout endpoint"
    )

    # Scopes and claims
    scopes_supported: List[str] = Field(
        default=["openid", "profile", "email", "offline_access"],
        description="OAuth 2.0 scope values supported"
    )
    claims_supported: List[str] = Field(
        default=["sub", "name", "email", "email_verified", "picture"],
        description="Claim types supported"
    )
    claims_parameter_supported: bool = Field(
        default=True,
        description="Whether claims parameter is supported"
    )

    # Token features
    request_parameter_supported: bool = Field(
        default=True,
        description="Whether request parameter is supported"
    )
    request_uri_parameter_supported: bool = Field(
        default=True,
        description="Whether request_uri parameter is supported"
    )

    # Security features
    require_request_uri_registration: bool = Field(
        default=False,
        description="Whether request_uri values must be pre-registered"
    )
    require_signed_request_object: bool = Field(
        default=False,
        description="Whether signed request objects are required"
    )

    # DPoP support (OAuth 2.1 enhancement)
    dpop_signing_alg_values_supported: Optional[List[str]] = Field(
        default=["RS256", "ES256"],
        description="JWS algorithms supported for DPoP proof JWTs"
    )

    # Service documentation
    service_documentation: Optional[str] = Field(
        None,
        description="URL of human-readable service documentation"
    )
    op_policy_uri: Optional[str] = Field(
        None,
        description="URL of authorization server's policy document"
    )
    op_tos_uri: Optional[str] = Field(
        None,
        description="URL of authorization server's terms of service"
    )

    class Config:
        use_enum_values = True


class MetadataDiscoveryService:
    """
    OAuth 2.1 / OIDC Metadata Discovery Service
    Generates and serves authorization server metadata
    """

    def __init__(
        self,
        issuer: str,
        auth0_domain: Optional[str] = None,
        enable_dcr: bool = True,
        enable_dpop: bool = True
    ):
        """
        Initialize metadata discovery service

        Args:
            issuer: Base URL of the authorization server (e.g., https://api.example.com)
            auth0_domain: Auth0 domain for delegation (optional)
            enable_dcr: Enable Dynamic Client Registration
            enable_dpop: Enable DPoP (Demonstration of Proof-of-Possession)
        """
        self.issuer = issuer.rstrip('/')
        self.auth0_domain = auth0_domain
        self.enable_dcr = enable_dcr
        self.enable_dpop = enable_dpop

        # Cache metadata for performance
        self._metadata_cache: Optional[Dict] = None
        self._cache_timestamp: float = 0
        self._cache_ttl: int = 3600  # 1 hour

    def get_metadata(self) -> Dict:
        """
        Get OAuth 2.1 / OIDC metadata
        Returns cached metadata if available and fresh
        """
        current_time = time.time()

        # Check cache
        if self._metadata_cache and (current_time - self._cache_timestamp) < self._cache_ttl:
            return self._metadata_cache

        # Generate fresh metadata
        metadata = self._generate_metadata()

        # Update cache
        self._metadata_cache = metadata
        self._cache_timestamp = current_time

        return metadata

    def _generate_metadata(self) -> Dict:
        """
        Generate OAuth 2.1 / OIDC metadata document
        """
        # If Auth0 domain is provided, delegate to Auth0
        if self.auth0_domain:
            return self._generate_auth0_delegated_metadata()

        # Otherwise, generate our own metadata
        return self._generate_local_metadata()

    def _generate_local_metadata(self) -> Dict:
        """
        Generate metadata for local authorization server
        """
        metadata = OIDCMetadata(
            issuer=self.issuer,
            authorization_endpoint=f"{self.issuer}/oauth/authorize",
            token_endpoint=f"{self.issuer}/oauth/token",
            jwks_uri=f"{self.issuer}/.well-known/jwks.json",
            userinfo_endpoint=f"{self.issuer}/userinfo",
            revocation_endpoint=f"{self.issuer}/oauth/revoke",
            introspection_endpoint=f"{self.issuer}/oauth/introspect",
            end_session_endpoint=f"{self.issuer}/logout",

            # OAuth 2.1 features
            response_types_supported=["code"],
            grant_types_supported=[
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ],
            code_challenge_methods_supported=["S256"],  # Only SHA-256

            # Token endpoint authentication
            token_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt",
                "none"  # For public clients with PKCE
            ],

            # Signing algorithms
            id_token_signing_alg_values_supported=["RS256", "ES256"],

            # Scopes
            scopes_supported=[
                "openid",
                "profile",
                "email",
                "offline_access",
                "read:mcp",
                "write:mcp"
            ],

            # Claims
            claims_supported=[
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "name",
                "email",
                "email_verified",
                "picture",
                "updated_at"
            ],

            # Security features
            require_signed_request_object=False,
            require_request_uri_registration=False,

            # Documentation
            service_documentation=f"{self.issuer}/docs",
            op_policy_uri=f"{self.issuer}/policy",
            op_tos_uri=f"{self.issuer}/terms"
        )

        # Add DCR endpoint if enabled
        if self.enable_dcr:
            metadata.registration_endpoint = f"{self.issuer}/oauth/register"

        # Add DPoP support if enabled
        if self.enable_dpop:
            metadata.dpop_signing_alg_values_supported = ["RS256", "ES256"]

        return metadata.dict(exclude_none=True)

    def _generate_auth0_delegated_metadata(self) -> Dict:
        """
        Generate metadata that delegates to Auth0
        Combines local MCP endpoints with Auth0 OAuth endpoints
        """
        auth0_base = f"https://{self.auth0_domain}"

        metadata = OIDCMetadata(
            issuer=auth0_base + "/",
            authorization_endpoint=f"{auth0_base}/authorize",
            token_endpoint=f"{auth0_base}/oauth/token",
            jwks_uri=f"{auth0_base}/.well-known/jwks.json",
            userinfo_endpoint=f"{auth0_base}/userinfo",
            revocation_endpoint=f"{auth0_base}/oauth/revoke",
            end_session_endpoint=f"{auth0_base}/v2/logout",

            # OAuth 2.1 features
            response_types_supported=[
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "token id_token",
                "code token id_token"
            ],
            grant_types_supported=[
                "authorization_code",
                "implicit",
                "refresh_token",
                "client_credentials",
                "password",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ],
            code_challenge_methods_supported=["S256", "plain"],

            # Token endpoint authentication
            token_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt"
            ],

            # Signing algorithms (Auth0 supports multiple)
            id_token_signing_alg_values_supported=[
                "RS256",
                "HS256"
            ],

            # Auth0 scopes
            scopes_supported=[
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access"
            ],

            # Claims
            claims_supported=[
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "acr",
                "amr",
                "azp",
                "name",
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "email",
                "email_verified",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "phone_number",
                "phone_number_verified",
                "address",
                "updated_at"
            ],

            # Subject types
            subject_types_supported=["public"],

            # Documentation
            service_documentation="https://auth0.com/docs",
            op_policy_uri=f"{auth0_base}/privacy",
            op_tos_uri=f"{auth0_base}/terms"
        )

        # Add MCP-specific endpoints (hosted locally)
        result = metadata.dict(exclude_none=True)
        result['mcp_endpoint'] = f"{self.issuer}/mcp"
        result['mcp_transport_types_supported'] = ["sse", "stdio", "http"]

        return result

    def get_jwks(self) -> Dict:
        """
        Get JSON Web Key Set (JWKS)
        Returns public keys for token verification
        """
        # If using Auth0, delegate to Auth0's JWKS endpoint
        if self.auth0_domain:
            return {
                'keys': [],
                'auth0_jwks_uri': f"https://{self.auth0_domain}/.well-known/jwks.json"
            }

        # Otherwise, return local JWKS
        # In production, load actual public keys from key storage
        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'ztag-2024-01',
                    'alg': 'RS256',
                    'n': 'placeholder_modulus',
                    'e': 'AQAB'
                }
            ]
        }

    async def fetch_auth0_metadata(self) -> Optional[Dict]:
        """
        Fetch metadata from Auth0 for validation
        Useful for testing delegation setup
        """
        if not self.auth0_domain:
            return None

        import aiohttp

        url = f"https://{self.auth0_domain}/.well-known/openid-configuration"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            print(f"Failed to fetch Auth0 metadata: {e}")
            return None

    def invalidate_cache(self):
        """
        Invalidate metadata cache
        Call this when configuration changes
        """
        self._metadata_cache = None
        self._cache_timestamp = 0