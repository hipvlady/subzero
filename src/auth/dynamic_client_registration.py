"""
Dynamic Client Registration (DCR) Implementation
RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol

Enables MCP clients to automatically register without manual configuration
"""

import secrets
import time
import hashlib
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta

import aiohttp
from pydantic import BaseModel, Field, HttpUrl, validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class ApplicationType(str, Enum):
    """OAuth 2.1 application types"""
    WEB = "web"
    NATIVE = "native"
    SERVICE = "service"


class TokenEndpointAuthMethod(str, Enum):
    """Token endpoint authentication methods"""
    CLIENT_SECRET_POST = "client_secret_post"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_JWT = "client_secret_jwt"
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"  # Public clients only


class GrantType(str, Enum):
    """Supported grant types"""
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"


@dataclass
class RegisteredClient:
    """Registered OAuth 2.1 client"""
    client_id: str
    client_secret: Optional[str] = None
    client_name: str = ""
    application_type: ApplicationType = ApplicationType.WEB
    redirect_uris: List[str] = field(default_factory=list)
    grant_types: List[GrantType] = field(default_factory=lambda: [GrantType.AUTHORIZATION_CODE])
    response_types: List[str] = field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
    scope: str = "openid profile email"

    # Client metadata
    logo_uri: Optional[str] = None
    client_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    tos_uri: Optional[str] = None
    contacts: List[str] = field(default_factory=list)

    # JWKS for private_key_jwt authentication
    jwks_uri: Optional[str] = None
    jwks: Optional[Dict] = None

    # Registration metadata
    created_at: float = field(default_factory=time.time)
    registration_access_token: Optional[str] = None
    registration_client_uri: Optional[str] = None

    # Security
    client_id_issued_at: float = field(default_factory=time.time)
    client_secret_expires_at: float = 0  # 0 = never expires

    # Rate limiting
    request_count: int = 0
    last_request_at: float = 0


class ClientRegistrationRequest(BaseModel):
    """OAuth 2.1 client registration request (RFC 7591)"""

    # Required for MCP clients
    client_name: str = Field(
        ...,
        description="Human-readable client name",
        min_length=1,
        max_length=100
    )
    redirect_uris: List[str] = Field(
        ...,
        description="Array of redirect URIs",
        min_items=1
    )

    # Optional metadata
    application_type: ApplicationType = Field(
        default=ApplicationType.WEB,
        description="Type of OAuth 2.0 client"
    )
    token_endpoint_auth_method: TokenEndpointAuthMethod = Field(
        default=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        description="Authentication method for token endpoint"
    )
    grant_types: List[GrantType] = Field(
        default=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        description="OAuth 2.0 grant types the client will use"
    )
    response_types: List[str] = Field(
        default=["code"],
        description="OAuth 2.0 response types the client will use"
    )
    scope: Optional[str] = Field(
        default="openid profile email",
        description="Space-separated scopes the client requests"
    )

    # Client information
    client_uri: Optional[str] = Field(
        None,
        description="URL of client's home page"
    )
    logo_uri: Optional[str] = Field(
        None,
        description="URL of client's logo"
    )
    tos_uri: Optional[str] = Field(
        None,
        description="URL of client's terms of service"
    )
    policy_uri: Optional[str] = Field(
        None,
        description="URL of client's privacy policy"
    )
    contacts: List[str] = Field(
        default_factory=list,
        description="Contact emails for client"
    )

    # JWKS (for private_key_jwt)
    jwks_uri: Optional[str] = Field(
        None,
        description="URL of client's JSON Web Key Set"
    )
    jwks: Optional[Dict] = Field(
        None,
        description="Client's JSON Web Key Set by value"
    )

    @validator('redirect_uris', each_item=True)
    def validate_redirect_uri(cls, uri: str) -> str:
        """Validate redirect URI format"""
        # Must be HTTPS (except localhost)
        if not uri.startswith(('https://', 'http://localhost', 'http://127.0.0.1')):
            raise ValueError("Redirect URIs must use HTTPS (except localhost)")

        # No fragments allowed
        if '#' in uri:
            raise ValueError("Redirect URIs cannot contain fragments")

        return uri

    @validator('grant_types')
    def validate_grant_types(cls, grant_types: List[GrantType], values: Dict) -> List[GrantType]:
        """Validate grant types consistency"""
        # OAuth 2.1 requires authorization_code with PKCE
        if GrantType.AUTHORIZATION_CODE in grant_types:
            # Automatically add refresh_token for authorization_code flow
            if GrantType.REFRESH_TOKEN not in grant_types:
                grant_types.append(GrantType.REFRESH_TOKEN)

        return grant_types


class DynamicClientRegistration:
    """
    Dynamic Client Registration service
    Implements RFC 7591 and RFC 7592
    """

    def __init__(
        self,
        issuer: str,
        auth0_domain: Optional[str] = None,
        enable_auth0_sync: bool = False
    ):
        """
        Initialize DCR service

        Args:
            issuer: Authorization server issuer URL
            auth0_domain: Auth0 domain for syncing registrations
            enable_auth0_sync: Whether to sync registrations with Auth0
        """
        self.issuer = issuer.rstrip('/')
        self.auth0_domain = auth0_domain
        self.enable_auth0_sync = enable_auth0_sync

        # In-memory client registry (use database in production)
        self.clients: Dict[str, RegisteredClient] = {}

        # Registration access tokens for client management
        self.registration_tokens: Dict[str, str] = {}  # token -> client_id

        # Security counters
        self.registration_count = 0
        self.failed_registrations = 0

        # HTTP session for Auth0 sync
        if self.enable_auth0_sync:
            connector = aiohttp.TCPConnector(limit=100)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    async def register_client(
        self,
        request: ClientRegistrationRequest,
        initial_access_token: Optional[str] = None
    ) -> Dict:
        """
        Register a new OAuth 2.1 client

        Args:
            request: Client registration request
            initial_access_token: Optional token for protected registration endpoint

        Returns:
            Client registration response with client_id and client_secret
        """
        start_time = time.perf_counter()

        try:
            # Validate initial access token (if required)
            if initial_access_token and not self._validate_initial_access_token(initial_access_token):
                self.failed_registrations += 1
                return {
                    'error': 'invalid_token',
                    'error_description': 'Invalid initial access token'
                }

            # Generate client credentials
            client_id = self._generate_client_id()
            client_secret = None

            # Only generate secret for confidential clients
            if request.token_endpoint_auth_method != TokenEndpointAuthMethod.NONE:
                client_secret = self._generate_client_secret()

            # Generate registration access token
            registration_access_token = secrets.token_urlsafe(64)
            registration_client_uri = f"{self.issuer}/oauth/register/{client_id}"

            # Create registered client
            registered_client = RegisteredClient(
                client_id=client_id,
                client_secret=client_secret,
                client_name=request.client_name,
                application_type=request.application_type,
                redirect_uris=request.redirect_uris,
                grant_types=request.grant_types,
                response_types=request.response_types,
                token_endpoint_auth_method=request.token_endpoint_auth_method,
                scope=request.scope or "openid profile email",
                logo_uri=request.logo_uri,
                client_uri=request.client_uri,
                policy_uri=request.policy_uri,
                tos_uri=request.tos_uri,
                contacts=request.contacts,
                jwks_uri=request.jwks_uri,
                jwks=request.jwks,
                registration_access_token=registration_access_token,
                registration_client_uri=registration_client_uri,
                client_secret_expires_at=0  # Never expires by default
            )

            # Store client
            self.clients[client_id] = registered_client
            self.registration_tokens[registration_access_token] = client_id

            # Sync with Auth0 if enabled
            if self.enable_auth0_sync and self.auth0_domain:
                await self._sync_with_auth0(registered_client)

            self.registration_count += 1

            latency_ms = (time.perf_counter() - start_time) * 1000

            # Return registration response (RFC 7591 Section 3.2.1)
            response = {
                'client_id': client_id,
                'client_id_issued_at': int(registered_client.client_id_issued_at),
                'registration_access_token': registration_access_token,
                'registration_client_uri': registration_client_uri,
                'client_name': request.client_name,
                'redirect_uris': request.redirect_uris,
                'grant_types': [gt.value for gt in request.grant_types],
                'response_types': request.response_types,
                'application_type': request.application_type.value,
                'token_endpoint_auth_method': request.token_endpoint_auth_method.value,
                'scope': request.scope,
                'processing_time_ms': latency_ms
            }

            # Add client_secret for confidential clients
            if client_secret:
                response['client_secret'] = client_secret
                response['client_secret_expires_at'] = 0

            # Add JWKS if provided
            if request.jwks_uri:
                response['jwks_uri'] = request.jwks_uri
            elif request.jwks:
                response['jwks'] = request.jwks

            # Add optional metadata
            if request.client_uri:
                response['client_uri'] = request.client_uri
            if request.logo_uri:
                response['logo_uri'] = request.logo_uri
            if request.policy_uri:
                response['policy_uri'] = request.policy_uri
            if request.tos_uri:
                response['tos_uri'] = request.tos_uri
            if request.contacts:
                response['contacts'] = request.contacts

            return response

        except ValueError as e:
            self.failed_registrations += 1
            latency_ms = (time.perf_counter() - start_time) * 1000
            return {
                'error': 'invalid_client_metadata',
                'error_description': str(e),
                'processing_time_ms': latency_ms
            }

        except Exception as e:
            self.failed_registrations += 1
            latency_ms = (time.perf_counter() - start_time) * 1000
            return {
                'error': 'server_error',
                'error_description': f'Registration failed: {str(e)}',
                'processing_time_ms': latency_ms
            }

    async def get_client(
        self,
        client_id: str,
        registration_access_token: str
    ) -> Optional[Dict]:
        """
        Retrieve client configuration (RFC 7592 Section 3)

        Args:
            client_id: Client identifier
            registration_access_token: Registration access token

        Returns:
            Client configuration or None if not found/unauthorized
        """
        # Validate registration access token
        if registration_access_token not in self.registration_tokens:
            return None

        token_client_id = self.registration_tokens[registration_access_token]

        # Verify token matches client
        if token_client_id != client_id:
            return None

        # Get client
        if client_id not in self.clients:
            return None

        client = self.clients[client_id]

        # Return client configuration
        return {
            'client_id': client.client_id,
            'client_name': client.client_name,
            'redirect_uris': client.redirect_uris,
            'grant_types': [gt.value for gt in client.grant_types],
            'response_types': client.response_types,
            'application_type': client.application_type.value,
            'token_endpoint_auth_method': client.token_endpoint_auth_method.value,
            'scope': client.scope,
            'client_id_issued_at': int(client.client_id_issued_at),
            'registration_access_token': client.registration_access_token,
            'registration_client_uri': client.registration_client_uri
        }

    async def update_client(
        self,
        client_id: str,
        registration_access_token: str,
        updates: Dict
    ) -> Optional[Dict]:
        """
        Update client configuration (RFC 7592 Section 2)

        Args:
            client_id: Client identifier
            registration_access_token: Registration access token
            updates: Updated client metadata

        Returns:
            Updated client configuration or None if not found/unauthorized
        """
        # Validate registration access token
        if registration_access_token not in self.registration_tokens:
            return None

        token_client_id = self.registration_tokens[registration_access_token]

        if token_client_id != client_id or client_id not in self.clients:
            return None

        client = self.clients[client_id]

        # Update allowed fields
        if 'client_name' in updates:
            client.client_name = updates['client_name']
        if 'redirect_uris' in updates:
            client.redirect_uris = updates['redirect_uris']
        if 'logo_uri' in updates:
            client.logo_uri = updates['logo_uri']
        if 'client_uri' in updates:
            client.client_uri = updates['client_uri']
        if 'policy_uri' in updates:
            client.policy_uri = updates['policy_uri']
        if 'tos_uri' in updates:
            client.tos_uri = updates['tos_uri']
        if 'contacts' in updates:
            client.contacts = updates['contacts']

        return await self.get_client(client_id, registration_access_token)

    async def delete_client(
        self,
        client_id: str,
        registration_access_token: str
    ) -> bool:
        """
        Delete client registration (RFC 7592 Section 4)

        Args:
            client_id: Client identifier
            registration_access_token: Registration access token

        Returns:
            True if deleted, False if not found/unauthorized
        """
        # Validate registration access token
        if registration_access_token not in self.registration_tokens:
            return False

        token_client_id = self.registration_tokens[registration_access_token]

        if token_client_id != client_id or client_id not in self.clients:
            return False

        # Delete client
        del self.clients[client_id]
        del self.registration_tokens[registration_access_token]

        return True

    def _generate_client_id(self) -> str:
        """Generate unique client identifier"""
        # Format: ztag_<timestamp>_<random>
        timestamp = int(time.time())
        random_part = secrets.token_urlsafe(16)
        return f"ztag_{timestamp}_{random_part}"

    def _generate_client_secret(self) -> str:
        """Generate cryptographically secure client secret"""
        return secrets.token_urlsafe(64)

    def _validate_initial_access_token(self, token: str) -> bool:
        """
        Validate initial access token for protected registration endpoint
        In production, verify against auth0 or token database
        """
        # Placeholder - implement actual validation
        return len(token) > 32

    async def _sync_with_auth0(self, client: RegisteredClient) -> bool:
        """
        Sync registered client with Auth0
        Creates corresponding client in Auth0 for SSO
        """
        if not self.auth0_domain:
            return False

        try:
            # Auth0 Management API endpoint
            url = f"https://{self.auth0_domain}/api/v2/clients"

            # Prepare Auth0 client payload
            payload = {
                'name': client.client_name,
                'app_type': self._map_app_type_to_auth0(client.application_type),
                'callbacks': client.redirect_uris,
                'grant_types': [gt.value for gt in client.grant_types],
                'client_id': client.client_id  # Use same client_id
            }

            # Add client_secret for confidential clients
            if client.client_secret:
                payload['client_secret'] = client.client_secret

            # In production, use Management API token
            # For now, log the sync attempt
            print(f"📡 Would sync client {client.client_id} with Auth0")

            return True

        except Exception as e:
            print(f"❌ Auth0 sync failed: {e}")
            return False

    def _map_app_type_to_auth0(self, app_type: ApplicationType) -> str:
        """Map OAuth 2.1 application type to Auth0 app type"""
        mapping = {
            ApplicationType.WEB: 'regular_web',
            ApplicationType.NATIVE: 'native',
            ApplicationType.SERVICE: 'non_interactive'
        }
        return mapping.get(app_type, 'regular_web')

    def get_client_by_id(self, client_id: str) -> Optional[RegisteredClient]:
        """Get registered client by ID (for internal use)"""
        return self.clients.get(client_id)

    async def get_metrics(self) -> Dict:
        """Get DCR metrics"""
        return {
            'total_clients': len(self.clients),
            'registration_count': self.registration_count,
            'failed_registrations': self.failed_registrations,
            'clients_by_type': {
                app_type.value: len([
                    c for c in self.clients.values()
                    if c.application_type == app_type
                ])
                for app_type in ApplicationType
            }
        }

    async def close(self):
        """Clean up resources"""
        if hasattr(self, 'session'):
            await self.session.close()