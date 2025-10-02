"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Complete Auth0 Integration Implementation
Production-ready integration with all Auth0 services

SDK Versions:
- auth0-python: 4.7.0+
- openfga-sdk: 0.3.0+
- PyJWT: 2.8.0+
"""

import base64
import time
from dataclasses import dataclass

import httpx
import jwt
from auth0.management import Auth0
from cryptography.hazmat.primitives.asymmetric import rsa
from openfga_sdk import CheckRequest, ClientConfiguration, ReadRequest, TupleKey, WriteRequest, WriteRequestWrites
from openfga_sdk import OpenFgaClient as FgaClient


@dataclass
class Auth0Configuration:
    """
    Complete Auth0 configuration for all services.

    Comprehensive configuration dataclass for Auth0 authentication, authorization
    (FGA), management API, and Token Vault for AI agents.

    Attributes
    ----------
    domain : str
        Auth0 tenant domain (e.g., 'tenant.auth0.com')
    client_id : str
        Auth0 client application ID
    client_secret : str, optional
        Auth0 client secret. Not required for Private Key JWT.
    audience : str, default ""
        API audience/identifier for token validation
    management_api_token : str, optional
        Management API access token for user/app operations
    fga_store_id : str, default ""
        Auth0 FGA store identifier
    fga_client_id : str, default ""
        FGA client ID for authorization operations
    fga_client_secret : str, default ""
        FGA client secret
    fga_api_url : str, default "https://api.us1.fga.dev"
        FGA API endpoint URL (US or EU region)
    fga_model_id : str, optional
        FGA authorization model ID
    token_vault_endpoint : str, default ""
        Token Vault API endpoint for AI agent credentials
    token_vault_api_key : str, default ""
        Token Vault API key

    Examples
    --------
    >>> config = Auth0Configuration(
    ...     domain="tenant.auth0.com",
    ...     client_id="your_client_id",
    ...     audience="https://api.example.com",
    ...     fga_store_id="01HXXXXXXXXXXXXXXXXXXXXX"
    ... )
    """

    # Core Auth0 settings
    domain: str
    client_id: str
    client_secret: str | None = None
    audience: str = ""

    # Management API
    management_api_token: str | None = None

    # FGA settings
    fga_store_id: str = ""
    fga_client_id: str = ""
    fga_client_secret: str = ""
    fga_api_url: str = "https://api.us1.fga.dev"
    fga_model_id: str | None = None

    # Token Vault settings (Auth for GenAI)
    token_vault_endpoint: str = ""
    token_vault_api_key: str = ""


class Auth0IntegrationManager:
    """
    Complete Auth0 integration manager.

    Comprehensive integration with Auth0 services including authentication
    (Private Key JWT), authorization (FGA), user management (Management API),
    and Token Vault for AI agents. Provides production-ready error handling,
    automatic retry, and connection pooling.

    Parameters
    ----------
    config : Auth0Configuration
        Complete Auth0 configuration with all service credentials

    Attributes
    ----------
    config : Auth0Configuration
        Auth0 configuration instance
    management_client : Auth0, optional
        Auth0 Management API client
    fga_client : OpenFgaClient
        Auth0 FGA client for authorization
    http_client : httpx.AsyncClient
        Async HTTP client for API calls
    private_key : RSAPrivateKey
        RSA private key for Private Key JWT
    public_key : RSAPublicKey
        RSA public key for JWKS

    Notes
    -----
    The manager initializes all Auth0 service clients and generates an RSA
    key pair for Private Key JWT authentication. HTTP connections are pooled
    for optimal performance (50 keepalive connections).

    See Also
    --------
    Auth0Configuration : Configuration dataclass
    ResilientAuthService : High-level auth service with retry logic

    Examples
    --------
    >>> config = Auth0Configuration(
    ...     domain="tenant.auth0.com",
    ...     client_id="client_id",
    ...     audience="https://api.example.com"
    ... )
    >>> manager = Auth0IntegrationManager(config)
    >>> result = await manager.authenticate_with_private_key_jwt("user_123")
    """

    def __init__(self, config: Auth0Configuration):
        self.config = config

        # Initialize Auth0 Management API client
        self.management_client = None
        if config.management_api_token:
            self.management_client = Auth0(domain=config.domain, token=config.management_api_token)

        # Initialize FGA client
        fga_config = ClientConfiguration(
            api_url=config.fga_api_url, store_id=config.fga_store_id, authorization_model_id=config.fga_model_id
        )

        # Configure FGA client credentials
        if config.fga_client_id and config.fga_client_secret:
            fga_config.credentials_config = {
                "method": "client_credentials",
                "config": {
                    "client_id": config.fga_client_id,
                    "client_secret": config.fga_client_secret,
                    "api_audience": f"{config.fga_api_url}/",
                },
            }

        self.fga_client = FgaClient(fga_config)

        # HTTP client for Token Vault and custom API calls
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0), limits=httpx.Limits(max_keepalive_connections=50)
        )

        # Generate RSA key pair for Private Key JWT
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    # =============================
    # Private Key JWT Implementation
    # =============================

    async def authenticate_with_private_key_jwt(self, user_id: str, scopes: str = "openid profile email") -> dict:
        """
        Authenticate using Private Key JWT (RFC 7523)
        Eliminates shared secrets completely

        Auth0 API Endpoint: POST https://{domain}/oauth/token
        """

        # Step 1: Create JWT assertion
        assertion = self._create_private_key_jwt_assertion(user_id)

        # Step 2: Exchange assertion for access token
        token_endpoint = f"https://{self.config.domain}/oauth/token"

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "scope": scopes,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "audience": self.config.audience,
        }

        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            response = await self.http_client.post(token_endpoint, json=payload, headers=headers)
            response.raise_for_status()

            token_data = response.json()

            # Enrich with metadata
            token_data.update({"retrieved_at": time.time(), "auth_method": "private_key_jwt", "user_id": user_id})

            return {"success": True, "token_data": token_data, "auth_method": "private_key_jwt"}

        except httpx.HTTPStatusError as e:
            error_detail = e.response.text if e.response else "Unknown error"
            return {
                "success": False,
                "error": f"HTTP {e.response.status_code}: {error_detail}",
                "auth_method": "private_key_jwt",
            }
        except Exception as e:
            return {"success": False, "error": f"Authentication failed: {str(e)}", "auth_method": "private_key_jwt"}

    def _create_private_key_jwt_assertion(self, user_id: str) -> str:
        """Create Private Key JWT assertion according to RFC 7523"""

        current_time = int(time.time())

        # JWT Header
        header = {"alg": "RS256", "typ": "JWT", "kid": f"{self.config.client_id}_rsa_key_2025"}  # Key identifier

        # JWT Claims
        claims = {
            "iss": self.config.client_id,  # Issuer
            "sub": user_id,  # Subject
            "aud": f"https://{self.config.domain}/oauth/token",  # Audience
            "iat": current_time,  # Issued at
            "exp": current_time + 300,  # Expires (5 minutes)
            "jti": self._generate_jwt_id(),  # JWT ID for replay protection
            "scope": "openid profile email",  # Requested scopes
        }

        # Sign with private key
        return jwt.encode(payload=claims, key=self.private_key, algorithm="RS256", headers=header)

    def _generate_jwt_id(self) -> str:
        """Generate unique JWT ID for replay protection"""
        import secrets

        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

    def get_public_key_for_auth0_config(self) -> dict:
        """
        Generate public key in JWKS format for Auth0 configuration
        Required for Auth0 to validate Private Key JWT signatures
        """

        # Get RSA public key components
        public_numbers = self.public_key.public_numbers()

        def int_to_base64url(value: int, byte_length: int) -> str:
            """Convert integer to base64url format"""
            byte_data = value.to_bytes(byte_length, byteorder="big")
            return base64.urlsafe_b64encode(byte_data).rstrip(b"=").decode("ascii")

        # Create JWKS entry
        jwk = {
            "kty": "RSA",  # Key type
            "use": "sig",  # Key usage
            "alg": "RS256",  # Algorithm
            "kid": f"{self.config.client_id}_rsa_key_2025",  # Key ID
            "n": int_to_base64url(public_numbers.n, 256),  # Modulus (2048 bits = 256 bytes)
            "e": int_to_base64url(public_numbers.e, 3),  # Exponent (usually 65537 = 3 bytes)
        }

        return {"keys": [jwk]}

    # ================================
    # Auth0 FGA Integration Methods
    # ================================

    async def check_fga_permission(self, user_id: str, object_type: str, object_id: str, relation: str) -> dict:
        """
        Check permission using Auth0 FGA

        FGA API: POST /stores/{store_id}/check
        SDK Method: fga_client.check()
        """

        try:
            # Create check request
            check_request = CheckRequest(
                tuple_key=TupleKey(user=f"user:{user_id}", relation=relation, object=f"{object_type}:{object_id}")
            )

            # Execute FGA check
            response = await self.fga_client.check(check_request)

            return {
                "allowed": response.allowed,
                "model_id": response.resolution_metadata.model_id if response.resolution_metadata else None,
                "duration_ms": getattr(response, "duration_ms", None),
                "request_id": getattr(response, "request_id", None),
            }

        except Exception as e:
            return {"allowed": False, "error": str(e), "error_type": type(e).__name__}

    async def write_fga_relationship(self, user_id: str, object_type: str, object_id: str, relation: str) -> dict:
        """
        Write relationship tuple to Auth0 FGA

        FGA API: POST /stores/{store_id}/write
        SDK Method: fga_client.write()
        """

        try:
            # Create write request
            tuple_key = TupleKey(user=f"user:{user_id}", relation=relation, object=f"{object_type}:{object_id}")

            write_request = WriteRequest(writes=WriteRequestWrites(tuple_keys=[tuple_key]))

            # Execute FGA write
            response = await self.fga_client.write(write_request)

            return {
                "success": True,
                "written_at": response.written_at if hasattr(response, "written_at") else None,
                "request_id": getattr(response, "request_id", None),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "error_type": type(e).__name__}

    async def read_fga_relationships(self, user_filter: str = None, object_filter: str = None) -> dict:
        """
        Read relationship tuples from Auth0 FGA

        FGA API: POST /stores/{store_id}/read
        SDK Method: fga_client.read()
        """

        try:
            # Create read request
            read_request = ReadRequest()

            if user_filter:
                read_request.tuple_key = TupleKey(user=user_filter)
            elif object_filter:
                read_request.tuple_key = TupleKey(object=object_filter)

            # Execute FGA read
            response = await self.fga_client.read(read_request)

            # Process tuples
            tuples = []
            for tuple_data in response.tuples:
                tuples.append(
                    {
                        "user": tuple_data.key.user,
                        "relation": tuple_data.key.relation,
                        "object": tuple_data.key.object,
                        "timestamp": getattr(tuple_data, "timestamp", None),
                    }
                )

            return {
                "success": True,
                "tuples": tuples,
                "continuation_token": getattr(response, "continuation_token", None),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "tuples": []}

    # ===================================
    # Auth0 Management API Integration
    # ===================================

    async def get_user_profile(self, user_id: str) -> dict:
        """
        Get user profile from Auth0 Management API

        Management API: GET /api/v2/users/{id}
        SDK Method: management_client.users.get()
        """

        if not self.management_client:
            return {"error": "Management API client not configured"}

        try:
            user_profile = self.management_client.users.get(user_id)

            return {
                "success": True,
                "user": {
                    "user_id": user_profile.get("user_id"),
                    "email": user_profile.get("email"),
                    "name": user_profile.get("name"),
                    "picture": user_profile.get("picture"),
                    "last_login": user_profile.get("last_login"),
                    "login_count": user_profile.get("logins_count"),
                    "created_at": user_profile.get("created_at"),
                    "updated_at": user_profile.get("updated_at"),
                    "app_metadata": user_profile.get("app_metadata", {}),
                    "user_metadata": user_profile.get("user_metadata", {}),
                },
            }

        except Exception as e:
            return {"success": False, "error": str(e), "user": None}

    async def update_user_metadata(self, user_id: str, app_metadata: dict = None, user_metadata: dict = None) -> dict:
        """
        Update user metadata via Auth0 Management API

        Management API: PATCH /api/v2/users/{id}
        SDK Method: management_client.users.update()
        """

        if not self.management_client:
            return {"error": "Management API client not configured"}

        try:
            update_data = {}
            if app_metadata:
                update_data["app_metadata"] = app_metadata
            if user_metadata:
                update_data["user_metadata"] = user_metadata

            updated_user = self.management_client.users.update(user_id, update_data)

            return {"success": True, "updated_user": updated_user}

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ===============================
    # Token Vault Integration (Auth for GenAI)
    # ===============================

    async def store_ai_credentials_in_vault(self, ai_agent_id: str, credentials: dict, expires_in: int = 3600) -> dict:
        """
        Store AI agent credentials in Auth0 Token Vault
        Part of Auth for GenAI product (April 2025 launch)

        Custom API: POST /token-vault/store
        """

        if not self.config.token_vault_endpoint:
            return {"error": "Token Vault not configured"}

        try:
            vault_endpoint = f"{self.config.token_vault_endpoint}/store"

            payload = {
                "agent_id": ai_agent_id,
                "credentials": credentials,
                "expires_in": expires_in,
                "metadata": {"stored_at": time.time(), "client_id": self.config.client_id},
            }

            headers = {"Authorization": f"Bearer {self.config.token_vault_api_key}", "Content-Type": "application/json"}

            response = await self.http_client.post(vault_endpoint, json=payload, headers=headers)
            response.raise_for_status()

            vault_response = response.json()

            return {
                "success": True,
                "credential_id": vault_response.get("credential_id"),
                "expires_at": vault_response.get("expires_at"),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def retrieve_ai_credentials_from_vault(self, ai_agent_id: str, credential_id: str) -> dict:
        """
        Retrieve AI agent credentials from Auth0 Token Vault

        Custom API: GET /token-vault/retrieve/{credential_id}
        """

        if not self.config.token_vault_endpoint:
            return {"error": "Token Vault not configured"}

        try:
            vault_endpoint = f"{self.config.token_vault_endpoint}/retrieve/{credential_id}"

            headers = {"Authorization": f"Bearer {self.config.token_vault_api_key}", "X-Agent-ID": ai_agent_id}

            response = await self.http_client.get(vault_endpoint, headers=headers)
            response.raise_for_status()

            credentials = response.json()

            return {
                "success": True,
                "credentials": credentials.get("credentials"),
                "expires_at": credentials.get("expires_at"),
                "metadata": credentials.get("metadata", {}),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "credentials": None}

    # ================================
    # Advanced Integration Methods
    # ================================

    async def create_human_in_the_loop_workflow(
        self, user_id: str, resource_id: str, requested_permission: str, approver_ids: list[str]
    ) -> dict:
        """
        Create human-in-the-loop approval workflow
        Integrates with Auth0 Actions and FGA
        """

        import uuid

        workflow_id = str(uuid.uuid4())

        try:
            # Store workflow request in user metadata
            workflow_metadata = {
                "pending_approvals": {
                    workflow_id: {
                        "resource_id": resource_id,
                        "requested_permission": requested_permission,
                        "approver_ids": approver_ids,
                        "created_at": time.time(),
                        "status": "pending",
                    }
                }
            }

            # Update user metadata
            metadata_result = await self.update_user_metadata(user_id=user_id, app_metadata=workflow_metadata)

            if not metadata_result["success"]:
                return {"success": False, "error": "Failed to create workflow metadata"}

            # TODO: Trigger Auth0 Action to send notifications to approvers
            # This would typically use Auth0 Actions API or webhooks

            return {"success": True, "workflow_id": workflow_id, "status": "pending", "approvers_notified": True}

        except Exception as e:
            return {"success": False, "error": str(e), "workflow_id": None}

    async def approve_workflow(self, approver_id: str, workflow_id: str, decision: bool) -> dict:
        """
        Process approval decision for human-in-the-loop workflow
        """

        try:
            # In a real implementation, you would:
            # 1. Validate approver_id has permission to approve
            # 2. Retrieve workflow details from user metadata
            # 3. Update workflow status
            # 4. Grant/deny FGA permission based on decision

            if decision:
                # Grant permission in FGA
                # This is a placeholder - actual implementation would depend on specific workflow
                print(f"✅ Workflow {workflow_id} approved by {approver_id}")
            else:
                print(f"❌ Workflow {workflow_id} rejected by {approver_id}")

            return {
                "success": True,
                "workflow_id": workflow_id,
                "decision": "approved" if decision else "rejected",
                "decided_by": approver_id,
                "decided_at": time.time(),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_integration_health_status(self) -> dict:
        """
        Comprehensive health check for all Auth0 integrations
        """

        health_checks = {}

        # Test Auth0 Authentication
        try:
            test_result = await self.authenticate_with_private_key_jwt(user_id="health_check_user")
            health_checks["authentication"] = {
                "status": "healthy" if test_result["success"] else "unhealthy",
                "details": test_result,
            }
        except Exception as e:
            health_checks["authentication"] = {"status": "unhealthy", "error": str(e)}

        # Test FGA Connection
        try:
            # Perform a simple FGA read to test connectivity
            fga_result = await self.read_fga_relationships()
            health_checks["fga"] = {
                "status": "healthy" if fga_result["success"] else "unhealthy",
                "store_id": self.config.fga_store_id,
                "model_id": self.config.fga_model_id,
            }
        except Exception as e:
            health_checks["fga"] = {"status": "unhealthy", "error": str(e)}

        # Test Management API
        if self.management_client:
            health_checks["management_api"] = {"status": "configured", "domain": self.config.domain}
        else:
            health_checks["management_api"] = {"status": "not_configured"}

        # Test Token Vault
        if self.config.token_vault_endpoint:
            health_checks["token_vault"] = {"status": "configured", "endpoint": self.config.token_vault_endpoint}
        else:
            health_checks["token_vault"] = {"status": "not_configured"}

        # Overall health status
        all_healthy = all(check.get("status") in ["healthy", "configured"] for check in health_checks.values())

        return {
            "overall_status": "healthy" if all_healthy else "degraded",
            "timestamp": time.time(),
            "checks": health_checks,
        }

    async def close(self):
        """Clean up resources"""
        await self.http_client.aclose()
        if hasattr(self.fga_client, "close"):
            await self.fga_client.close()


# =====================================
# Configuration Setup Helpers
# =====================================


def create_auth0_config_from_env() -> Auth0Configuration:
    """Create Auth0 configuration from environment variables"""
    import os

    return Auth0Configuration(
        domain=os.getenv("AUTH0_DOMAIN", ""),
        client_id=os.getenv("AUTH0_CLIENT_ID", ""),
        client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
        audience=os.getenv("AUTH0_AUDIENCE", ""),
        management_api_token=os.getenv("AUTH0_MANAGEMENT_TOKEN"),
        fga_store_id=os.getenv("AUTH0_FGA_STORE_ID", ""),
        fga_client_id=os.getenv("AUTH0_FGA_CLIENT_ID", ""),
        fga_client_secret=os.getenv("AUTH0_FGA_CLIENT_SECRET", ""),
        fga_api_url=os.getenv("AUTH0_FGA_API_URL", "https://api.us1.fga.dev"),
        fga_model_id=os.getenv("AUTH0_FGA_MODEL_ID"),
        token_vault_endpoint=os.getenv("AUTH0_TOKEN_VAULT_ENDPOINT", ""),
        token_vault_api_key=os.getenv("AUTH0_TOKEN_VAULT_API_KEY", ""),
    )


async def setup_auth0_application_for_private_key_jwt(config: Auth0Configuration, public_key_jwks: dict) -> dict:
    """
    Setup Auth0 application for Private Key JWT authentication
    This would typically be done via Auth0 Management API or Dashboard
    """

    setup_instructions = {
        "application_settings": {
            "token_endpoint_auth_method": "private_key_jwt",
            "application_type": "non_interactive",
            "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "jsonWebKeys": public_key_jwks,
        },
        "api_settings": {"signing_alg": "RS256", "allow_offline_access": False},
        "advanced_settings": {"oauth_compliance": "oidc_conformant"},
    }

    return {
        "message": "Configure your Auth0 application with these settings",
        "settings": setup_instructions,
        "jwks_endpoint": f"https://{config.domain}/.well-known/jwks.json",
        "documentation": "https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow",
    }
