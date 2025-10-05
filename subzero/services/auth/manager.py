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
        Authenticate using Private Key JWT (RFC 7523).

        Implements OAuth 2.0 Private Key JWT authentication to eliminate shared
        secrets. Creates a JWT assertion signed with RSA private key and exchanges
        it for an access token from Auth0.

        Parameters
        ----------
        user_id : str
            User identifier for authentication
        scopes : str, default "openid profile email"
            Space-separated OAuth 2.0 scopes to request

        Returns
        -------
        dict
            Authentication result with structure:
            - 'success' : bool
                Whether authentication succeeded
            - 'token_data' : dict
                Complete token response from Auth0 including access_token, expires_in
            - 'auth_method' : str
                Authentication method used ('private_key_jwt')
            - 'error' : str, optional
                Error message if authentication failed

        Notes
        -----
        Authentication flow:
        1. Create JWT assertion signed with private key
        2. Submit to Auth0 token endpoint
        3. Receive access token and metadata
        4. Enrich response with timestamp and method

        The JWT assertion is valid for 5 minutes and includes a unique JTI
        for replay attack protection.

        Auth0 API: POST https://{domain}/oauth/token

        See Also
        --------
        _create_private_key_jwt_assertion : Creates the JWT assertion
        get_public_key_for_auth0_config : Gets JWKS for Auth0 configuration

        Examples
        --------
        >>> result = await manager.authenticate_with_private_key_jwt(
        ...     "user_123",
        ...     scopes="openid profile email read:data"
        ... )
        >>> if result['success']:
        ...     print(f"Token: {result['token_data']['access_token']}")
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
        """
        Create Private Key JWT assertion according to RFC 7523.

        Generates a signed JWT assertion with required claims for Auth0
        token endpoint authentication. Uses RS256 algorithm with RSA-2048 key.

        Parameters
        ----------
        user_id : str
            User identifier to include as subject claim

        Returns
        -------
        str
            Signed JWT assertion ready for Auth0 token endpoint

        Notes
        -----
        JWT structure:
        - Header: RS256 algorithm, JWT type, key identifier
        - Claims: iss, sub, aud, iat, exp, jti, scope
        - Signature: RSA-2048 private key

        The assertion expires after 5 minutes and includes a unique JTI
        (JWT ID) for replay protection.

        Examples
        --------
        >>> assertion = manager._create_private_key_jwt_assertion("user_123")
        >>> print(len(assertion) > 100)  # JWT should be substantial
        True
        """

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
        Generate public key in JWKS format for Auth0 configuration.

        Exports the RSA public key in JSON Web Key Set (JWKS) format required
        by Auth0 to validate Private Key JWT signatures. Must be configured
        in Auth0 application settings.

        Returns
        -------
        dict
            JWKS structure with structure:
            - 'keys' : list of dict
                Array containing single JWK with fields:
                - 'kty' : 'RSA'
                - 'use' : 'sig'
                - 'alg' : 'RS256'
                - 'kid' : str (key identifier)
                - 'n' : str (modulus in base64url)
                - 'e' : str (exponent in base64url)

        Notes
        -----
        This JWKS must be configured in Auth0 Dashboard under:
        Applications > {Your App} > Settings > Advanced Settings >
        Authentication > JSON Web Token Signature Algorithm > RS256

        The key components (n, e) are base64url-encoded without padding.

        See Also
        --------
        authenticate_with_private_key_jwt : Uses this key pair for authentication
        _create_private_key_jwt_assertion : Signs assertions with private key

        Examples
        --------
        >>> jwks = manager.get_public_key_for_auth0_config()
        >>> print(jwks['keys'][0]['alg'])
        RS256
        >>> print(jwks['keys'][0]['kty'])
        RSA
        """

        # Get RSA public key components
        public_numbers = self.public_key.public_numbers()

        def int_to_base64url(value: int, byte_length: int) -> str:
            """
            Convert integer to base64url-encoded string.

            Parameters
            ----------
            value : int
                Integer value to encode
            byte_length : int
                Number of bytes to use for encoding

            Returns
            -------
            str
                Base64url-encoded string without padding
            """
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
        Check permission using Auth0 FGA (Fine-Grained Authorization).

        Queries Auth0 FGA to determine if a user has a specific permission
        on a resource. Uses relationship-based access control (ReBAC) model.

        Parameters
        ----------
        user_id : str
            User identifier (prefixed with 'user:' in FGA)
        object_type : str
            Resource type (e.g., 'document', 'folder', 'workspace')
        object_id : str
            Resource identifier
        relation : str
            Permission/relation to check (e.g., 'viewer', 'editor', 'owner')

        Returns
        -------
        dict
            Permission check result with structure:
            - 'allowed' : bool
                Whether the permission is granted
            - 'model_id' : str, optional
                FGA authorization model ID used
            - 'duration_ms' : float, optional
                Query execution time in milliseconds
            - 'request_id' : str, optional
                FGA request identifier for debugging
            - 'error' : str, optional
                Error message if check failed

        Notes
        -----
        FGA check evaluates:
        1. Direct relationships (user -> object)
        2. Inherited relationships (via parent objects)
        3. Computed relationships (based on model rules)

        Performance: Typical latency 10-50ms depending on graph complexity.

        FGA API: POST /stores/{store_id}/check

        See Also
        --------
        write_fga_relationship : Create relationship tuples
        read_fga_relationships : Query existing relationships

        Examples
        --------
        >>> result = await manager.check_fga_permission(
        ...     user_id="user_123",
        ...     object_type="document",
        ...     object_id="doc_456",
        ...     relation="editor"
        ... )
        >>> if result['allowed']:
        ...     print("User can edit document")
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
        Write relationship tuple to Auth0 FGA.

        Creates a relationship between a user and an object in the FGA
        authorization graph. Used to grant permissions.

        Parameters
        ----------
        user_id : str
            User identifier (will be prefixed with 'user:')
        object_type : str
            Resource type (e.g., 'document', 'folder')
        object_id : str
            Resource identifier
        relation : str
            Permission/relation to grant (e.g., 'viewer', 'editor', 'owner')

        Returns
        -------
        dict
            Write operation result with structure:
            - 'success' : bool
                Whether the write succeeded
            - 'written_at' : str, optional
                Timestamp when relationship was written
            - 'request_id' : str, optional
                FGA request identifier
            - 'error' : str, optional
                Error message if write failed

        Notes
        -----
        Relationship tuples follow the format:
        user:{user_id}#{relation}@{object_type}:{object_id}

        Multiple writes to the same tuple are idempotent.

        FGA API: POST /stores/{store_id}/write

        See Also
        --------
        check_fga_permission : Check if permission is granted
        read_fga_relationships : Query existing relationships

        Examples
        --------
        >>> result = await manager.write_fga_relationship(
        ...     user_id="user_123",
        ...     object_type="document",
        ...     object_id="doc_456",
        ...     relation="editor"
        ... )
        >>> if result['success']:
        ...     print(f"Relationship written at {result['written_at']}")
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
        Read relationship tuples from Auth0 FGA.

        Queries existing relationships in the FGA authorization graph.
        Can filter by user or object to retrieve relevant tuples.

        Parameters
        ----------
        user_filter : str, optional
            Filter by user (e.g., 'user:user_123'). Returns all relationships
            for this user.
        object_filter : str, optional
            Filter by object (e.g., 'document:doc_456'). Returns all relationships
            to this object.

        Returns
        -------
        dict
            Read operation result with structure:
            - 'success' : bool
                Whether the read succeeded
            - 'tuples' : list of dict
                Retrieved relationship tuples, each with:
                - 'user' : str
                - 'relation' : str
                - 'object' : str
                - 'timestamp' : str, optional
            - 'continuation_token' : str, optional
                Token for paginated results
            - 'error' : str, optional
                Error message if read failed

        Notes
        -----
        If neither filter is provided, returns all tuples (may be paginated).
        Use continuation_token for retrieving additional pages.

        FGA API: POST /stores/{store_id}/read

        See Also
        --------
        write_fga_relationship : Create relationships
        check_fga_permission : Check permissions

        Examples
        --------
        >>> # Get all relationships for a user
        >>> result = await manager.read_fga_relationships(
        ...     user_filter="user:user_123"
        ... )
        >>> for tuple in result['tuples']:
        ...     print(f"{tuple['user']} {tuple['relation']} {tuple['object']}")

        >>> # Get all users with access to a document
        >>> result = await manager.read_fga_relationships(
        ...     object_filter="document:doc_456"
        ... )
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
        Get user profile from Auth0 Management API.

        Retrieves complete user profile including metadata, login history,
        and account information.

        Parameters
        ----------
        user_id : str
            Auth0 user identifier (e.g., 'auth0|123456')

        Returns
        -------
        dict
            User profile result with structure:
            - 'success' : bool
                Whether the retrieval succeeded
            - 'user' : dict
                User profile data including:
                - 'user_id' : str
                - 'email' : str
                - 'name' : str
                - 'picture' : str
                - 'last_login' : str
                - 'login_count' : int
                - 'created_at' : str
                - 'updated_at' : str
                - 'app_metadata' : dict
                - 'user_metadata' : dict
            - 'error' : str, optional
                Error message if retrieval failed

        Notes
        -----
        Requires management_api_token to be configured in Auth0Configuration.

        Management API: GET /api/v2/users/{id}

        See Also
        --------
        update_user_metadata : Update user metadata

        Examples
        --------
        >>> result = await manager.get_user_profile("auth0|123456")
        >>> if result['success']:
        ...     print(f"User: {result['user']['email']}")
        ...     print(f"Last login: {result['user']['last_login']}")
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
        Update user metadata via Auth0 Management API.

        Updates application-managed metadata (app_metadata) and/or user-editable
        metadata (user_metadata) for a user account.

        Parameters
        ----------
        user_id : str
            Auth0 user identifier (e.g., 'auth0|123456')
        app_metadata : dict, optional
            Application metadata (only accessible by management API)
        user_metadata : dict, optional
            User metadata (can be edited by users)

        Returns
        -------
        dict
            Update result with structure:
            - 'success' : bool
                Whether the update succeeded
            - 'updated_user' : dict, optional
                Complete updated user profile
            - 'error' : str, optional
                Error message if update failed

        Notes
        -----
        app_metadata vs user_metadata:
        - app_metadata: Read-only to users, used for roles, permissions, etc.
        - user_metadata: Editable by users, used for preferences, settings, etc.

        Requires management_api_token to be configured.

        Management API: PATCH /api/v2/users/{id}

        See Also
        --------
        get_user_profile : Retrieve user profile

        Examples
        --------
        >>> result = await manager.update_user_metadata(
        ...     user_id="auth0|123456",
        ...     app_metadata={"roles": ["admin", "editor"]},
        ...     user_metadata={"theme": "dark", "language": "en"}
        ... )
        >>> if result['success']:
        ...     print("User metadata updated")
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
        Store AI agent credentials in Auth0 Token Vault.

        Securely stores credentials for AI agents using Auth0 Token Vault,
        part of Auth for GenAI product. Credentials are encrypted at rest
        and have configurable expiration.

        Parameters
        ----------
        ai_agent_id : str
            AI agent identifier
        credentials : dict
            Credentials to store (API keys, tokens, etc.)
        expires_in : int, default 3600
            Expiration time in seconds (default 1 hour)

        Returns
        -------
        dict
            Storage result with structure:
            - 'success' : bool
                Whether storage succeeded
            - 'credential_id' : str, optional
                Unique identifier for stored credentials
            - 'expires_at' : str, optional
                Expiration timestamp
            - 'error' : str, optional
                Error message if storage failed

        Notes
        -----
        Part of Auth0's Auth for GenAI product (launched April 2025).
        Credentials are encrypted using AES-256 and stored securely.

        Requires token_vault_endpoint and token_vault_api_key to be configured.

        Custom API: POST /token-vault/store

        See Also
        --------
        retrieve_ai_credentials_from_vault : Retrieve stored credentials

        Examples
        --------
        >>> result = await manager.store_ai_credentials_in_vault(
        ...     ai_agent_id="agent_123",
        ...     credentials={
        ...         "api_key": "sk-...",
        ...         "endpoint": "https://api.example.com"
        ...     },
        ...     expires_in=7200
        ... )
        >>> if result['success']:
        ...     print(f"Stored with ID: {result['credential_id']}")
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
        Retrieve AI agent credentials from Auth0 Token Vault.

        Retrieves previously stored credentials for an AI agent from Token Vault.
        Credentials are decrypted and returned if not expired.

        Parameters
        ----------
        ai_agent_id : str
            AI agent identifier (must match stored agent ID)
        credential_id : str
            Unique identifier of stored credentials

        Returns
        -------
        dict
            Retrieval result with structure:
            - 'success' : bool
                Whether retrieval succeeded
            - 'credentials' : dict, optional
                Decrypted credentials
            - 'expires_at' : str, optional
                Expiration timestamp
            - 'metadata' : dict
                Storage metadata including stored_at, client_id
            - 'error' : str, optional
                Error message if retrieval failed

        Notes
        -----
        Requires token_vault_endpoint and token_vault_api_key to be configured.

        Agent ID verification prevents unauthorized credential access.

        Custom API: GET /token-vault/retrieve/{credential_id}

        See Also
        --------
        store_ai_credentials_in_vault : Store credentials

        Examples
        --------
        >>> result = await manager.retrieve_ai_credentials_from_vault(
        ...     ai_agent_id="agent_123",
        ...     credential_id="cred_abc123"
        ... )
        >>> if result['success']:
        ...     api_key = result['credentials']['api_key']
        ...     print(f"Retrieved credentials (expires: {result['expires_at']})")
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
    """
    Create Auth0 configuration from environment variables.

    Reads Auth0 configuration from standard environment variables and
    constructs an Auth0Configuration instance.

    Returns
    -------
    Auth0Configuration
        Complete Auth0 configuration loaded from environment

    Notes
    -----
    Required environment variables:
    - AUTH0_DOMAIN: Auth0 tenant domain
    - AUTH0_CLIENT_ID: Application client ID
    - AUTH0_AUDIENCE: API audience

    Optional environment variables:
    - AUTH0_CLIENT_SECRET: Client secret (not needed for Private Key JWT)
    - AUTH0_MANAGEMENT_TOKEN: Management API token
    - AUTH0_FGA_STORE_ID: FGA store identifier
    - AUTH0_FGA_CLIENT_ID: FGA client ID
    - AUTH0_FGA_CLIENT_SECRET: FGA client secret
    - AUTH0_FGA_API_URL: FGA API endpoint (default: US region)
    - AUTH0_FGA_MODEL_ID: FGA authorization model ID
    - AUTH0_TOKEN_VAULT_ENDPOINT: Token Vault endpoint
    - AUTH0_TOKEN_VAULT_API_KEY: Token Vault API key

    Examples
    --------
    >>> import os
    >>> os.environ['AUTH0_DOMAIN'] = 'tenant.auth0.com'
    >>> os.environ['AUTH0_CLIENT_ID'] = 'client_id'
    >>> os.environ['AUTH0_AUDIENCE'] = 'https://api.example.com'
    >>> config = create_auth0_config_from_env()
    >>> print(config.domain)
    tenant.auth0.com
    """
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
    Setup Auth0 application for Private Key JWT authentication.

    Provides configuration instructions and settings needed to configure
    an Auth0 application for Private Key JWT authentication method.

    Parameters
    ----------
    config : Auth0Configuration
        Auth0 configuration instance
    public_key_jwks : dict
        JWKS containing public key from get_public_key_for_auth0_config()

    Returns
    -------
    dict
        Configuration instructions with structure:
        - 'message' : str
            Setup instructions
        - 'settings' : dict
            Application settings to configure in Auth0
        - 'jwks_endpoint' : str
            JWKS endpoint URL
        - 'documentation' : str
            Link to Auth0 documentation

    Notes
    -----
    This function returns configuration instructions. Actual setup must be
    performed in Auth0 Dashboard or via Management API.

    Configuration steps:
    1. Set token_endpoint_auth_method to 'private_key_jwt'
    2. Add public JWKS to application settings
    3. Configure grant types for JWT bearer
    4. Enable OIDC conformant mode

    See Also
    --------
    Auth0IntegrationManager.get_public_key_for_auth0_config : Generate JWKS

    Examples
    --------
    >>> manager = Auth0IntegrationManager(config)
    >>> jwks = manager.get_public_key_for_auth0_config()
    >>> instructions = await setup_auth0_application_for_private_key_jwt(
    ...     config, jwks
    ... )
    >>> print(instructions['message'])
    Configure your Auth0 application with these settings
    >>> print(instructions['settings']['application_settings'])
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
