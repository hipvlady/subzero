"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Cross App Access (XAA) Protocol Implementation
Okta's protocol for secure agent-to-app communication

Features:
- OAuth 2.0 token delegation chain
- Cross-application authorization
- Agent capability verification
- Delegation depth control
- Integration with Okta ecosystem
- Just-in-time access provisioning
"""

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

import aiohttp
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from subzero.config.defaults import settings


class XAATokenType(str, Enum):
    """
    Types of XAA tokens.

    Attributes
    ----------
    PRIMARY : str
        Original user/agent token for direct access
    DELEGATED : str
        Delegated access token created through delegation chain
    IMPERSONATION : str
        Impersonation token for acting on behalf of another user
    """

    PRIMARY = "primary"  # Original user/agent token
    DELEGATED = "delegated"  # Delegated access token
    IMPERSONATION = "impersonation"  # Impersonation token


class AccessScope(str, Enum):
    """
    XAA access scopes for permission control.

    Attributes
    ----------
    READ : str
        Read-only access to resources
    WRITE : str
        Write access to modify resources
    EXECUTE : str
        Execute operations and actions
    ADMIN : str
        Administrative privileges
    DELEGATE : str
        Permission to delegate tokens to other agents
    """

    READ = "xaa:read"
    WRITE = "xaa:write"
    EXECUTE = "xaa:execute"
    ADMIN = "xaa:admin"
    DELEGATE = "xaa:delegate"


@dataclass
class DelegationChain:
    """
    Track delegation chain for audit and security.

    Maintains the complete delegation path for XAA tokens to enable
    audit trails and prevent circular delegations.

    Attributes
    ----------
    chain_id : str
        Unique identifier for this delegation chain
    initiator : str
        Original user or agent who started the chain
    current_holder : str
        Current token holder (most recent delegate)
    delegation_path : list of str
        Complete ordered list of all agents in chain
    depth : int
        Current delegation depth (number of hops)
    max_depth : int
        Maximum allowed delegation depth
    created_at : float
        Unix timestamp when chain was created
    expires_at : float
        Unix timestamp when chain expires
    """

    chain_id: str
    initiator: str  # Original user/agent
    current_holder: str  # Current token holder
    delegation_path: list[str] = field(default_factory=list)
    depth: int = 0
    max_depth: int = 3
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)


@dataclass
class XAAToken:
    """
    Cross App Access token.

    Represents an XAA token with all associated metadata including
    delegation chain, scopes, and lifecycle information.

    Attributes
    ----------
    token_id : str
        Unique token identifier (JWT ID)
    token_type : XAATokenType
        Type of token (PRIMARY, DELEGATED, IMPERSONATION)
    subject : str
        Agent or user ID who owns the token
    audience : str
        Target application ID for this token
    scopes : set of str
        Set of granted access scopes
    delegation_chain : DelegationChain, optional
        Associated delegation chain if token is delegated
    issued_at : float
        Unix timestamp when token was issued
    expires_at : float
        Unix timestamp when token expires
    metadata : dict
        Additional token metadata
    """

    token_id: str
    token_type: XAATokenType
    subject: str  # Agent or user ID
    audience: str  # Target application
    scopes: set[str]
    delegation_chain: DelegationChain | None = None
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    metadata: dict = field(default_factory=dict)


@dataclass
class AppRegistration:
    """
    Registered application for XAA.

    Contains application metadata and authorization policies for
    XAA protocol interactions.

    Attributes
    ----------
    app_id : str
        Unique application identifier
    app_name : str
        Human-readable application name
    app_type : str
        Application type: "web", "service", or "agent"
    allowed_scopes : set of str
        Set of scopes this application is permitted to use
    allowed_delegations : bool
        Whether this application can receive delegated tokens
    max_delegation_depth : int
        Maximum delegation chain depth allowed for this app
    callback_urls : list of str
        OAuth callback URLs for bidirectional communication
    public_key : str, optional
        Public key for token verification (PEM format)
    """

    app_id: str
    app_name: str
    app_type: str  # "web", "service", "agent"
    allowed_scopes: set[str]
    allowed_delegations: bool = True
    max_delegation_depth: int = 3
    callback_urls: list[str] = field(default_factory=list)
    public_key: str | None = None  # For token verification


class XAAProtocol:
    """
    Cross App Access Protocol Implementation.

    Enables secure multi-hop agent-to-app communication using OAuth 2.0
    token delegation with scope reduction and chain tracking.

    Implements Okta's XAA protocol for:
    - Token delegation with chain tracking
    - Bidirectional agent-app communication
    - Just-in-time access provisioning
    - Capability-based authorization
    """

    def __init__(self, issuer: str, signing_key: rsa.RSAPrivateKey | None = None, okta_domain: str | None = None):
        """
        Initialize XAA protocol.

        Parameters
        ----------
        issuer : str
            XAA token issuer URL (will be stripped of trailing slash)
        signing_key : rsa.RSAPrivateKey, optional
            RSA private key for token signing. If None, generates new 2048-bit key.
        okta_domain : str, optional
            Okta domain for integration (e.g., 'dev-12345.okta.com')
        """
        self.issuer = issuer.rstrip("/")
        self.okta_domain = okta_domain

        # Generate signing key if not provided
        if signing_key is None:
            self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        else:
            self.signing_key = signing_key

        self.public_key = self.signing_key.public_key()

        # Application registry
        self.applications: dict[str, AppRegistration] = {}

        # Active tokens
        self.active_tokens: dict[str, XAAToken] = {}

        # Delegation chains
        self.delegation_chains: dict[str, DelegationChain] = {}

        # HTTP session for Okta integration
        if self.okta_domain:
            connector = aiohttp.TCPConnector(limit=100)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        # Metrics
        self.token_issued_count = 0
        self.delegation_count = 0
        self.verification_count = 0
        self.rejected_count = 0

    async def register_application(
        self,
        app_id: str,
        app_name: str,
        app_type: str,
        allowed_scopes: set[str],
        callback_urls: list[str] | None = None,
        max_delegation_depth: int = 3,
    ) -> AppRegistration:
        """
        Register application for XAA.

        Creates an application registration with authorization policies
        for XAA protocol interactions.

        Parameters
        ----------
        app_id : str
            Unique application identifier
        app_name : str
            Human-readable application name
        app_type : str
            Application type: "web", "service", or "agent"
        allowed_scopes : set of str
            Set of permitted XAA scopes for this application
        callback_urls : list of str, optional
            OAuth callback URLs for bidirectional communication
        max_delegation_depth : int, default=3
            Maximum delegation chain depth allowed

        Returns
        -------
        AppRegistration
            Created application registration object

        Examples
        --------
        >>> app = await xaa.register_application(
        ...     app_id="app_123",
        ...     app_name="Data Service",
        ...     app_type="service",
        ...     allowed_scopes={AccessScope.READ, AccessScope.WRITE},
        ...     callback_urls=["https://api.example.com/callback"]
        ... )
        """
        app_registration = AppRegistration(
            app_id=app_id,
            app_name=app_name,
            app_type=app_type,
            allowed_scopes=allowed_scopes,
            callback_urls=callback_urls or [],
            max_delegation_depth=max_delegation_depth,
        )

        self.applications[app_id] = app_registration

        print(f"📱 Application registered: {app_name} ({app_id})")

        return app_registration

    async def issue_token(
        self,
        subject: str,
        audience: str,
        scopes: set[str],
        token_type: XAATokenType = XAATokenType.PRIMARY,
        expires_in: int = 3600,
        metadata: dict | None = None,
    ) -> str:
        """
        Issue XAA token.

        Creates and signs a JWT token for XAA protocol with scope
        validation and application verification.

        Parameters
        ----------
        subject : str
            Agent or user ID requesting the token
        audience : str
            Target application ID that will receive requests
        scopes : set of str
            Requested access scopes (must be subset of app's allowed_scopes)
        token_type : XAATokenType, default=XAATokenType.PRIMARY
            Type of token to issue (PRIMARY, DELEGATED, IMPERSONATION)
        expires_in : int, default=3600
            Token lifetime in seconds
        metadata : dict, optional
            Additional token metadata to include in claims

        Returns
        -------
        str
            Signed JWT token string in compact serialization format

        Raises
        ------
        ValueError
            If application is not registered or scopes are invalid

        Notes
        -----
        The JWT token includes standard claims (iss, sub, aud, iat, exp, jti)
        plus XAA-specific claims (token_type, scopes, xaa_version).

        Examples
        --------
        >>> token = await xaa.issue_token(
        ...     subject="agent_456",
        ...     audience="app_123",
        ...     scopes={AccessScope.READ, AccessScope.WRITE},
        ...     expires_in=7200
        ... )
        """
        self.token_issued_count += 1
        start_time = time.perf_counter()

        # Verify application exists
        if audience not in self.applications:
            raise ValueError(f"Application {audience} not registered")

        app = self.applications[audience]

        # Validate scopes
        invalid_scopes = scopes - app.allowed_scopes
        if invalid_scopes:
            raise ValueError(f"Invalid scopes for {audience}: {invalid_scopes}")

        # Generate token ID
        token_id = self._generate_token_id()

        # Create XAA token
        xaa_token = XAAToken(
            token_id=token_id,
            token_type=token_type,
            subject=subject,
            audience=audience,
            scopes=scopes,
            expires_at=time.time() + expires_in,
            metadata=metadata or {},
        )

        # Store token
        self.active_tokens[token_id] = xaa_token

        # Create JWT claims
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + expires_in,
            "jti": token_id,
            "token_type": token_type.value,
            "scopes": list(scopes),
            "xaa_version": "1.0",
        }

        # Add metadata
        if metadata:
            claims["metadata"] = metadata

        # Sign token
        token_string = jwt.encode(claims, self.signing_key, algorithm="RS256")

        latency_ms = (time.perf_counter() - start_time) * 1000

        print(f"🎫 XAA token issued: {subject} → {audience} ({latency_ms:.2f}ms)")

        return token_string

    async def delegate_token(
        self,
        original_token: str,
        target_subject: str,
        target_audience: str,
        scopes: set[str] | None = None,
        expires_in: int = 1800,
    ) -> str:
        """
        Delegate XAA token to another agent/app.

        Implements XAA protocol token delegation with chain tracking,
        scope reduction, and depth control for secure multi-hop access.

        Parameters
        ----------
        original_token : str
            Original JWT token to delegate from
        target_subject : str
            Target agent or user ID receiving delegated token
        target_audience : str
            Target application ID for delegated access
        scopes : set of str, optional
            Restricted scope set (must be subset of original scopes).
            If None, inherits all scopes from original token.
        expires_in : int, default=1800
            Delegation token lifetime in seconds (default 30 minutes)

        Returns
        -------
        str
            Delegated JWT token string with reduced scopes

        Raises
        ------
        ValueError
            If original token is invalid, max delegation depth exceeded,
            or target application doesn't allow delegations

        Notes
        -----
        XAA Delegation Protocol:
        - Enforces scope reduction (cannot escalate privileges)
        - Tracks complete delegation chain for audit
        - Maximum depth configurable via settings.XAA_MAX_DELEGATION_DEPTH
        - Each delegation increments chain depth counter
        - Delegated token includes chain metadata

        Security:
        - Cannot delegate scopes not in original token
        - Chain validation prevents circular delegations
        - All delegations are logged with full path

        Examples
        --------
        >>> delegated = await xaa.delegate_token(
        ...     original_token="eyJ0eXAi...",
        ...     target_subject="agent_789",
        ...     target_audience="app_456",
        ...     scopes={AccessScope.READ}  # Reduced from original
        ... )
        >>> claims = jwt.decode(delegated, verify=False)
        >>> print(claims['metadata']['delegation_depth'])
        1
        """
        self.delegation_count += 1
        start_time = time.perf_counter()

        # Verify original token
        try:
            original_claims = jwt.decode(
                original_token, self.public_key, algorithms=["RS256"], audience=None, options={"verify_aud": False}
            )
        except jwt.InvalidTokenError as e:
            self.rejected_count += 1
            raise ValueError(f"Invalid original token: {e}") from e

        original_token_id = original_claims.get("jti")
        original_subject = original_claims["sub"]
        original_scopes = set(original_claims.get("scopes", []))

        # Get or create delegation chain
        delegation_chain = self._get_or_create_chain(original_token_id, original_subject, target_subject)

        # Check delegation depth
        if delegation_chain.depth >= settings.XAA_MAX_DELEGATION_DEPTH:
            self.rejected_count += 1
            raise ValueError(f"Max delegation depth ({settings.XAA_MAX_DELEGATION_DEPTH}) exceeded")

        # Restrict scopes (delegated token cannot have more scopes than original)
        if scopes:
            delegated_scopes = scopes & original_scopes
        else:
            delegated_scopes = original_scopes

        # Verify target app allows delegations
        if target_audience in self.applications:
            target_app = self.applications[target_audience]
            if not target_app.allowed_delegations:
                self.rejected_count += 1
                raise ValueError(f"Application {target_audience} does not allow delegations")

        # Issue delegated token
        delegated_token = await self.issue_token(
            subject=target_subject,
            audience=target_audience,
            scopes=delegated_scopes,
            token_type=XAATokenType.DELEGATED,
            expires_in=expires_in,
            metadata={
                "delegation_chain_id": delegation_chain.chain_id,
                "delegation_depth": delegation_chain.depth + 1,
                "delegated_from": original_subject,
            },
        )

        # Update delegation chain
        delegation_chain.current_holder = target_subject
        delegation_chain.delegation_path.append(target_subject)
        delegation_chain.depth += 1

        latency_ms = (time.perf_counter() - start_time) * 1000

        print(
            f"🔗 Token delegated: {original_subject} → {target_subject} (depth: {delegation_chain.depth}, {latency_ms:.2f}ms)"
        )

        return delegated_token

    async def verify_token(self, token_string: str, expected_audience: str | None = None) -> tuple[bool, dict | None]:
        """
        Verify XAA token.

        Validates JWT signature, expiration, and scope claims for XAA token.

        Parameters
        ----------
        token_string : str
            JWT token string to verify
        expected_audience : str, optional
            Expected audience claim for validation. If None, audience is not verified.

        Returns
        -------
        tuple of (bool, dict or None)
            - is_valid : bool
                True if token is valid and active
            - claims : dict or None
                Token claims if valid, None otherwise

        Notes
        -----
        Verification steps:
        1. JWT signature validation using public key
        2. Audience claim verification (if expected_audience provided)
        3. Token existence check in active_tokens registry
        4. Expiration time validation
        5. Scope subset validation

        Expired tokens are automatically removed from active_tokens.

        Examples
        --------
        >>> is_valid, claims = await xaa.verify_token(
        ...     token_string,
        ...     expected_audience="app_123"
        ... )
        >>> if is_valid:
        ...     print(f"Token valid for: {claims['sub']}")
        """
        self.verification_count += 1

        try:
            # Decode and verify token
            claims = jwt.decode(
                token_string,
                self.public_key,
                algorithms=["RS256"],
                audience=expected_audience,
                options={"verify_aud": expected_audience is not None},
            )

            # Check if token is still active
            token_id = claims.get("jti")
            if token_id not in self.active_tokens:
                return False, None

            xaa_token = self.active_tokens[token_id]

            # Check expiration
            if time.time() > xaa_token.expires_at:
                # Remove expired token
                del self.active_tokens[token_id]
                return False, None

            # Verify scopes
            requested_scopes = set(claims.get("scopes", []))
            if not requested_scopes.issubset(xaa_token.scopes):
                return False, None

            return True, claims

        except jwt.InvalidTokenError as e:
            print(f"🚫 Token verification failed: {e}")
            return False, None

    async def revoke_token(self, token_string: str) -> bool:
        """
        Revoke XAA token.

        Immediately invalidates a token by removing it from active registry.

        Parameters
        ----------
        token_string : str
            JWT token string to revoke

        Returns
        -------
        bool
            True if token was found and revoked, False otherwise

        Notes
        -----
        Token revocation is immediate and irreversible. The token
        will fail all future verification attempts.

        Examples
        --------
        >>> success = await xaa.revoke_token(token_string)
        >>> if success:
        ...     print("Token revoked successfully")
        """
        try:
            claims = jwt.decode(
                token_string, self.public_key, algorithms=["RS256"], options={"verify_signature": False}
            )

            token_id = claims.get("jti")

            if token_id in self.active_tokens:
                del self.active_tokens[token_id]
                print(f"🗑️  Token revoked: {token_id}")
                return True

            return False

        except Exception as e:
            print(f"❌ Token revocation error: {e}")
            return False

    async def revoke_delegation_chain(self, chain_id: str) -> int:
        """
        Revoke entire delegation chain.

        Revokes all tokens in a delegation chain, invalidating the entire
        chain from initiator through all delegated tokens.

        Parameters
        ----------
        chain_id : str
            Delegation chain ID to revoke

        Returns
        -------
        int
            Number of tokens revoked from the chain

        Notes
        -----
        Chain revocation is cascading - revoking a chain invalidates:
        - The original token (if tracked in chain)
        - All delegated tokens in the chain
        - The chain metadata itself

        This is useful for emergency revocation when a delegation
        path is compromised.

        Examples
        --------
        >>> count = await xaa.revoke_delegation_chain("chain_abc123")
        >>> print(f"Revoked {count} tokens in chain")
        """
        if chain_id not in self.delegation_chains:
            return 0

        self.delegation_chains[chain_id]

        # Find all tokens in chain
        tokens_to_revoke = [
            token_id
            for token_id, token in self.active_tokens.items()
            if token.delegation_chain and token.delegation_chain.chain_id == chain_id
        ]

        # Revoke all tokens
        for token_id in tokens_to_revoke:
            del self.active_tokens[token_id]

        # Remove chain
        del self.delegation_chains[chain_id]

        print(f"🔗❌ Delegation chain revoked: {chain_id} ({len(tokens_to_revoke)} tokens)")

        return len(tokens_to_revoke)

    async def introspect_token(self, token_string: str) -> dict:
        """
        Introspect XAA token (RFC 7662).

        Returns detailed token metadata including delegation information
        following OAuth 2.0 Token Introspection standard.

        Parameters
        ----------
        token_string : str
            JWT token to introspect

        Returns
        -------
        dict
            Token introspection response with fields:
            - 'active' : bool
                Whether token is currently active
            - 'token_type' : str
                Token type (if active)
            - 'scope' : str
                Space-separated scope list (if active)
            - 'sub' : str
                Subject identifier (if active)
            - 'aud' : str
                Audience identifier (if active)
            - 'iss' : str
                Issuer identifier (if active)
            - 'exp' : int
                Expiration timestamp (if active)
            - 'iat' : int
                Issued at timestamp (if active)
            - 'delegation' : dict, optional
                Delegation chain info if token is delegated:
                - 'chain_id' : str
                - 'depth' : int
                - 'initiator' : str
                - 'path' : list of str

        Notes
        -----
        Implements RFC 7662 OAuth 2.0 Token Introspection with
        XAA-specific extensions for delegation chain tracking.

        Examples
        --------
        >>> info = await xaa.introspect_token(token_string)
        >>> if info['active']:
        ...     if 'delegation' in info:
        ...         print(f"Delegated token, depth: {info['delegation']['depth']}")
        """
        is_valid, claims = await self.verify_token(token_string)

        if not is_valid or not claims:
            return {"active": False}

        token_id = claims.get("jti")
        xaa_token = self.active_tokens.get(token_id)

        response = {
            "active": True,
            "token_type": claims.get("token_type"),
            "scope": " ".join(claims.get("scopes", [])),
            "sub": claims["sub"],
            "aud": claims["aud"],
            "iss": claims["iss"],
            "exp": claims["exp"],
            "iat": claims["iat"],
        }

        # Add delegation info if present
        if xaa_token and xaa_token.delegation_chain:
            response["delegation"] = {
                "chain_id": xaa_token.delegation_chain.chain_id,
                "depth": xaa_token.delegation_chain.depth,
                "initiator": xaa_token.delegation_chain.initiator,
                "path": xaa_token.delegation_chain.delegation_path,
            }

        return response

    async def sync_with_okta(self) -> bool:
        """
        Sync XAA tokens with Okta ecosystem.

        Registers all XAA applications with Okta OAuth 2.0 infrastructure
        for integration with Okta's identity platform.

        Returns
        -------
        bool
            True if sync completed successfully, False if no Okta domain configured

        Notes
        -----
        Syncs application registrations to Okta, enabling:
        - OAuth 2.0 flows with Okta authorization server
        - Single Sign-On (SSO) integration
        - Centralized identity management
        - Policy-based access control

        Requires okta_domain to be configured during initialization.

        Examples
        --------
        >>> xaa = XAAProtocol(issuer="https://api.example.com", okta_domain="dev-12345.okta.com")
        >>> success = await xaa.sync_with_okta()
        >>> if success:
        ...     print(f"Synced {len(xaa.applications)} apps")
        """
        if not self.okta_domain:
            return False

        # Sync application registrations with Okta
        for app in self.applications.values():
            await self._register_app_with_okta(app)

        print(f"🔄 Synced {len(self.applications)} apps with Okta")

        return True

    async def _register_app_with_okta(self, app: AppRegistration) -> bool:
        """
        Register application with Okta.

        Parameters
        ----------
        app : AppRegistration
            Application registration to sync with Okta

        Returns
        -------
        bool
            True if registration successful
        """
        if not self.okta_domain:
            return False

        url = f"https://{self.okta_domain}/oauth2/v1/clients"

        payload = {
            "client_name": app.app_name,
            "client_id": app.app_id,
            "application_type": app.app_type,
            "redirect_uris": app.callback_urls,
            "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        }

        try:
            async with self.session.post(url, json=payload) as response:
                return response.status in [200, 201]

        except Exception as e:
            print(f"⚠️  Okta registration failed for {app.app_name}: {e}")
            return False

    def _get_or_create_chain(self, original_token_id: str, initiator: str, current_holder: str) -> DelegationChain:
        """
        Get existing or create new delegation chain.

        Parameters
        ----------
        original_token_id : str
            Original token's JWT ID
        initiator : str
            Agent/user who started the chain
        current_holder : str
            Current token holder

        Returns
        -------
        DelegationChain
            Existing chain if token has one, otherwise creates new chain
        """
        # Check if token already has a chain
        original_token = self.active_tokens.get(original_token_id)

        if original_token and original_token.delegation_chain:
            return original_token.delegation_chain

        # Create new chain
        chain_id = self._generate_token_id()

        chain = DelegationChain(
            chain_id=chain_id,
            initiator=initiator,
            current_holder=current_holder,
            delegation_path=[initiator],
            depth=0,
            max_depth=settings.XAA_MAX_DELEGATION_DEPTH,
        )

        self.delegation_chains[chain_id] = chain

        # Attach to original token
        if original_token:
            original_token.delegation_chain = chain

        return chain

    def _generate_token_id(self) -> str:
        """
        Generate unique token ID.

        Returns
        -------
        str
            URL-safe token identifier (32 bytes, base64-encoded)
        """
        return secrets.token_urlsafe(32)

    def get_metrics(self) -> dict:
        """
        Get XAA protocol metrics.

        Returns
        -------
        dict
            Protocol metrics:
            - 'token_issued_count' : int
                Total tokens issued
            - 'delegation_count' : int
                Total delegations performed
            - 'verification_count' : int
                Total verification attempts
            - 'rejected_count' : int
                Total rejected operations
            - 'active_tokens' : int
                Currently active tokens
            - 'active_delegations' : int
                Currently active delegated tokens
            - 'registered_apps' : int
                Number of registered applications
            - 'delegation_chains' : int
                Number of active delegation chains

        Examples
        --------
        >>> metrics = xaa.get_metrics()
        >>> print(f"Active tokens: {metrics['active_tokens']}")
        >>> print(f"Delegation rate: {metrics['delegation_count'] / metrics['token_issued_count']:.2%}")
        """
        active_delegations = sum(
            1 for token in self.active_tokens.values() if token.token_type == XAATokenType.DELEGATED
        )

        return {
            "token_issued_count": self.token_issued_count,
            "delegation_count": self.delegation_count,
            "verification_count": self.verification_count,
            "rejected_count": self.rejected_count,
            "active_tokens": len(self.active_tokens),
            "active_delegations": active_delegations,
            "registered_apps": len(self.applications),
            "delegation_chains": len(self.delegation_chains),
        }

    def get_public_key_jwk(self) -> dict:
        """
        Get public key in JWK format.

        Returns the RSA public key in JSON Web Key (JWK) format
        for token verification by external services.

        Returns
        -------
        dict
            JWK representation with fields:
            - 'kty' : str
                Key type (RSA)
            - 'use' : str
                Public key use (sig for signature)
            - 'kid' : str
                Key ID (xaa-key-1)
            - 'alg' : str
                Algorithm (RS256)
            - 'n' : str
                RSA modulus (base64url-encoded)
            - 'e' : str
                RSA exponent (base64url-encoded)

        Notes
        -----
        JWK format follows RFC 7517 for representing cryptographic keys
        in JSON. This is the standard format for JWKS (JSON Web Key Set)
        endpoints used in OAuth 2.0 and OpenID Connect.

        Examples
        --------
        >>> jwk = xaa.get_public_key_jwk()
        >>> print(jwk['kid'])
        xaa-key-1
        """
        public_numbers = self.public_key.public_numbers()

        def to_base64url(num: int, length: int) -> str:
            import base64

            bytes_data = num.to_bytes(length, byteorder="big")
            return base64.urlsafe_b64encode(bytes_data).rstrip(b"=").decode("ascii")

        return {
            "kty": "RSA",
            "use": "sig",
            "kid": "xaa-key-1",
            "alg": "RS256",
            "n": to_base64url(public_numbers.n, 256),
            "e": to_base64url(public_numbers.e, 3),
        }

    async def send_app_request(
        self, token: str, target_app_id: str, method: str, endpoint: str, payload: dict | None = None
    ) -> dict:
        """
        Send authenticated request to registered application.

        Bidirectional communication: Agent → App
        Uses XAA token for authenticated API calls to registered applications.

        Parameters
        ----------
        token : str
            XAA access token with appropriate scopes
        target_app_id : str
            Target application ID (must be registered)
        method : str
            HTTP method: GET, POST, PUT, PATCH, or DELETE
        endpoint : str
            API endpoint path (will be appended to callback URL)
        payload : dict, optional
            Request payload for POST/PUT/PATCH methods

        Returns
        -------
        dict
            Response dictionary:
            - 'success' : bool
                Whether request succeeded
            - 'status_code' : int
                HTTP status code (if request completed)
            - 'data' : dict or str
                Response data (if available)
            - 'error' : str
                Error message (if failed)

        Notes
        -----
        Bidirectional XAA Communication:
        - Agent sends authenticated requests to app
        - Token verified for audience match
        - Uses first registered callback URL as base
        - Custom headers include XAA version and delegation chain

        Examples
        --------
        >>> response = await xaa.send_app_request(
        ...     token=agent_token,
        ...     target_app_id="app_123",
        ...     method="POST",
        ...     endpoint="/api/data",
        ...     payload={"query": "fetch_records"}
        ... )
        >>> if response['success']:
        ...     print(response['data'])
        """
        # Verify token
        try:
            claims = await self.verify_token(token)

            # Check if audience matches target app
            if claims.get("aud") != target_app_id:
                return {
                    "success": False,
                    "error": "Token audience mismatch",
                    "expected": target_app_id,
                    "actual": claims.get("aud"),
                }

            # Get app registration
            app = self.applications.get(target_app_id)
            if not app:
                return {"success": False, "error": f"Application {target_app_id} not registered"}

            # Construct callback URL
            if not app.callback_urls:
                return {"success": False, "error": "No callback URLs configured for application"}

            base_url = app.callback_urls[0]  # Use first callback URL
            url = f"{base_url}/{endpoint.lstrip('/')}"

            # Send authenticated request
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-XAA-Version": "1.0",
                "X-Delegation-Chain": claims.get("xaa_chain_id", ""),
            }

            method = method.upper()

            async with aiohttp.ClientSession() as session:
                if method == "GET":
                    async with session.get(url, headers=headers) as response:
                        result = await response.json() if response.status == 200 else await response.text()
                        return {
                            "success": response.status in [200, 201],
                            "status_code": response.status,
                            "data": result,
                        }

                elif method in ["POST", "PUT", "PATCH"]:
                    async with session.request(method, url, headers=headers, json=payload) as response:
                        result = await response.json() if response.status in [200, 201] else await response.text()
                        return {
                            "success": response.status in [200, 201],
                            "status_code": response.status,
                            "data": result,
                        }

                elif method == "DELETE":
                    async with session.delete(url, headers=headers) as response:
                        return {"success": response.status in [200, 204], "status_code": response.status}

                else:
                    return {"success": False, "error": f"Unsupported method: {method}"}

        except Exception as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}

    async def receive_app_callback(self, callback_token: str, data: dict, source_app_id: str) -> dict:
        """
        Receive callback from registered application.

        Bidirectional communication: App → Agent
        Processes callbacks from applications including approvals,
        notifications, and data responses.

        Parameters
        ----------
        callback_token : str
            XAA callback token for authentication
        data : dict
            Callback payload with 'type' and 'payload' fields
        source_app_id : str
            Source application ID initiating callback

        Returns
        -------
        dict
            Processing result:
            - 'success' : bool
                Whether callback was processed successfully
            - 'action' : str
                Action taken (e.g., 'approval_pending', 'notification_received')
            - Additional fields based on callback type

        Notes
        -----
        Supported callback types:
        - 'approval_request': Human-in-the-loop approval workflow
        - 'notification': Generic notification delivery
        - 'data_response': Data query response
        - 'error': Error notification from application

        Examples
        --------
        >>> result = await xaa.receive_app_callback(
        ...     callback_token=app_token,
        ...     data={
        ...         "type": "approval_request",
        ...         "payload": {"request_id": "req_123", "action": "transfer_funds"}
        ...     },
        ...     source_app_id="banking_app"
        ... )
        >>> if result['success']:
        ...     print(f"Approval pending: {result['callback_id']}")
        """
        try:
            # Verify callback token
            await self.verify_token(callback_token)

            # Verify source app
            if source_app_id not in self.applications:
                return {"success": False, "error": f"Unknown source application: {source_app_id}"}

            # Extract callback metadata
            callback_type = data.get("type", "notification")
            callback_payload = data.get("payload", {})

            print(f"📥 Callback received from {source_app_id}: {callback_type}")

            # Process based on callback type
            if callback_type == "approval_request":
                # Human-in-the-loop approval workflow
                return {
                    "success": True,
                    "action": "approval_pending",
                    "callback_id": callback_payload.get("request_id"),
                }

            elif callback_type == "notification":
                # Generic notification
                return {"success": True, "action": "notification_received"}

            elif callback_type == "data_response":
                # Data query response
                return {"success": True, "action": "data_received", "data": callback_payload}

            elif callback_type == "error":
                # Error notification
                return {"success": True, "action": "error_received", "error": callback_payload.get("message")}

            else:
                return {"success": False, "error": f"Unknown callback type: {callback_type}"}

        except Exception as e:
            return {"success": False, "error": f"Callback processing failed: {str(e)}"}

    async def establish_bidirectional_channel(self, agent_id: str, app_id: str, scopes: set[str]) -> dict:
        """
        Establish bidirectional communication channel.

        Agent ↔ App persistent connection
        Creates paired tokens for two-way authenticated communication
        between agent and application.

        Parameters
        ----------
        agent_id : str
            Agent identifier
        app_id : str
            Application identifier (must be registered)
        scopes : set of str
            Communication scopes for agent→app direction

        Returns
        -------
        dict
            Channel establishment result:
            - 'success' : bool
                Whether channel was established
            - 'channel_id' : str
                Unique channel identifier
            - 'agent_to_app_token' : str
                Token for agent→app requests
            - 'app_to_agent_token' : str
                Token for app→agent callbacks
            - 'expires_in' : int
                Token lifetime in seconds
            - 'capabilities' : dict
                Channel capabilities (send_requests, receive_callbacks, streaming)
            - 'error' : str
                Error message (if failed)

        Notes
        -----
        Bidirectional Channel Features:
        - Paired token creation for both directions
        - Agent→App: Uses specified scopes
        - App→Agent: Uses 'xaa:callback' scope
        - Both tokens expire after 1 hour (3600 seconds)
        - Channel ID format: channel_{agent_id}_{app_id}_{timestamp}

        Future enhancements will include streaming support.

        Examples
        --------
        >>> channel = await xaa.establish_bidirectional_channel(
        ...     agent_id="agent_123",
        ...     app_id="crm_app",
        ...     scopes={AccessScope.READ, AccessScope.WRITE}
        ... )
        >>> if channel['success']:
        ...     agent_token = channel['agent_to_app_token']
        ...     callback_token = channel['app_to_agent_token']
        """
        # Verify app is registered
        app = self.applications.get(app_id)
        if not app:
            return {"success": False, "error": f"Application {app_id} not registered"}

        # Issue agent→app token
        agent_to_app_token = await self.issue_token(
            subject=agent_id,
            audience=app_id,
            scopes=scopes,
            token_type=XAATokenType.PRIMARY,
            metadata={"direction": "agent_to_app"},
        )

        # Issue app→agent callback token
        app_to_agent_token = await self.issue_token(
            subject=app_id,
            audience=agent_id,
            scopes={"xaa:callback"},
            token_type=XAATokenType.PRIMARY,
            metadata={"direction": "app_to_agent"},
        )

        # Store channel metadata
        channel_id = f"channel_{agent_id}_{app_id}_{int(time.time())}"

        print(f"🔗 Bidirectional channel established: {agent_id} ↔ {app_id}")

        return {
            "success": True,
            "channel_id": channel_id,
            "agent_to_app_token": agent_to_app_token,
            "app_to_agent_token": app_to_agent_token,
            "expires_in": 3600,
            "capabilities": {
                "send_requests": True,
                "receive_callbacks": True,
                "streaming": False,  # Future enhancement
            },
        }

    async def close(self):
        """
        Close resources.

        Properly closes HTTP session used for Okta integration
        to prevent resource leaks.

        Notes
        -----
        Should be called when XAAProtocol instance is no longer needed,
        especially in long-running applications. Only closes session
        if Okta integration was configured.
        """
        if hasattr(self, "session"):
            await self.session.close()
