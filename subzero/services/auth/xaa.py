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

import asyncio
import time
import secrets
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

import jwt
import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from subzero.config.defaults import settings


class XAATokenType(str, Enum):
    """Types of XAA tokens"""

    PRIMARY = "primary"  # Original user/agent token
    DELEGATED = "delegated"  # Delegated access token
    IMPERSONATION = "impersonation"  # Impersonation token


class AccessScope(str, Enum):
    """XAA access scopes"""

    READ = "xaa:read"
    WRITE = "xaa:write"
    EXECUTE = "xaa:execute"
    ADMIN = "xaa:admin"
    DELEGATE = "xaa:delegate"


@dataclass
class DelegationChain:
    """Track delegation chain for audit and security"""

    chain_id: str
    initiator: str  # Original user/agent
    current_holder: str  # Current token holder
    delegation_path: List[str] = field(default_factory=list)
    depth: int = 0
    max_depth: int = 3
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)


@dataclass
class XAAToken:
    """Cross App Access token"""

    token_id: str
    token_type: XAATokenType
    subject: str  # Agent or user ID
    audience: str  # Target application
    scopes: Set[str]
    delegation_chain: Optional[DelegationChain] = None
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    metadata: Dict = field(default_factory=dict)


@dataclass
class AppRegistration:
    """Registered application for XAA"""

    app_id: str
    app_name: str
    app_type: str  # "web", "service", "agent"
    allowed_scopes: Set[str]
    allowed_delegations: bool = True
    max_delegation_depth: int = 3
    callback_urls: List[str] = field(default_factory=list)
    public_key: Optional[str] = None  # For token verification


class XAAProtocol:
    """
    Cross App Access Protocol Implementation
    Enables secure multi-hop agent-to-app communication
    """

    def __init__(self, issuer: str, signing_key: Optional[rsa.RSAPrivateKey] = None, okta_domain: Optional[str] = None):
        """
        Initialize XAA protocol

        Args:
            issuer: XAA token issuer URL
            signing_key: RSA private key for token signing
            okta_domain: Okta domain for integration
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
        self.applications: Dict[str, AppRegistration] = {}

        # Active tokens
        self.active_tokens: Dict[str, XAAToken] = {}

        # Delegation chains
        self.delegation_chains: Dict[str, DelegationChain] = {}

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
        allowed_scopes: Set[str],
        callback_urls: Optional[List[str]] = None,
        max_delegation_depth: int = 3,
    ) -> AppRegistration:
        """
        Register application for XAA

        Args:
            app_id: Unique application identifier
            app_name: Human-readable name
            app_type: Application type
            allowed_scopes: Permitted XAA scopes
            callback_urls: OAuth callback URLs
            max_delegation_depth: Maximum delegation depth

        Returns:
            Application registration
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
        scopes: Set[str],
        token_type: XAATokenType = XAATokenType.PRIMARY,
        expires_in: int = 3600,
        metadata: Optional[Dict] = None,
    ) -> str:
        """
        Issue XAA token

        Args:
            subject: Agent or user ID
            audience: Target application
            scopes: Requested scopes
            token_type: Type of XAA token
            expires_in: Token lifetime (seconds)
            metadata: Additional metadata

        Returns:
            JWT token string
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
        scopes: Optional[Set[str]] = None,
        expires_in: int = 1800,
    ) -> str:
        """
        Delegate XAA token to another agent/app

        Args:
            original_token: Original JWT token
            target_subject: Target agent/user
            target_audience: Target application
            scopes: Optional scope restriction
            expires_in: Delegation token lifetime

        Returns:
            Delegated JWT token
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
            raise ValueError(f"Invalid original token: {e}")

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

    async def verify_token(
        self, token_string: str, expected_audience: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Verify XAA token

        Args:
            token_string: JWT token to verify
            expected_audience: Expected audience (optional)

        Returns:
            Tuple of (is_valid, claims)
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
        Revoke XAA token

        Args:
            token_string: JWT token to revoke

        Returns:
            True if revoked successfully
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
        Revoke entire delegation chain

        Args:
            chain_id: Delegation chain ID

        Returns:
            Number of tokens revoked
        """
        if chain_id not in self.delegation_chains:
            return 0

        chain = self.delegation_chains[chain_id]

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

    async def introspect_token(self, token_string: str) -> Dict:
        """
        Introspect XAA token (RFC 7662)

        Args:
            token_string: JWT token

        Returns:
            Token introspection response
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
        Sync XAA tokens with Okta ecosystem

        Returns:
            True if successful
        """
        if not self.okta_domain:
            return False

        # Sync application registrations with Okta
        for app in self.applications.values():
            await self._register_app_with_okta(app)

        print(f"🔄 Synced {len(self.applications)} apps with Okta")

        return True

    async def _register_app_with_okta(self, app: AppRegistration) -> bool:
        """Register application with Okta"""
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
        """Get existing or create new delegation chain"""
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
        """Generate unique token ID"""
        return secrets.token_urlsafe(32)

    def get_metrics(self) -> Dict:
        """Get XAA protocol metrics"""
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

    def get_public_key_jwk(self) -> Dict:
        """Get public key in JWK format"""
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
        self, token: str, target_app_id: str, method: str, endpoint: str, payload: Optional[Dict] = None
    ) -> Dict:
        """
        Send authenticated request to registered application
        Bidirectional communication: Agent → App

        Args:
            token: XAA access token
            target_app_id: Target application ID
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            payload: Request payload

        Returns:
            Response from target application
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

    async def receive_app_callback(self, callback_token: str, data: Dict, source_app_id: str) -> Dict:
        """
        Receive callback from registered application
        Bidirectional communication: App → Agent

        Args:
            callback_token: XAA callback token
            data: Callback payload
            source_app_id: Source application ID

        Returns:
            Processing result
        """
        try:
            # Verify callback token
            claims = await self.verify_token(callback_token)

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

    async def establish_bidirectional_channel(self, agent_id: str, app_id: str, scopes: Set[str]) -> Dict:
        """
        Establish bidirectional communication channel
        Agent ↔ App persistent connection

        Args:
            agent_id: Agent identifier
            app_id: Application identifier
            scopes: Communication scopes

        Returns:
            Channel establishment result with tokens
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
        """Close resources"""
        if hasattr(self, "session"):
            await self.session.close()
