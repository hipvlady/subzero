"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT
"""

import time
from dataclasses import dataclass

import aiohttp
import jwt
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from numba import jit


@dataclass
class TokenCache:
    """Memory-efficient token cache using numpy arrays"""

    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self.tokens = {}  # user_id -> token_data
        self.timestamps = np.zeros(capacity, dtype=np.float64)
        self.user_hashes = np.zeros(capacity, dtype=np.uint64)
        self.current_index = 0

    @jit(nopython=True)
    def _hash_user_id(user_id_bytes: np.ndarray) -> np.uint64:
        """JIT-compiled hash function for ultra-fast lookups"""
        hash_val = np.uint64(5381)
        for byte in user_id_bytes:
            hash_val = ((hash_val << np.uint64(5)) + hash_val) + np.uint64(byte)
        return hash_val


class PrivateKeyJWTAuthenticator:
    """
    High-performance Private Key JWT authenticator for Auth0
    Implements Zero Shared Secrets principle
    """

    def __init__(self, auth0_domain: str, client_id: str, cache_capacity: int = 10000):
        self.auth0_domain = auth0_domain
        self.client_id = client_id

        # Generate RSA key pair for JWT signing
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        self.public_key = self.private_key.public_key()

        # Initialize high-performance cache
        self.cache = TokenCache(capacity=cache_capacity)

        # Connection pooling for optimal network performance
        connector = aiohttp.TCPConnector(limit=1000, limit_per_host=100, ttl_dns_cache=300, enable_cleanup_closed=True)

        timeout = aiohttp.ClientTimeout(total=30, connect=5)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        # Pre-compile JIT functions
        self._warmup_jit()

    def _warmup_jit(self):
        """Pre-compile JIT functions for faster first execution"""
        test_bytes = np.array([1, 2, 3], dtype=np.uint8)
        _ = TokenCache._hash_user_id(test_bytes)

    async def authenticate(self, user_id: str, scopes: str = "openid profile email") -> dict:
        """
        Perform Private Key JWT authentication
        Returns access token with sub-10ms latency for cached tokens
        """
        start_time = time.perf_counter()

        # Check cache first
        cached_token = self._get_cached_token(user_id)
        if cached_token:
            latency_ms = (time.perf_counter() - start_time) * 1000
            print(f"✅ Cache hit - Authentication latency: {latency_ms:.2f}ms")
            return cached_token

        # Generate JWT assertion
        assertion = self._create_jwt_assertion(user_id)

        # Exchange assertion for access token
        token_data = await self._exchange_assertion_for_token(assertion, scopes)

        # Cache the token
        self._cache_token(user_id, token_data)

        latency_ms = (time.perf_counter() - start_time) * 1000
        print(f"📡 New authentication - Latency: {latency_ms:.2f}ms")

        return token_data

    def _create_jwt_assertion(self, user_id: str) -> str:
        """
        Create a JWT assertion for Private Key JWT authentication
        """
        now = int(time.time())

        # JWT claims as per Auth0 spec
        claims = {
            "iss": self.client_id,
            "sub": user_id,
            "aud": f"https://{self.auth0_domain}/oauth/token",
            "iat": now,
            "exp": now + 60,  # 60-second lifetime
            "jti": self._generate_jti(),  # Unique identifier for replay protection
        }

        # Sign with private key
        token = jwt.encode(claims, self.private_key, algorithm="RS256")

        return token

    def _generate_jti(self) -> str:
        """Generate unique JWT ID for replay protection"""
        import uuid

        return str(uuid.uuid4())

    async def _exchange_assertion_for_token(self, assertion: str, scopes: str) -> dict:
        """
        Exchange JWT assertion for access token
        """
        url = f"https://{self.auth0_domain}/oauth/token"

        payload = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion, "scope": scopes}

        async with self.session.post(url, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Token exchange failed: {error_text}")

            return await response.json()

    def _get_cached_token(self, user_id: str) -> dict | None:
        """
        Retrieve token from cache if valid
        """
        if user_id not in self.cache.tokens:
            return None

        token_data = self.cache.tokens[user_id]

        # Check if token is still valid (with 5-minute buffer)
        expires_at = token_data.get("expires_at", 0)
        if time.time() >= expires_at - 300:
            # Token expired or expiring soon
            del self.cache.tokens[user_id]
            return None

        return token_data

    def _cache_token(self, user_id: str, token_data: dict):
        """
        Cache token with expiration tracking
        """
        # Add expiration timestamp
        token_data["expires_at"] = time.time() + token_data.get("expires_in", 3600)

        # Store in cache
        self.cache.tokens[user_id] = token_data

        # Update numpy arrays for performance tracking
        idx = self.cache.current_index
        self.cache.timestamps[idx] = time.time()

        user_bytes = np.frombuffer(user_id.encode(), dtype=np.uint8)
        self.cache.user_hashes[idx] = TokenCache._hash_user_id(user_bytes)

        self.cache.current_index = (idx + 1) % self.cache.capacity

    async def close(self):
        """Clean up resources"""
        await self.session.close()

    def get_public_key_jwk(self) -> dict:
        """
        Get public key in JWK format for Auth0 configuration
        """
        import base64

        public_numbers = self.public_key.public_numbers()

        # Convert to base64url encoding
        def to_base64url(num: int, length: int) -> str:
            bytes_data = num.to_bytes(length, byteorder="big")
            return base64.urlsafe_b64encode(bytes_data).rstrip(b"=").decode("ascii")

        return {
            "kty": "RSA",
            "use": "sig",
            "kid": self.client_id,
            "n": to_base64url(public_numbers.n, 256),
            "e": to_base64url(public_numbers.e, 3),
        }
