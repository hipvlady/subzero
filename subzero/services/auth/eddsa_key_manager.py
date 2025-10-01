"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

EdDSA (Ed25519) Key Manager for High-Performance JWT Signing
Provides 10x faster signing compared to RSA
"""

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class EdDSAKeyManager:
    """
    EdDSA (Ed25519) key manager for ultra-fast JWT operations

    Benefits over RSA:
    - 10x faster signing
    - 5x faster verification
    - Smaller signatures (64 bytes vs 256 bytes)
    - Better security per bit
    """

    def __init__(self):
        """Initialize with Ed25519 key pair"""
        # Generate Ed25519 private key
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Serialize keys for JWT library
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_jwt(self, payload: dict[str, Any]) -> str:
        """
        Sign JWT with EdDSA

        Args:
            payload: JWT payload dict

        Returns:
            Signed JWT token string
        """
        # Add iat if not present
        if "iat" not in payload:
            payload["iat"] = int(time.time())

        # Sign with EdDSA
        token = jwt.encode(payload, self.private_pem, algorithm="EdDSA")

        return token

    def verify_jwt(self, token: str) -> dict[str, Any]:
        """
        Verify and decode JWT

        Args:
            token: JWT token string

        Returns:
            Decoded payload dict

        Raises:
            jwt.InvalidTokenError: If verification fails
        """
        payload = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])

        return payload

    def get_public_key_pem(self) -> bytes:
        """Get public key in PEM format"""
        return self.public_pem

    def get_private_key_pem(self) -> bytes:
        """Get private key in PEM format"""
        return self.private_pem
