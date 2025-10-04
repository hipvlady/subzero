"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Try .env.demo first (for testing), then .env, then environment variables only
    _env_file = ".env.demo" if os.path.exists(".env.demo") else ".env"
    model_config = SettingsConfigDict(extra="ignore", env_file=_env_file, case_sensitive=True)
    # Auth0 Configuration
    AUTH0_DOMAIN: str = "example.auth0.com"
    AUTH0_CLIENT_ID: str = "test_client_id"
    AUTH0_CLIENT_SECRET: str | None = None
    AUTH0_AUDIENCE: str = "https://api.example.com"
    AUTH0_MANAGEMENT_API_TOKEN: str | None = None

    # Auth0 FGA Configuration
    FGA_STORE_ID: str = "test_store_id"
    FGA_CLIENT_ID: str = "test_fga_client_id"
    FGA_CLIENT_SECRET: str = "test_fga_secret"
    FGA_API_URL: str = "https://api.us1.fga.dev"

    # Auth0 Token Vault Configuration
    TOKEN_VAULT_ENABLED: bool = True
    TOKEN_VAULT_API_URL: str = "https://api.auth0.com/token-vault/v1"
    TOKEN_VAULT_NAMESPACE: str = "ztag"
    TOKEN_VAULT_ENCRYPTION_KEY: str | None = None
    TOKEN_VAULT_SUPPORTED_PROVIDERS: list[str] = ["google", "microsoft", "slack", "github", "box", "salesforce"]

    # Okta Configuration (for XAA support)
    OKTA_DOMAIN: str | None = None
    OKTA_CLIENT_ID: str | None = None
    OKTA_CLIENT_SECRET: str | None = None
    OKTA_API_TOKEN: str | None = None

    # Cross App Access (XAA) Configuration
    XAA_ENABLED: bool = True
    XAA_ISSUER: str = "https://api.ztag.dev"
    XAA_SIGNING_KEY: str | None = None
    XAA_TOKEN_TTL: int = 3600  # 1 hour
    XAA_MAX_DELEGATION_DEPTH: int = 3

    # Identity Security Posture Management (ISPM)
    ISPM_ENABLED: bool = True
    ISPM_RISK_THRESHOLD: float = 0.7
    ISPM_AUTO_REMEDIATION: bool = True
    ISPM_ALERT_WEBHOOK: str | None = None

    # Threat Detection
    THREAT_DETECTION_ENABLED: bool = True
    SIGNUP_ATTACK_DETECTION: bool = True
    ATO_PROTECTION_ENABLED: bool = True
    MFA_ABUSE_DETECTION: bool = True
    AI_HALLUCINATION_DETECTION: bool = True

    # Universal Directory for Agents
    AGENT_DIRECTORY_ENABLED: bool = True
    AGENT_REGISTRY_URL: str | None = None
    AGENT_MAX_REGISTRATIONS: int = 10000

    # Compliance
    GDPR_COMPLIANCE_MODE: bool = False
    HIPAA_COMPLIANCE_MODE: bool = False
    AUDIT_LOG_RETENTION_DAYS: int = 90
    AUDIT_LOG_ENDPOINT: str | None = None

    # Performance Settings
    CACHE_CAPACITY: int = 10000
    MAX_CONNECTIONS: int = 1000
    CONNECTION_POOL_SIZE: int = 100

    # Multiprocessing Settings
    ENABLE_MULTIPROCESSING: bool = True
    JWT_PROCESSOR_WORKERS: int = 4
    HASH_PROCESSOR_WORKERS: int = 2
    VERIFICATION_WORKERS: int = 2
    SHARED_MEMORY_SIZE: int = 10_000_000  # 10MB
    PROCESS_POOL_TIMEOUT: int = 30
    BATCH_SIZE_THRESHOLD: int = 10  # Minimum batch size for multiprocessing

    # Process Pool Configuration
    PROCESS_START_METHOD: str = "spawn"  # Options: fork, spawn, forkserver
    NUMA_AWARE_PLACEMENT: bool = True
    CPU_AFFINITY_ENABLED: bool = True

    # Security Settings
    ENABLE_BOT_DETECTION: bool = True
    BOT_DETECTION_THRESHOLD: float = 0.8
    RATE_LIMIT_REQUESTS: int = 1000
    RATE_LIMIT_WINDOW: int = 60

    # MCP Settings
    MCP_SERVER_NAME: str = "Zero Trust Gateway"
    MCP_SERVER_VERSION: str = "1.0.0"
    MCP_TRANSPORT: str = "sse"  # Options: stdio, sse, custom
    MCP_ENABLE_DYNAMIC_DISCOVERY: bool = True
    MCP_CAPABILITY_NEGOTIATION: bool = True

    # OPA Settings
    OPA_ENABLED: bool = True
    OPA_URL: str = "http://localhost:8181"

    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_PASSWORD: str | None = None


settings = Settings()
