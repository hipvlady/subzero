"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Configuration settings for Subzero Zero Trust API Gateway.
"""

import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuration settings for Subzero Zero Trust API Gateway.

    Manages all configuration parameters loaded from environment variables or
    .env files. Uses Pydantic for validation and type coercion. Settings are
    loaded in priority order: .env.demo (if exists) → .env → environment variables.

    Attributes
    ----------
    AUTH0_DOMAIN : str, default "example.auth0.com"
        Auth0 tenant domain (e.g., "tenant.auth0.com")
    AUTH0_CLIENT_ID : str, default "test_client_id"
        Auth0 application client ID
    AUTH0_CLIENT_SECRET : str, optional
        Auth0 application client secret for confidential clients
    AUTH0_AUDIENCE : str, default "https://api.example.com"
        Auth0 API audience identifier
    AUTH0_MANAGEMENT_API_TOKEN : str, optional
        Token for Auth0 Management API access

    FGA_STORE_ID : str, default "test_store_id"
        Auth0 Fine-Grained Authorization store ID
    FGA_CLIENT_ID : str, default "test_fga_client_id"
        FGA client ID for API access
    FGA_CLIENT_SECRET : str, default "test_fga_secret"
        FGA client secret
    FGA_API_URL : str, default "https://api.us1.fga.dev"
        FGA API endpoint URL

    TOKEN_VAULT_ENABLED : bool, default True
        Enable Auth0 Token Vault for credential storage
    TOKEN_VAULT_API_URL : str, default "https://api.auth0.com/token-vault/v1"
        Token Vault API endpoint
    TOKEN_VAULT_NAMESPACE : str, default "ztag"
        Namespace for token storage isolation
    TOKEN_VAULT_ENCRYPTION_KEY : str, optional
        Encryption key for vault data
    TOKEN_VAULT_SUPPORTED_PROVIDERS : list of str
        Supported OAuth providers for token storage.
        Default: ["google", "microsoft", "slack", "github", "box", "salesforce"]

    OKTA_DOMAIN : str, optional
        Okta tenant domain for XAA support
    OKTA_CLIENT_ID : str, optional
        Okta application client ID
    OKTA_CLIENT_SECRET : str, optional
        Okta application client secret
    OKTA_API_TOKEN : str, optional
        Okta API token for management operations

    XAA_ENABLED : bool, default True
        Enable Cross-App Access (XAA) for AI agent delegation
    XAA_ISSUER : str, default "https://api.ztag.dev"
        XAA token issuer URL
    XAA_SIGNING_KEY : str, optional
        Private key for XAA token signing
    XAA_TOKEN_TTL : int, default 3600
        XAA token time-to-live in seconds (1 hour)
    XAA_MAX_DELEGATION_DEPTH : int, default 3
        Maximum delegation chain depth to prevent infinite loops

    ISPM_ENABLED : bool, default True
        Enable Identity Security Posture Management
    ISPM_RISK_THRESHOLD : float, default 0.7
        Risk score threshold for ISPM alerts (0.0-1.0)
    ISPM_AUTO_REMEDIATION : bool, default True
        Enable automatic remediation of security issues
    ISPM_ALERT_WEBHOOK : str, optional
        Webhook URL for ISPM alerts

    THREAT_DETECTION_ENABLED : bool, default True
        Enable threat detection subsystem
    SIGNUP_ATTACK_DETECTION : bool, default True
        Detect automated signup attacks
    ATO_PROTECTION_ENABLED : bool, default True
        Enable Account Takeover (ATO) protection
    MFA_ABUSE_DETECTION : bool, default True
        Detect MFA bypass attempts
    AI_HALLUCINATION_DETECTION : bool, default True
        Detect AI agent hallucination attacks

    AGENT_DIRECTORY_ENABLED : bool, default True
        Enable universal directory for AI agents
    AGENT_REGISTRY_URL : str, optional
        URL for agent registry service
    AGENT_MAX_REGISTRATIONS : int, default 10000
        Maximum number of registered agents

    GDPR_COMPLIANCE_MODE : bool, default False
        Enable GDPR compliance features
    HIPAA_COMPLIANCE_MODE : bool, default False
        Enable HIPAA compliance features
    AUDIT_LOG_RETENTION_DAYS : int, default 90
        Audit log retention period in days
    AUDIT_LOG_ENDPOINT : str, optional
        External audit log endpoint URL

    CACHE_CAPACITY : int, default 10000
        Maximum number of entries in LRU caches
    MAX_CONNECTIONS : int, default 1000
        Maximum concurrent connections
    CONNECTION_POOL_SIZE : int, default 100
        Database/HTTP connection pool size

    ENABLE_MULTIPROCESSING : bool, default True
        Enable multiprocessing for CPU-intensive operations
    JWT_PROCESSOR_WORKERS : int, default 4
        Number of worker processes for JWT operations
    HASH_PROCESSOR_WORKERS : int, default 2
        Number of worker processes for hashing
    VERIFICATION_WORKERS : int, default 2
        Number of worker processes for verification
    SHARED_MEMORY_SIZE : int, default 10000000
        Shared memory size in bytes (10MB)
    PROCESS_POOL_TIMEOUT : int, default 30
        Process pool operation timeout in seconds
    BATCH_SIZE_THRESHOLD : int, default 10
        Minimum batch size to trigger multiprocessing

    PROCESS_START_METHOD : str, default "spawn"
        Process start method: "fork", "spawn", or "forkserver"
    NUMA_AWARE_PLACEMENT : bool, default True
        Enable NUMA-aware process placement
    CPU_AFFINITY_ENABLED : bool, default True
        Enable CPU affinity for worker processes

    ENABLE_BOT_DETECTION : bool, default True
        Enable bot detection
    BOT_DETECTION_THRESHOLD : float, default 0.8
        Bot probability threshold (0.0-1.0)
    RATE_LIMIT_REQUESTS : int, default 1000
        Maximum requests per rate limit window
    RATE_LIMIT_WINDOW : int, default 60
        Rate limit window in seconds

    MCP_SERVER_NAME : str, default "Zero Trust Gateway"
        Model Context Protocol server name
    MCP_SERVER_VERSION : str, default "1.0.0"
        MCP server version
    MCP_TRANSPORT : str, default "sse"
        MCP transport protocol: "stdio", "sse", or "custom"
    MCP_ENABLE_DYNAMIC_DISCOVERY : bool, default True
        Enable MCP dynamic capability discovery
    MCP_CAPABILITY_NEGOTIATION : bool, default True
        Enable MCP capability negotiation

    OPA_ENABLED : bool, default True
        Enable Open Policy Agent integration
    OPA_URL : str, default "http://localhost:8181"
        OPA server URL

    REDIS_URL : str, default "redis://localhost:6379"
        Redis connection URL
    REDIS_PASSWORD : str, optional
        Redis authentication password

    Notes
    -----
    Configuration Priority:
    1. .env.demo file (if exists, for testing)
    2. .env file (if exists)
    3. Environment variables
    4. Default values

    The settings instance is created with case-sensitive environment variable
    matching and allows extra fields for flexibility.

    Security Considerations:
    - Never commit .env files with production credentials
    - Use environment variables in production
    - Rotate secrets regularly
    - Use Auth0_CLIENT_SECRET only for confidential clients

    Examples
    --------
    Access settings in code:

    >>> from subzero.config.defaults import settings
    >>> settings.AUTH0_DOMAIN
    'example.auth0.com'
    >>> settings.CACHE_CAPACITY
    10000

    Override via environment variables:

    ```bash
    export AUTH0_DOMAIN="production.auth0.com"
    export CACHE_CAPACITY=50000
    python -m subzero
    ```

    Override via .env file:

    ```
    # .env
    AUTH0_DOMAIN=production.auth0.com
    AUTH0_CLIENT_ID=prod_client_123
    CACHE_CAPACITY=50000
    ```
    """

    # Try .env.demo first (for testing), then .env, then environment variables only
    _env_file = ".env.demo" if os.path.exists(".env.demo") else ".env"
    model_config = SettingsConfigDict(extra="allow", env_file=_env_file, case_sensitive=True)

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
