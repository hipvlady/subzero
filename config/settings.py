from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Auth0 Configuration
    AUTH0_DOMAIN: str
    AUTH0_CLIENT_ID: str
    AUTH0_CLIENT_SECRET: Optional[str] = None
    AUTH0_AUDIENCE: str
    
    # Auth0 FGA Configuration
    FGA_STORE_ID: str
    FGA_CLIENT_ID: str
    FGA_CLIENT_SECRET: str
    FGA_API_URL: str = "https://api.us1.fga.dev"
    
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
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()