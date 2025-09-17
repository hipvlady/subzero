# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a Zero Trust API Gateway (ZTAG) project implementing high-performance authentication and authorization for AI-native applications. The system achieves 10,000+ requests per second with sub-10ms authentication latency using secretless authentication principles.

## Architecture

The project follows a modular architecture with four main layers:

### Core Components

- **Authentication Layer** (`src/auth/`) - Private Key JWT authentication with JIT-compiled token validation
- **Authorization Engine** (`src/fga/`) - Auth0 Fine-Grained Authorization integration
- **AI Security Module** (`src/mcp/`) - MCP protocol support and AI agent security
- **Performance Intelligence** (`src/performance/`) - NumPy-based analytics and monitoring
- **Security Module** (`src/security/`) - Bot detection and threat analysis

### Key Design Patterns

- **Secretless Authentication**: Uses Private Key JWT (RFC 7523) instead of shared secrets
- **JIT Compilation**: Numba-optimized functions for critical performance paths
- **Contiguous Memory Caching**: NumPy arrays for high-performance token caching
- **AsyncIO Pipeline**: Non-blocking I/O for concurrent request handling

## Development Setup

### Environment Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env  # Configure Auth0 and FGA credentials
```

### Configuration
- Main settings in `config/settings.py` using Pydantic Settings
- Environment variables loaded from `.env` file
- Key configurations:
  - Auth0 domain, client ID, audience
  - Auth0 FGA store ID and credentials
  - Performance tuning (cache capacity, connection pools)
  - Security settings (bot detection thresholds)

## Common Development Commands

### Running the Application
```bash
# Development server with hot reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production server with performance optimization
uvicorn main:app --workers 4 --host 0.0.0.0 --port 8000
```

### Testing
```bash
# Run unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run performance benchmarks
pytest tests/performance/ -v --benchmark-only

# Run load tests
locust -f tests/performance/load_test.py --host=http://localhost:8000
```

### Code Quality
```bash
# Format code
black src/ tests/ config/

# Lint code
ruff check src/ tests/ config/

# Type checking (if configured)
mypy src/
```

### Performance Analysis
```bash
# Generate performance profile
python -m cProfile -o profile.stats main.py

# Analyze JIT compilation
NUMBA_DEBUG=1 python your_script.py
```

## Technology Stack

- **Framework**: FastAPI with uvloop for async performance
- **Authentication**: Auth0 with Private Key JWT (secretless)
- **Authorization**: Auth0 FGA for fine-grained permissions
- **Performance**: NumPy + Numba JIT compilation
- **Caching**: Redis with aiocache for distributed caching
- **Monitoring**: Prometheus + OpenTelemetry
- **AI Integration**: MCP protocol for AI agent interaction
- **Database**: AsyncPG for PostgreSQL (when needed)

## Security Considerations

- **No Shared Secrets**: Uses Private Key JWT exclusively
- **Token Vault Integration**: Secure credential management for AI agents
- **Bot Detection**: ML-based suspicious pattern detection
- **Rate Limiting**: Configurable request throttling
- **Prompt Injection Detection**: AI-specific security filters

## Performance Targets

- Authentication latency: <10ms (cached tokens)
- Authorization checks: 50,000 permissions/sec
- Concurrent connections: 10,000+
- Cache hit ratio: 95%+
- Memory usage: Optimized with contiguous NumPy arrays

## Key Files

- `src/auth/private_key_jwt.py` - Core authentication implementation
- `config/settings.py` - Application configuration
- `requirements.txt` - Python dependencies
- `readme.md` - Project overview and architecture diagrams