# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

# Multi-stage Dockerfile for Subzero Zero Trust API Gateway
# Optimized for security, performance, and minimal image size

# ========================================
# Stage 1: Builder
# ========================================
FROM python:3.11-slim AS builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies to user site-packages
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY . .

# Install application
RUN pip install --no-cache-dir --user .

# ========================================
# Stage 2: Runtime
# ========================================
FROM python:3.11-slim

# Set labels for image metadata
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Subzero Development Team <dev@subzero.dev>" \
      org.opencontainers.image.url="https://github.com/subzero-dev/subzero" \
      org.opencontainers.image.source="https://github.com/subzero-dev/subzero" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Subzero" \
      org.opencontainers.image.title="Subzero Zero Trust API Gateway" \
      org.opencontainers.image.description="High-performance Zero Trust API Gateway with enterprise-grade security" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash subzero && \
    mkdir -p /app /data /logs && \
    chown -R subzero:subzero /app /data /logs

# Copy installed packages from builder
COPY --from=builder --chown=subzero:subzero /root/.local /home/subzero/.local

# Set working directory
WORKDIR /app

# Copy application files
COPY --chown=subzero:subzero . .

# Set environment variables
ENV PATH=/home/subzero/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Switch to non-root user
USER subzero

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set entrypoint
ENTRYPOINT ["python", "-m", "subzero"]

# Default command (can be overridden)
CMD ["--host", "0.0.0.0", "--port", "8000"]

# ========================================
# Build instructions:
# docker build -t subzero:latest \
#   --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
#   --build-arg VCS_REF=$(git rev-parse --short HEAD) \
#   --build-arg VERSION=$(cat subzero/_version.py | grep __version__ | cut -d'"' -f2) \
#   .
#
# Run instructions:
# docker run -d \
#   -p 8000:8000 \
#   --name subzero \
#   --env-file .env \
#   subzero:latest
# ========================================