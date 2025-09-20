FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY zero_trust_ai_gateway/ ./zero_trust_ai_gateway/
COPY etc/ ./etc/

# Create non-root user
RUN useradd -m -u 1000 ztag && chown -R ztag:ztag /app
USER ztag

# Set environment variables
ENV ZTAG_PORT=8080
ENV ZTAG_HOST=0.0.0.0
ENV ZTAG_LOG_LEVEL=INFO
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "-m", "zero_trust_ai_gateway"]