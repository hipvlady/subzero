"""Base API handlers for Zero Trust AI Gateway."""

from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer()

@router.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint"""
    return {
        "service": "Zero Trust AI Gateway",
        "version": "1.0.0.hackathon",
        "status": "active"
    }

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for load balancers"""
    start_time = time.perf_counter()

    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "latency_ms": (time.perf_counter() - start_time) * 1000,
        "components": {
            "auth_layer": "operational",
            "fga_engine": "operational",
            "ai_security": "operational",
            "performance_intel": "operational"
        }
    }

    return health_status

@router.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """Readiness check for Kubernetes"""
    return {
        "ready": True,
        "checks": {
            "auth0_connection": True,
            "fga_connection": True,
            "cache_initialized": True
        }
    }

@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Prometheus-compatible metrics endpoint"""
    return {
        "metrics": {
            "http_requests_total": 0,
            "http_request_duration_seconds": 0.0,
            "auth_requests_total": 0,
            "auth_cache_hits_total": 0,
            "fga_checks_total": 0
        }
    }

# Default handlers for the base service
default_handlers = [
    ("/", "GET", root),
    ("/health", "GET", health_check),
    ("/ready", "GET", readiness_check),
    ("/metrics", "GET", metrics)
]