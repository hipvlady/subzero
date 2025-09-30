"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Auth0 Service Health Monitoring
Real-time monitoring of Auth0 services and graceful degradation

Features:
- Multi-service health checking
- Circuit breaker pattern
- Graceful degradation strategies
- Alert notifications
- Health dashboard data
"""

import asyncio
import time
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from collections import deque

import aiohttp
import httpx

from subzero.config.defaults import settings


class ServiceStatus(str, Enum):
    """Service health status"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CircuitState(str, Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit breaker triggered
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class HealthCheck:
    """Individual health check result"""

    service: str
    status: ServiceStatus
    response_time_ms: float
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class CircuitBreaker:
    """Circuit breaker for service protection"""

    service_name: str
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout: int = 60  # seconds

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0
    opened_at: Optional[float] = None

    def record_success(self):
        """Record successful request"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1

            if self.success_count >= self.success_threshold:
                # Fully recovered
                self.close()
        elif self.state == CircuitState.CLOSED:
            # Reset failure count
            self.failure_count = 0

    def record_failure(self):
        """Record failed request"""
        self.last_failure_time = time.time()
        self.failure_count += 1

        if self.failure_count >= self.failure_threshold:
            self.open()

    def open(self):
        """Open circuit breaker"""
        self.state = CircuitState.OPEN
        self.opened_at = time.time()
        self.success_count = 0
        print(f"⚠️  Circuit breaker OPEN for {self.service_name}")

    def close(self):
        """Close circuit breaker"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.opened_at = None
        print(f"✅ Circuit breaker CLOSED for {self.service_name}")

    def half_open(self):
        """Enter half-open state to test recovery"""
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
        print(f"🔄 Circuit breaker HALF-OPEN for {self.service_name}")

    def should_allow_request(self) -> bool:
        """Check if request should be allowed"""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if time.time() - self.opened_at >= self.timeout:
                self.half_open()
                return True
            return False

        # HALF_OPEN: allow requests to test recovery
        return True


class Auth0HealthMonitor:
    """
    Comprehensive Auth0 service health monitoring
    Implements circuit breakers and graceful degradation
    """

    def __init__(self):
        # Circuit breakers for each service
        self.circuit_breakers = {
            "authentication": CircuitBreaker("authentication"),
            "fga": CircuitBreaker("fga"),
            "management_api": CircuitBreaker("management_api"),
            "token_vault": CircuitBreaker("token_vault"),
        }

        # Health check history
        self.health_history: Dict[str, deque] = {service: deque(maxlen=100) for service in self.circuit_breakers.keys()}

        # HTTP clients
        self.http_client = httpx.AsyncClient(timeout=10.0)

        # Monitoring configuration
        self.check_interval = 30  # seconds
        self.alert_threshold = 3  # consecutive failures before alert

        # Metrics
        self.total_checks = 0
        self.total_failures = 0
        self.alerts_sent = 0

        # Background monitoring task
        self._monitoring_task: Optional[asyncio.Task] = None

    async def start_monitoring(self):
        """Start continuous health monitoring"""
        if self._monitoring_task:
            return

        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        print(f"🏥 Health monitoring started (interval: {self.check_interval}s)")

    async def stop_monitoring(self):
        """Stop health monitoring"""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None

    async def _monitoring_loop(self):
        """Continuous monitoring loop"""
        while True:
            try:
                await self.check_all_services()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                await asyncio.sleep(self.check_interval)

    async def check_all_services(self) -> Dict[str, HealthCheck]:
        """Check health of all Auth0 services"""
        results = {}

        # Run checks in parallel
        checks = [
            self.check_authentication_service(),
            self.check_fga_service(),
            self.check_management_api(),
            self.check_token_vault(),
        ]

        health_results = await asyncio.gather(*checks, return_exceptions=True)

        service_names = ["authentication", "fga", "management_api", "token_vault"]

        for service_name, result in zip(service_names, health_results):
            if isinstance(result, Exception):
                result = HealthCheck(
                    service=service_name, status=ServiceStatus.UNHEALTHY, response_time_ms=0, error=str(result)
                )

            # Store in history
            self.health_history[service_name].append(result)

            # Update circuit breaker
            breaker = self.circuit_breakers[service_name]

            if result.status == ServiceStatus.HEALTHY:
                breaker.record_success()
            else:
                breaker.record_failure()

            # Check for alerts
            await self._check_alerts(service_name)

            results[service_name] = result

        self.total_checks += len(service_names)

        return results

    async def check_authentication_service(self) -> HealthCheck:
        """Check Auth0 authentication endpoint"""
        start_time = time.perf_counter()

        try:
            url = f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration"

            response = await self.http_client.get(url)

            response_time_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code == 200:
                data = response.json()

                return HealthCheck(
                    service="authentication",
                    status=ServiceStatus.HEALTHY,
                    response_time_ms=response_time_ms,
                    metadata={
                        "issuer": data.get("issuer"),
                        "endpoints": {
                            "authorization": bool(data.get("authorization_endpoint")),
                            "token": bool(data.get("token_endpoint")),
                            "userinfo": bool(data.get("userinfo_endpoint")),
                        },
                    },
                )
            else:
                self.total_failures += 1
                return HealthCheck(
                    service="authentication",
                    status=ServiceStatus.UNHEALTHY,
                    response_time_ms=response_time_ms,
                    error=f"HTTP {response.status_code}",
                )

        except Exception as e:
            self.total_failures += 1
            response_time_ms = (time.perf_counter() - start_time) * 1000

            return HealthCheck(
                service="authentication",
                status=ServiceStatus.UNHEALTHY,
                response_time_ms=response_time_ms,
                error=str(e),
            )

    async def check_fga_service(self) -> HealthCheck:
        """Check Auth0 FGA service"""
        start_time = time.perf_counter()

        try:
            # Check FGA store endpoint
            url = f"{settings.FGA_API_URL}/stores/{settings.FGA_STORE_ID}"

            headers = {}
            if settings.FGA_CLIENT_ID and settings.FGA_CLIENT_SECRET:
                # Would typically get bearer token here
                pass

            response = await self.http_client.get(url, headers=headers)

            response_time_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code in [200, 401]:  # 401 expected without auth
                return HealthCheck(
                    service="fga",
                    status=ServiceStatus.HEALTHY,
                    response_time_ms=response_time_ms,
                    metadata={"store_id": settings.FGA_STORE_ID},
                )
            else:
                self.total_failures += 1
                return HealthCheck(
                    service="fga",
                    status=ServiceStatus.UNHEALTHY,
                    response_time_ms=response_time_ms,
                    error=f"HTTP {response.status_code}",
                )

        except Exception as e:
            self.total_failures += 1
            response_time_ms = (time.perf_counter() - start_time) * 1000

            return HealthCheck(
                service="fga", status=ServiceStatus.UNHEALTHY, response_time_ms=response_time_ms, error=str(e)
            )

    async def check_management_api(self) -> HealthCheck:
        """Check Auth0 Management API"""
        start_time = time.perf_counter()

        if not settings.AUTH0_MANAGEMENT_API_TOKEN:
            return HealthCheck(
                service="management_api", status=ServiceStatus.UNKNOWN, response_time_ms=0, error="Not configured"
            )

        try:
            url = f"https://{settings.AUTH0_DOMAIN}/api/v2/stats/daily"

            headers = {"Authorization": f"Bearer {settings.AUTH0_MANAGEMENT_API_TOKEN}"}

            response = await self.http_client.get(url, headers=headers)

            response_time_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code == 200:
                return HealthCheck(
                    service="management_api", status=ServiceStatus.HEALTHY, response_time_ms=response_time_ms
                )
            else:
                self.total_failures += 1
                return HealthCheck(
                    service="management_api",
                    status=ServiceStatus.UNHEALTHY,
                    response_time_ms=response_time_ms,
                    error=f"HTTP {response.status_code}",
                )

        except Exception as e:
            self.total_failures += 1
            response_time_ms = (time.perf_counter() - start_time) * 1000

            return HealthCheck(
                service="management_api",
                status=ServiceStatus.UNHEALTHY,
                response_time_ms=response_time_ms,
                error=str(e),
            )

    async def check_token_vault(self) -> HealthCheck:
        """Check Token Vault service"""
        start_time = time.perf_counter()

        if not settings.TOKEN_VAULT_API_URL:
            return HealthCheck(
                service="token_vault", status=ServiceStatus.UNKNOWN, response_time_ms=0, error="Not configured"
            )

        try:
            # Health check endpoint
            url = f"{settings.TOKEN_VAULT_API_URL}/health"

            response = await self.http_client.get(url)

            response_time_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code == 200:
                return HealthCheck(
                    service="token_vault", status=ServiceStatus.HEALTHY, response_time_ms=response_time_ms
                )
            else:
                self.total_failures += 1
                return HealthCheck(
                    service="token_vault",
                    status=ServiceStatus.UNHEALTHY,
                    response_time_ms=response_time_ms,
                    error=f"HTTP {response.status_code}",
                )

        except Exception as e:
            self.total_failures += 1
            response_time_ms = (time.perf_counter() - start_time) * 1000

            return HealthCheck(
                service="token_vault", status=ServiceStatus.UNHEALTHY, response_time_ms=response_time_ms, error=str(e)
            )

    async def _check_alerts(self, service_name: str):
        """Check if alerts should be sent for service"""
        history = list(self.health_history[service_name])

        if len(history) < self.alert_threshold:
            return

        # Check last N checks
        recent_checks = history[-self.alert_threshold :]

        all_unhealthy = all(check.status == ServiceStatus.UNHEALTHY for check in recent_checks)

        if all_unhealthy:
            await self._send_alert(service_name, recent_checks)

    async def _send_alert(self, service_name: str, failed_checks: List[HealthCheck]):
        """Send alert notification"""
        self.alerts_sent += 1

        alert_message = {
            "service": service_name,
            "status": "CRITICAL",
            "consecutive_failures": len(failed_checks),
            "last_error": failed_checks[-1].error,
            "timestamp": time.time(),
        }

        # Send to webhook if configured
        if settings.ISPM_ALERT_WEBHOOK:
            try:
                await self.http_client.post(settings.ISPM_ALERT_WEBHOOK, json=alert_message)
            except Exception as e:
                print(f"❌ Alert webhook failed: {e}")

        print(f"🚨 ALERT: {service_name} - {len(failed_checks)} consecutive failures")

    def get_service_health(self, service_name: str) -> Optional[HealthCheck]:
        """Get latest health check for service"""
        history = self.health_history.get(service_name)

        if not history:
            return None

        return history[-1]

    def get_circuit_breaker_status(self, service_name: str) -> Optional[Dict]:
        """Get circuit breaker status for service"""
        breaker = self.circuit_breakers.get(service_name)

        if not breaker:
            return None

        return {
            "state": breaker.state.value,
            "failure_count": breaker.failure_count,
            "success_count": breaker.success_count,
            "last_failure": breaker.last_failure_time,
            "opened_at": breaker.opened_at,
        }

    def should_use_fallback(self, service_name: str) -> bool:
        """Check if service should use fallback/degraded mode"""
        breaker = self.circuit_breakers.get(service_name)

        if not breaker:
            return False

        return breaker.state == CircuitState.OPEN

    def get_dashboard_data(self) -> Dict:
        """Get data for health dashboard"""
        services_health = {}

        for service_name in self.circuit_breakers.keys():
            latest_check = self.get_service_health(service_name)
            breaker_status = self.get_circuit_breaker_status(service_name)
            history = list(self.health_history[service_name])

            # Calculate uptime
            recent_checks = history[-20:] if len(history) > 20 else history
            healthy_count = sum(1 for check in recent_checks if check.status == ServiceStatus.HEALTHY)
            uptime_percent = (healthy_count / len(recent_checks) * 100) if recent_checks else 0

            # Calculate average response time
            response_times = [
                check.response_time_ms for check in recent_checks if check.status == ServiceStatus.HEALTHY
            ]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0

            services_health[service_name] = {
                "status": latest_check.status.value if latest_check else "unknown",
                "response_time_ms": latest_check.response_time_ms if latest_check else 0,
                "last_check": latest_check.timestamp if latest_check else 0,
                "circuit_breaker": breaker_status,
                "uptime_percent": uptime_percent,
                "avg_response_time_ms": avg_response_time,
                "checks_count": len(history),
            }

        failure_rate = (self.total_failures / max(self.total_checks, 1)) * 100

        return {
            "timestamp": time.time(),
            "services": services_health,
            "global_stats": {
                "total_checks": self.total_checks,
                "total_failures": self.total_failures,
                "failure_rate_percent": failure_rate,
                "alerts_sent": self.alerts_sent,
            },
        }

    async def close(self):
        """Clean up resources"""
        await self.stop_monitoring()
        await self.http_client.aclose()
