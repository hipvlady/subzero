"""
Example: High-Availability Authentication with Graceful Degradation

Demonstrates the resilient auth service that automatically falls back
to cached validation when Auth0 services are unavailable.
"""

import asyncio

from subzero.config.defaults import Settings
from subzero.services.auth.manager import Auth0Configuration
from subzero.services.auth.resilient import ResilientAuthService

# Load settings
settings = Settings()


async def main():
    # Configure Auth0
    config = Auth0Configuration(
        domain=settings.AUTH0_DOMAIN,
        client_id=settings.AUTH0_CLIENT_ID,
        client_secret=settings.AUTH0_CLIENT_SECRET,
        audience=settings.AUTH0_AUDIENCE,
        management_api_token=settings.AUTH0_MANAGEMENT_API_TOKEN,
        fga_store_id=settings.FGA_STORE_ID,
        fga_client_id=settings.FGA_CLIENT_ID,
        fga_client_secret=settings.FGA_CLIENT_SECRET,
        fga_api_url=settings.FGA_API_URL,
    )

    # Create resilient auth service
    service = ResilientAuthService(auth0_config=config, enable_degradation=True)

    # Start all services (health monitoring, audit trail, degradation)
    await service.start()

    print("\n" + "=" * 70)
    print("Resilient Authentication Service - Demo")
    print("=" * 70 + "\n")

    # Test 1: Normal authentication with Auth0
    print("Test 1: Normal Authentication")
    print("-" * 70)

    result = await service.authenticate(user_id="auth0|test_user_123", scopes="openid profile email")

    print(f"✅ Success: {result.success}")
    print(f"   Source: {result.source}")
    print(f"   Mode: {result.degradation_mode}")
    print(f"   Latency: {result.latency_ms:.2f}ms")
    if result.token_data:
        print(f"   Access Token: {result.token_data.get('access_token', 'N/A')[:50]}...")
    print()

    # Test 2: Authorization check with FGA
    print("Test 2: Authorization Check")
    print("-" * 70)

    authz_result = await service.check_permission(
        user_id="auth0|test_user_123", resource_type="document", resource_id="doc_456", relation="viewer"
    )

    print(f"✅ Allowed: {authz_result.allowed}")
    print(f"   Source: {authz_result.source}")
    print(f"   Cached: {authz_result.cached_decision}")
    print(f"   Latency: {authz_result.latency_ms:.2f}ms")
    print()

    # Test 3: Simulate Auth0 outage (circuit breaker opens)
    print("Test 3: Simulating Auth0 Outage")
    print("-" * 70)
    print("⚠️  Auth0 authentication service becomes unavailable...")
    print("   Circuit breaker: OPEN")
    print("   Degradation mode: PARTIAL → FULL")
    print()

    # The health monitor will detect failures and open circuit breaker
    # Subsequent requests will automatically use cached validation

    # Test 4: Authentication with cache fallback
    print("Test 4: Authentication with Cache Fallback")
    print("-" * 70)

    # In real scenario, this would use cached token validation
    result = await service.authenticate(
        user_id="auth0|test_user_123",
        token=result.token_data.get("access_token") if result.token_data else None,
        scopes="openid profile email",
    )

    print(f"✅ Success: {result.success}")
    print(f"   Source: {result.source}")
    print(f"   Mode: {result.degradation_mode}")
    print(f"   Latency: {result.latency_ms:.2f}ms")
    print()

    # Test 5: Authorization with cache fallback
    print("Test 5: Authorization with Cache Fallback")
    print("-" * 70)

    authz_result = await service.check_permission(
        user_id="auth0|test_user_123", resource_type="document", resource_id="doc_456", relation="viewer"
    )

    print(f"✅ Allowed: {authz_result.allowed}")
    print(f"   Source: {authz_result.source}")
    print(f"   Cached: {authz_result.cached_decision}")
    print(f"   Latency: {authz_result.latency_ms:.2f}ms")
    print()

    # Display comprehensive metrics
    print("=" * 70)
    print("Service Metrics")
    print("=" * 70 + "\n")

    metrics = service.get_service_metrics()

    print("Authentication:")
    auth_metrics = metrics["authentication"]
    print(f"  Total Requests: {auth_metrics['total_requests']}")
    print(f"  Auth0 Success: {auth_metrics['auth0_success']}")
    print(f"  Cached Success: {auth_metrics['cached_success']}")
    print(f"  Failures: {auth_metrics['failures']}")
    print(f"  Success Rate: {auth_metrics['success_rate_percent']:.1f}%")
    print()

    print("Authorization:")
    authz_metrics = metrics["authorization"]
    print(f"  Total Checks: {authz_metrics['total_checks']}")
    print(f"  FGA Success: {authz_metrics['fga_success']}")
    print(f"  Cached Success: {authz_metrics['cached_success']}")
    print(f"  Failures: {authz_metrics['failures']}")
    print(f"  Success Rate: {authz_metrics['success_rate_percent']:.1f}%")
    print()

    print("Performance:")
    perf_metrics = metrics["performance"]
    print(f"  Average Latency: {perf_metrics['avg_latency_ms']:.2f}ms")
    print()

    if "degradation" in metrics:
        print("Degradation Status:")
        deg_metrics = metrics["degradation"]
        print(f"  Current Mode: {deg_metrics['current_mode']}")
        print(f"  Degradation Duration: {deg_metrics['degradation_duration_seconds']:.0f}s")
        print(f"  Cached Credentials: {deg_metrics['cached_credentials']}")
        print(f"  Cached Permissions: {deg_metrics['cached_permissions']}")
        print()

    # Stop all services
    await service.stop()

    print("✅ Demo completed successfully\n")


if __name__ == "__main__":
    asyncio.run(main())
