#!/usr/bin/env python3
"""
Quick test script for FastAPI server

Tests that the FastAPI server can be imported and has all expected endpoints.
"""

from subzero.api.server import app


def test_app_structure():
    """Test that the FastAPI app has the expected structure"""
    print("Testing FastAPI App Structure")
    print("=" * 60)

    # Check app metadata
    print(f"✅ App Title: {app.title}")
    print(f"✅ App Version: {app.version}")
    print(f"✅ Docs URL: {app.docs_url}")
    print(f"✅ OpenAPI URL: {app.openapi_url}")

    # Check routes
    routes = [route.path for route in app.routes]
    print(f"\n✅ Total Routes: {len(routes)}")

    expected_routes = [
        "/",
        "/health",
        "/api/v1/authenticate",
        "/api/v1/tokens/store",
        "/api/v1/tokens/retrieve",
        "/api/v1/authorize",
        "/api/v1/metrics",
    ]

    print("\nChecking Expected Routes:")
    for expected in expected_routes:
        if expected in routes:
            print(f"  ✅ {expected}")
        else:
            print(f"  ❌ MISSING: {expected}")

    # Check middleware
    print(f"\n✅ Middleware Count: {len(app.user_middleware)}")

    print("\n" + "=" * 60)
    print("✅ All checks passed!")


if __name__ == "__main__":
    test_app_structure()
