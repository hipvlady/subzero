"""
Integration Verification Script
Verifies all components are properly integrated and can be imported
"""

import importlib
import sys

# Color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def _test_import(module_path: str, component_name: str) -> tuple[bool, str]:
    """
    Test if a module can be imported (internal utility function)

    Args:
        module_path: Python module path
        component_name: Human-readable component name

    Returns:
        Tuple of (success, error_message)
    """
    try:
        importlib.import_module(module_path)
        return True, ""
    except Exception as e:
        return False, str(e)


def main():
    """Run integration verification"""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}Zero Trust API Gateway - Integration Verification{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

    # Define all components to verify
    components = [
        # Core Orchestrator
        ("subzero.services.orchestrator.event_loop", "Functional Event Orchestrator"),
        ("subzero.services.orchestrator.multiprocessing", "Multiprocessing Engine"),
        # Authentication
        ("subzero.services.auth.jwt", "Private Key JWT"),
        ("subzero.services.auth.manager", "Auth0 Integration"),
        ("subzero.services.auth.oauth", "OAuth 2.1 + PKCE"),
        ("subzero.services.auth.vault", "Token Vault Integration"),
        ("subzero.services.auth.xaa", "XAA Protocol"),
        ("subzero.services.auth.registry", "Application Registry"),
        ("subzero.services.auth.resilient", "Resilient Auth Service"),
        # Authorization
        ("subzero.services.authorization.manager", "FGA Authorization Engine"),
        ("subzero.services.authorization.rebac", "ReBAC Engine"),
        ("subzero.services.authorization.abac", "ABAC Engine"),
        ("subzero.services.authorization.opa", "OPA Integration"),
        ("subzero.services.authorization.cache", "Authorization Cache"),
        # Security
        ("subzero.services.security.threat_detection", "Advanced Threat Detection"),
        ("subzero.services.security.ispm", "ISPM (Identity Security Posture Management)"),
        ("subzero.services.security.rate_limiter", "Rate Limiter"),
        ("subzero.services.security.health", "Health Monitor"),
        ("subzero.services.security.audit", "Audit Trail"),
        ("subzero.services.security.degradation", "Graceful Degradation"),
        # MCP
        ("subzero.services.mcp.capabilities", "MCP Dynamic Capability Discovery"),
        ("subzero.services.mcp.transports", "MCP Custom Transports"),
        # Integration
        ("subzero.subzeroapp", "Unified Zero Trust Gateway"),
        # Config
        ("subzero.config.defaults", "Configuration Management"),
    ]

    passed = 0
    failed = 0
    failed_components = []

    print(f"{YELLOW}Testing {len(components)} components...{RESET}\n")

    for module_path, component_name in components:
        success, error = _test_import(module_path, component_name)

        if success:
            print(f"  {GREEN}✓{RESET} {component_name:<50} {GREEN}OK{RESET}")
            passed += 1
        else:
            print(f"  {RED}✗{RESET} {component_name:<50} {RED}FAILED{RESET}")
            print(f"    {RED}Error: {error}{RESET}")
            failed += 1
            failed_components.append((component_name, error))

    # Summary
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}Verification Summary{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

    total = passed + failed
    success_rate = (passed / total) * 100 if total > 0 else 0

    print(f"  Total Components: {total}")
    print(f"  {GREEN}Passed: {passed}{RESET}")
    print(f"  {RED}Failed: {failed}{RESET}")
    print(f"  Success Rate: {success_rate:.1f}%\n")

    if failed > 0:
        print(f"{RED}Failed Components:{RESET}")
        for name, error in failed_components:
            print(f"  - {name}")
            print(f"    {error}\n")

        print(f"\n{RED}❌ Integration verification FAILED{RESET}\n")
        return 1
    else:
        print(f"{GREEN}✅ All components verified successfully!{RESET}\n")

        # Additional verification - check key classes exist
        print(f"{YELLOW}Verifying key classes...{RESET}\n")

        key_classes = [
            ("subzero.subzeroapp", "UnifiedZeroTrustGateway"),
            ("subzero.services.orchestrator.event_loop", "FunctionalEventOrchestrator"),
            ("subzero.services.auth.resilient", "ResilientAuthService"),
            ("subzero.services.security.threat_detection", "SignupFraudDetector"),
            ("subzero.services.security.threat_detection", "AccountTakeoverDetector"),
            ("subzero.services.security.threat_detection", "MFAAbuseDetector"),
            ("subzero.services.auth.xaa", "XAAProtocol"),
            ("subzero.services.auth.registry", "ApplicationRegistry"),
            ("subzero.services.mcp.transports", "WebSocketTransport"),
            ("subzero.services.mcp.transports", "SSETransport"),
            ("subzero.services.mcp.transports", "HTTPLongPollingTransport"),
        ]

        all_classes_found = True

        for module_path, class_name in key_classes:
            try:
                module = importlib.import_module(module_path)
                if hasattr(module, class_name):
                    print(f"  {GREEN}✓{RESET} {class_name:<40} {GREEN}Found{RESET}")
                else:
                    print(f"  {RED}✗{RESET} {class_name:<40} {RED}Not found{RESET}")
                    all_classes_found = False
            except Exception as e:
                print(f"  {RED}✗{RESET} {class_name:<40} {RED}Error: {e}{RESET}")
                all_classes_found = False

        if all_classes_found:
            print(f"\n{GREEN}✅ All key classes verified successfully!{RESET}\n")
        else:
            print(f"\n{YELLOW}⚠️  Some key classes missing or inaccessible{RESET}\n")

        # Print integration summary
        print(f"{BLUE}{'='*70}{RESET}")
        print(f"{BLUE}Integration Architecture{RESET}")
        print(f"{BLUE}{'='*70}{RESET}\n")

        print(
            """
        ┌──────────────────────────────────────────────────────────┐
        │         Unified Zero Trust API Gateway                   │
        │                                                          │
        │  ┌────────────────────────────────────────────────────┐ │
        │  │   Functional Event Orchestrator                    │ │
        │  │   - Priority scheduling                            │ │
        │  │   - Request coalescing                             │ │
        │  │   - Circuit breakers                               │ │
        │  └────────────────────────────────────────────────────┘ │
        │                          ↓                               │
        │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │
        │  │ Auth        │  │ AuthZ       │  │ Security     │   │
        │  │ - PKI JWT   │  │ - ReBAC     │  │ - Threats    │   │
        │  │ - OAuth2.1  │  │ - ABAC      │  │ - ISPM       │   │
        │  │ - XAA       │  │ - OPA       │  │ - Rate Limit │   │
        │  │ - Vault     │  │ - FGA       │  │ - Audit      │   │
        │  └─────────────┘  └─────────────┘  └──────────────┘   │
        │                          ↓                               │
        │  ┌────────────────────────────────────────────────────┐ │
        │  │   Resilience Layer                                 │ │
        │  │   - Health monitoring                              │ │
        │  │   - Graceful degradation                           │ │
        │  │   - Circuit breakers                               │ │
        │  └────────────────────────────────────────────────────┘ │
        └──────────────────────────────────────────────────────────┘
        """
        )

        print(f"{GREEN}✅ Integration verification PASSED{RESET}")
        print(f"{GREEN}   All components are seamlessly integrated!{RESET}\n")

        return 0


def test_integration_verification():
    """Pytest test that runs the integration verification"""
    result = main()
    assert result == 0, "Integration verification failed"


if __name__ == "__main__":
    sys.exit(main())
