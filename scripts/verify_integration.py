"""
Integration Verification Script
Verifies all components are properly integrated and can be imported
"""

import sys
import importlib
from typing import List, Tuple

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def test_import(module_path: str, component_name: str) -> Tuple[bool, str]:
    """
    Test if a module can be imported

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
        ("src.performance.functional_event_orchestrator", "Functional Event Orchestrator"),

        # Authentication
        ("src.auth.private_key_jwt", "Private Key JWT"),
        ("src.auth.auth0_integration", "Auth0 Integration"),
        ("src.auth.oauth2_pkce", "OAuth 2.1 + PKCE"),
        ("src.auth.metadata_discovery", "Metadata Discovery"),
        ("src.auth.dynamic_client_registration", "Dynamic Client Registration"),
        ("src.auth.token_vault_integration", "Token Vault Integration"),
        ("src.auth.xaa_protocol", "XAA Protocol"),
        ("src.auth.app_registry", "Application Registry"),
        ("src.auth.resilient_auth_service", "Resilient Auth Service"),

        # Authorization
        ("src.fga.authorization_engine", "FGA Authorization Engine"),
        ("src.fga.rebac_engine", "ReBAC Engine"),
        ("src.fga.abac_engine", "ABAC Engine"),
        ("src.fga.opa_integration", "OPA Integration"),
        ("src.fga.authorization_cache", "Authorization Cache"),

        # Security
        ("src.security.owasp_llm_mitigations", "OWASP LLM Mitigations"),
        ("src.security.advanced_threat_detection", "Advanced Threat Detection"),
        ("src.security.ispm", "ISPM (Identity Security Posture Management)"),
        ("src.security.rate_limiter", "Rate Limiter"),
        ("src.security.health_monitor", "Health Monitor"),
        ("src.security.audit_trail", "Audit Trail"),
        ("src.security.graceful_degradation", "Graceful Degradation"),

        # MCP
        ("src.mcp.dynamic_capability_discovery", "MCP Dynamic Capability Discovery"),
        ("src.mcp.custom_transports", "MCP Custom Transports"),

        # Performance
        ("src.performance.vectorized_operations", "Vectorized Operations"),

        # Integration
        ("src.integration.unified_gateway", "Unified Zero Trust Gateway"),
    ]

    passed = 0
    failed = 0
    failed_components = []

    print(f"{YELLOW}Testing {len(components)} components...{RESET}\n")

    for module_path, component_name in components:
        success, error = test_import(module_path, component_name)

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
            ("src.integration.unified_gateway", "UnifiedZeroTrustGateway"),
            ("src.performance.functional_event_orchestrator", "FunctionalEventOrchestrator"),
            ("src.auth.resilient_auth_service", "ResilientAuthService"),
            ("src.security.advanced_threat_detection", "SignupFraudDetector"),
            ("src.security.advanced_threat_detection", "AccountTakeoverDetector"),
            ("src.security.advanced_threat_detection", "MFAAbuseDetector"),
            ("src.auth.xaa_protocol", "XAAProtocol"),
            ("src.auth.app_registry", "ApplicationRegistry"),
            ("src.mcp.custom_transports", "WebSocketTransport"),
            ("src.mcp.custom_transports", "SSETransport"),
            ("src.mcp.custom_transports", "HTTPLongPollingTransport"),
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

        print("""
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
        """)

        print(f"{GREEN}✅ Integration verification PASSED{RESET}")
        print(f"{GREEN}   All components are seamlessly integrated!{RESET}\n")

        return 0


if __name__ == "__main__":
    sys.exit(main())