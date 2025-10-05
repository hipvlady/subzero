"""
Comprehensive Feature and Metrics Verification Script
Verifies all claimed features exist and collects actual performance metrics
"""

import asyncio
import importlib
import inspect
import sys
import time
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class FeatureVerifier:
    """Verifies all claimed features in the codebase"""

    def __init__(self):
        self.verified_features = {}
        self.failed_features = {}
        self.performance_metrics = {}

    def verify_mcp_oauth(self):
        """Verify MCP OAuth 2.1 features"""
        try:
            from subzero.services.mcp.oauth import MCPOAuthProvider, GrantType, TokenType

            features = {
                "OAuth 2.1 Authorization Code Flow": hasattr(MCPOAuthProvider, "authorize_agent"),
                "PKCE Support": hasattr(MCPOAuthProvider, "_generate_pkce_challenge"),
                "Dynamic Client Registration (RFC 7591)": hasattr(MCPOAuthProvider, "register_dynamic_client"),
                "Token Exchange (RFC 8693)": hasattr(MCPOAuthProvider, "exchange_token"),
                "Token Introspection (RFC 7662)": hasattr(MCPOAuthProvider, "introspect_token"),
                "DPoP Validation (RFC 9449)": hasattr(MCPOAuthProvider, "validate_dpop_proof"),
                "Metadata Discovery (RFC 8414)": hasattr(MCPOAuthProvider, "get_oauth_metadata"),
                "Client Credentials Flow": "CLIENT_CREDENTIALS" in [g.value for g in GrantType],
                "Refresh Token Flow": "REFRESH_TOKEN" in [g.value for g in GrantType],
            }

            self.verified_features["MCP OAuth 2.1"] = features
            return True
        except Exception as e:
            self.failed_features["MCP OAuth 2.1"] = str(e)
            return False

    def verify_llm_security(self):
        """Verify OWASP LLM Top 10 security features"""
        try:
            from subzero.services.security.llm_security import LLMSecurityGuard, LLMThreatType

            features = {
                "LLM01: Prompt Injection Detection": "PROMPT_INJECTION" in [t.value for t in LLMThreatType],
                "LLM02: Insecure Output Handling": "INSECURE_OUTPUT" in [t.value for t in LLMThreatType],
                "LLM03: Data Poisoning": "DATA_POISONING" in [t.value for t in LLMThreatType],
                "LLM04: DoS Protection": "DOS" in [t.value for t in LLMThreatType],
                "LLM05: Supply Chain": "SUPPLY_CHAIN" in [t.value for t in LLMThreatType],
                "LLM06: Info Disclosure": "INFO_DISCLOSURE" in [t.value for t in LLMThreatType],
                "LLM07: Insecure Plugin": "INSECURE_PLUGIN" in [t.value for t in LLMThreatType],
                "LLM08: Excessive Agency": "EXCESSIVE_AGENCY" in [t.value for t in LLMThreatType],
                "LLM09: Overreliance": "OVERRELIANCE" in [t.value for t in LLMThreatType],
                "LLM10: Model Theft": "MODEL_THEFT" in [t.value for t in LLMThreatType],
                "Input Validation": hasattr(LLMSecurityGuard, "validate_input"),
                "Output Validation": hasattr(LLMSecurityGuard, "validate_output"),
                "Rate Limiting": hasattr(LLMSecurityGuard, "check_rate_limit"),
                "Action Authorization": hasattr(LLMSecurityGuard, "authorize_action"),
                "Model Access Logging": hasattr(LLMSecurityGuard, "log_model_access"),
            }

            self.verified_features["OWASP LLM Security"] = features
            return True
        except Exception as e:
            self.failed_features["OWASP LLM Security"] = str(e)
            return False

    def verify_xaa_protocol(self):
        """Verify XAA Protocol features"""
        try:
            from subzero.services.auth.xaa import XAAProtocol, XAATokenType, AccessScope

            features = {
                "Token Delegation": hasattr(XAAProtocol, "delegate_token"),
                "Bidirectional Communication": hasattr(XAAProtocol, "establish_bidirectional_channel"),
                "Primary Token Type": "PRIMARY" in [t.value for t in XAATokenType],
                "Delegated Token Type": "DELEGATED" in [t.value for t in XAATokenType],
                "Impersonation Token Type": "IMPERSONATION" in [t.value for t in XAATokenType],
                "5 Access Scopes": len(list(AccessScope)) == 5,
                "App Registration": hasattr(XAAProtocol, "register_application"),
            }

            self.verified_features["XAA Protocol"] = features
            return True
        except Exception as e:
            self.failed_features["XAA Protocol"] = str(e)
            return False

    def verify_token_vault(self):
        """Verify Token Vault features"""
        try:
            from subzero.services.auth.vault import Auth0TokenVault, TokenProvider

            features = {
                "Auth0 Token Vault API": True,
                "Google Provider": "GOOGLE" in [p.value for p in TokenProvider],
                "Microsoft Provider": "MICROSOFT" in [p.value for p in TokenProvider],
                "Slack Provider": "SLACK" in [p.value for p in TokenProvider],
                "GitHub Provider": "GITHUB" in [p.value for p in TokenProvider],
                "Box Provider": "BOX" in [p.value for p in TokenProvider],
                "Salesforce Provider": "SALESFORCE" in [p.value for p in TokenProvider],
                "Auth0 Provider": "AUTH0" in [p.value for p in TokenProvider],
                "Okta Provider": "OKTA" in [p.value for p in TokenProvider],
                "Store Token": hasattr(Auth0TokenVault, "store_token"),
                "Retrieve Token": hasattr(Auth0TokenVault, "retrieve_token"),
                "Refresh Token": hasattr(Auth0TokenVault, "refresh_token"),
                "Revoke Token": hasattr(Auth0TokenVault, "revoke_token"),
            }

            self.verified_features["Token Vault"] = features
            return True
        except Exception as e:
            self.failed_features["Token Vault"] = str(e)
            return False

    def verify_authorization(self):
        """Verify ReBAC, ABAC, OPA features"""
        try:
            from subzero.services.authorization.rebac import ReBACEngine
            from subzero.services.authorization.abac import ABACEngine
            from subzero.services.authorization.opa import OPAClient

            features = {
                "ReBAC Engine": True,
                "ReBAC Check": hasattr(ReBACEngine, "check"),
                "ReBAC Expand": hasattr(ReBACEngine, "expand"),
                "ReBAC Batch Check": hasattr(ReBACEngine, "batch_check"),
                "ABAC Engine": True,
                "ABAC Evaluate": hasattr(ABACEngine, "evaluate"),
                "ABAC Risk Calculation": hasattr(ABACEngine, "calculate_risk"),
                "OPA Client": True,
                "OPA Query": hasattr(OPAClient, "query"),
                "OPA Upload Policy": hasattr(OPAClient, "upload_policy"),
            }

            self.verified_features["Authorization (ReBAC/ABAC/OPA)"] = features
            return True
        except Exception as e:
            self.failed_features["Authorization"] = str(e)
            return False

    def verify_ispm(self):
        """Verify ISPM features"""
        try:
            from subzero.services.security.ispm import ISPMEngine

            features = {
                "ISPM Engine": True,
                "Risk Assessment": hasattr(ISPMEngine, "assess_agent_risk"),
                "Auto-Remediation": hasattr(ISPMEngine, "auto_remediate"),
                "Security Posture": hasattr(ISPMEngine, "get_security_posture"),
                "Compliance Check": hasattr(ISPMEngine, "check_compliance"),
            }

            self.verified_features["ISPM"] = features
            return True
        except Exception as e:
            self.failed_features["ISPM"] = str(e)
            return False

    async def measure_performance(self):
        """Measure actual performance metrics"""
        try:
            # Measure ReBAC performance
            from subzero.services.authorization.rebac import ReBACEngine, AuthzTuple

            rebac = ReBACEngine()
            rebac.write_tuple(AuthzTuple("doc", "test", "viewer", "user", "alice"))

            start = time.perf_counter()
            for _ in range(100):
                await rebac.check("doc", "test", "viewer", "user", "alice")
            rebac_latency = ((time.perf_counter() - start) / 100) * 1000

            self.performance_metrics["ReBAC Check Latency (ms)"] = f"{rebac_latency:.2f}"

            # Measure ABAC performance
            from subzero.services.authorization.abac import ABACEngine, AuthorizationContext

            abac = ABACEngine()
            context = AuthorizationContext(user_id="test", user_role="user", resource_id="doc", action="read")

            start = time.perf_counter()
            for _ in range(100):
                await abac.evaluate(context)
            abac_latency = ((time.perf_counter() - start) / 100) * 1000

            self.performance_metrics["ABAC Evaluate Latency (ms)"] = f"{abac_latency:.2f}"

            # Measure LLM Security validation
            from subzero.services.security.llm_security import LLMSecurityGuard

            guard = LLMSecurityGuard()

            start = time.perf_counter()
            for _ in range(1000):
                guard.validate_input("test_agent", "This is a normal user input")
            llm_latency = ((time.perf_counter() - start) / 1000) * 1000

            self.performance_metrics["LLM Input Validation (ms)"] = f"{llm_latency:.3f}"

            return True
        except Exception as e:
            print(f"Performance measurement error: {e}")
            return False

    def print_report(self):
        """Print verification report"""
        print("\n" + "=" * 80)
        print(" " * 20 + "FEATURE VERIFICATION REPORT")
        print("=" * 80 + "\n")

        total_features = 0
        passed_features = 0

        for category, features in self.verified_features.items():
            print(f"\n📦 {category}:")
            print("-" * 80)

            for feature, status in features.items():
                total_features += 1
                if status:
                    passed_features += 1
                    print(f"  ✅ {feature}")
                else:
                    print(f"  ❌ {feature}")

        if self.failed_features:
            print(f"\n\n❌ FAILED CATEGORIES:")
            print("-" * 80)
            for category, error in self.failed_features.items():
                print(f"  {category}: {error}")

        print(f"\n\n🔢 PERFORMANCE METRICS:")
        print("-" * 80)
        for metric, value in self.performance_metrics.items():
            print(f"  📊 {metric}: {value}")

        print(f"\n\n📈 SUMMARY:")
        print("-" * 80)
        print(f"  Total Features Verified: {passed_features}/{total_features}")
        print(f"  Success Rate: {(passed_features/total_features)*100:.1f}%")
        print(f"  Categories Passed: {len(self.verified_features)}")
        print(f"  Categories Failed: {len(self.failed_features)}")

        return passed_features, total_features


async def main():
    """Main verification function"""
    verifier = FeatureVerifier()

    print("\n🔍 Starting comprehensive feature verification...")

    # Verify all feature categories
    verifier.verify_mcp_oauth()
    verifier.verify_llm_security()
    verifier.verify_xaa_protocol()
    verifier.verify_token_vault()
    verifier.verify_authorization()
    verifier.verify_ispm()

    # Measure performance
    await verifier.measure_performance()

    # Print report
    passed, total = verifier.print_report()

    print("\n" + "=" * 80)
    print(" " * 25 + "VERIFICATION COMPLETE")
    print("=" * 80 + "\n")

    return 0 if passed == total else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
