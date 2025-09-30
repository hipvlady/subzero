"""
Verify the new production-ready directory structure
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test that all core modules can be imported"""
    print("\n🔍 Testing module imports...")

    successes = []
    failures = []

    # Test version import
    try:
        from subzero import __version__, version_info
        successes.append("✅ subzero.__version__")
    except Exception as e:
        failures.append(f"❌ subzero.__version__: {e}")

    # Test orchestrator
    try:
        from subzero.services.orchestrator.event_loop import FunctionalEventOrchestrator
        successes.append("✅ FunctionalEventOrchestrator")
    except Exception as e:
        failures.append(f"❌ FunctionalEventOrchestrator: {e}")

    # Test auth services
    try:
        from subzero.services.auth.jwt import PrivateKeyJWT
        successes.append("✅ PrivateKeyJWT")
    except Exception as e:
        failures.append(f"❌ PrivateKeyJWT: {e}")

    try:
        from subzero.services.auth.oauth import OAuth2PKCEAuthenticator
        successes.append("✅ OAuth2PKCEAuthenticator")
    except Exception as e:
        failures.append(f"❌ OAuth2PKCEAuthenticator: {e}")

    # Test authorization engines
    try:
        from subzero.services.authorization.rebac import ReBACEngine
        successes.append("✅ ReBACEngine")
    except Exception as e:
        failures.append(f"❌ ReBACEngine: {e}")

    try:
        from subzero.services.authorization.abac import ABACEngine
        successes.append("✅ ABACEngine")
    except Exception as e:
        failures.append(f"❌ ABACEngine: {e}")

    try:
        from subzero.services.authorization.opa import PolicyEngine
        successes.append("✅ PolicyEngine (OPA)")
    except Exception as e:
        failures.append(f"❌ PolicyEngine: {e}")

    # Test security services
    try:
        from subzero.services.security.threat_detection import SignupFraudDetector
        successes.append("✅ SignupFraudDetector")
    except Exception as e:
        failures.append(f"❌ SignupFraudDetector: {e}")

    # Test MCP
    try:
        from subzero.services.mcp.transports import TransportFactory
        successes.append("✅ TransportFactory (MCP)")
    except Exception as e:
        failures.append(f"❌ TransportFactory: {e}")

    # Print results
    print(f"\n📊 Import Test Results:")
    print(f"   ✅ Successful: {len(successes)}")
    print(f"   ❌ Failed: {len(failures)}")

    if successes:
        print("\n✅ Successful imports:")
        for s in successes:
            print(f"   {s}")

    if failures:
        print("\n❌ Failed imports:")
        for f in failures:
            print(f"   {f}")

    return len(failures) == 0


def test_structure():
    """Test that directory structure is correct"""
    print("\n🔍 Testing directory structure...")

    expected_dirs = [
        "subzero",
        "subzero/base",
        "subzero/config",
        "subzero/services",
        "subzero/services/auth",
        "subzero/services/authorization",
        "subzero/services/security",
        "subzero/services/mcp",
        "subzero/services/orchestrator",
        "subzero/client",
        "subzero/utils",
        "tests/unit",
        "tests/integration",
        "tests/performance",
        "tests/security",
        "etc/docker",
        "etc/kubernetes",
        "docs",
    ]

    missing = []
    found = []

    root = Path(__file__).parent.parent

    for dir_path in expected_dirs:
        full_path = root / dir_path
        if full_path.exists():
            found.append(f"✅ {dir_path}")
        else:
            missing.append(f"❌ {dir_path}")

    print(f"\n📊 Directory Structure:")
    print(f"   ✅ Found: {len(found)}/{len(expected_dirs)}")
    print(f"   ❌ Missing: {len(missing)}/{len(expected_dirs)}")

    if missing:
        print("\n❌ Missing directories:")
        for m in missing:
            print(f"   {m}")

    return len(missing) == 0


def test_key_files():
    """Test that key files exist"""
    print("\n🔍 Testing key files...")

    expected_files = [
        "subzero/__init__.py",
        "subzero/_version.py",
        "subzero/subzeroapp.py",
        "subzero/config/defaults.py",
        "subzero/services/auth/jwt.py",
        "subzero/services/auth/oauth.py",
        "subzero/services/auth/xaa.py",
        "subzero/services/auth/vault.py",
        "subzero/services/authorization/rebac.py",
        "subzero/services/authorization/abac.py",
        "subzero/services/authorization/opa.py",
        "subzero/services/security/threat_detection.py",
        "subzero/services/security/ispm.py",
        "subzero/services/security/rate_limiter.py",
        "subzero/services/mcp/transports.py",
        "subzero/services/orchestrator/event_loop.py",
    ]

    missing = []
    found = []

    root = Path(__file__).parent.parent

    for file_path in expected_files:
        full_path = root / file_path
        if full_path.exists():
            found.append(f"✅ {file_path}")
        else:
            missing.append(f"❌ {file_path}")

    print(f"\n📊 Key Files:")
    print(f"   ✅ Found: {len(found)}/{len(expected_files)}")
    print(f"   ❌ Missing: {len(missing)}/{len(expected_files)}")

    if missing:
        print("\n❌ Missing files:")
        for m in missing:
            print(f"   {m}")

    return len(missing) == 0


def main():
    """Run all verification tests"""
    print("=" * 70)
    print("🔍 Subzero Production Structure Verification")
    print("=" * 70)

    structure_ok = test_structure()
    files_ok = test_key_files()
    imports_ok = test_imports()

    print("\n" + "=" * 70)

    if structure_ok and files_ok and imports_ok:
        print("✅ ALL VERIFICATION TESTS PASSED!")
        print("=" * 70)
        return 0
    else:
        print("❌ SOME VERIFICATION TESTS FAILED")
        print("=" * 70)
        return 1


if __name__ == '__main__':
    sys.exit(main())