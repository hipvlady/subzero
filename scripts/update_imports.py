"""
Script to update import statements in migrated files
"""

import os
import re
from pathlib import Path

# Import mapping from old to new structure
IMPORT_MAPPINGS = {
    'from src.auth.private_key_jwt': 'from subzero.services.auth.jwt',
    'from src.auth.auth0_integration': 'from subzero.services.auth.manager',
    'from src.auth.oauth2_pkce': 'from subzero.services.auth.oauth',
    'from src.auth.token_vault_integration': 'from subzero.services.auth.vault',
    'from src.auth.xaa_protocol': 'from subzero.services.auth.xaa',
    'from src.auth.app_registry': 'from subzero.services.auth.registry',
    'from src.auth.resilient_auth_service': 'from subzero.services.auth.resilient',

    'from src.fga.rebac_engine': 'from subzero.services.authorization.rebac',
    'from src.fga.abac_engine': 'from subzero.services.authorization.abac',
    'from src.fga.opa_integration': 'from subzero.services.authorization.opa',
    'from src.fga.authorization_engine': 'from subzero.services.authorization.manager',
    'from src.fga.authorization_cache': 'from subzero.services.authorization.cache',

    'from src.security.advanced_threat_detection': 'from subzero.services.security.threat_detection',
    'from src.security.ispm': 'from subzero.services.security.ispm',
    'from src.security.rate_limiter': 'from subzero.services.security.rate_limiter',
    'from src.security.audit_trail': 'from subzero.services.security.audit',
    'from src.security.health_monitor': 'from subzero.services.security.health',
    'from src.security.graceful_degradation': 'from subzero.services.security.degradation',

    'from src.mcp.custom_transports': 'from subzero.services.mcp.transports',
    'from src.mcp.dynamic_capability_discovery': 'from subzero.services.mcp.capabilities',

    'from src.performance.functional_event_orchestrator': 'from subzero.services.orchestrator.event_loop',
    'from src.performance.cpu_bound_multiprocessing': 'from subzero.services.orchestrator.multiprocessing',

    'from config.settings': 'from subzero.config.defaults',
    'import config.settings': 'import subzero.config.defaults',
}


def update_imports_in_file(file_path: Path):
    """Update imports in a single file"""
    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content

    # Apply all import mappings
    for old_import, new_import in IMPORT_MAPPINGS.items():
        content = content.replace(old_import, new_import)

    # Only write if changes were made
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"✅ Updated: {file_path}")
        return True
    return False


def main():
    """Update imports in all Python files in subzero/ directory"""
    subzero_dir = Path('subzero')

    if not subzero_dir.exists():
        print("❌ Error: subzero/ directory not found")
        return

    updated_count = 0
    total_count = 0

    # Process all Python files
    for py_file in subzero_dir.rglob('*.py'):
        total_count += 1
        if update_imports_in_file(py_file):
            updated_count += 1

    print(f"\n📊 Summary:")
    print(f"   Total files: {total_count}")
    print(f"   Updated: {updated_count}")
    print(f"   Unchanged: {total_count - updated_count}")


if __name__ == '__main__':
    main()