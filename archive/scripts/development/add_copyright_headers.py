#!/usr/bin/env python3
"""
Script to add copyright headers to Markdown documentation files.

Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
"""

import os
from pathlib import Path
from datetime import datetime

COPYRIGHT_HEADER = """<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

"""

def has_copyright(content: str) -> bool:
    """Check if file already has copyright header."""
    return "Copyright (c) Subzero Development Team" in content

def add_copyright_header(file_path: Path) -> bool:
    """Add copyright header to a markdown file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if has_copyright(content):
            print(f"  ⏭️  Skipped (already has copyright): {file_path.name}")
            return False

        # Add copyright header at the beginning
        new_content = COPYRIGHT_HEADER + content

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"  ✅ Added copyright header: {file_path.name}")
        return True
    except Exception as e:
        print(f"  ❌ Error processing {file_path.name}: {e}")
        return False

def main():
    """Main function to process all markdown files."""
    project_root = Path(__file__).parent.parent

    # Files to process
    doc_files = [
        # Root level
        project_root / "readme.md",
        project_root / "CHANGELOG.md",
        project_root / "CONTRIBUTING.md",
        project_root / "SECURITY.md",
        project_root / "DOCUMENTATION_ANALYSIS_REPORT.md",

        # Docs directory
        project_root / "docs" / "architecture.md",
        project_root / "docs" / "api.md",
        project_root / "docs" / "configuration.md",
        project_root / "docs" / "deployment.md",
        project_root / "docs" / "troubleshooting.md",
        project_root / "docs" / "performance.md",
        project_root / "docs" / "examples.md",
        project_root / "docs" / "auth0_setup_guide.md",
        project_root / "docs" / "business_case.md",
        project_root / "docs" / "performance_results.md",
        project_root / "docs" / "ADVANCED_OPTIMIZATIONS.md",
        project_root / "docs" / "BENCHMARK_RESULTS.md",
        project_root / "docs" / "IMPLEMENTATION_SUMMARY.md",
        project_root / "docs" / "FINAL_TEST_REPORT.md",

        # Test docs
        project_root / "tests" / "performance" / "README.md",
    ]

    print("Adding copyright headers to documentation files...\n")

    processed = 0
    skipped = 0

    for file_path in doc_files:
        if file_path.exists():
            if add_copyright_header(file_path):
                processed += 1
            else:
                skipped += 1
        else:
            print(f"  ⚠️  File not found: {file_path.name}")

    print(f"\n✅ Processing complete!")
    print(f"   Added: {processed}")
    print(f"   Skipped: {skipped}")
    print(f"   Total: {processed + skipped}")

if __name__ == "__main__":
    main()
