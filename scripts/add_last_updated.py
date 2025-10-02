#!/usr/bin/env python3
"""
Script to add 'Last updated' footers to documentation files.

Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
"""

from pathlib import Path
from datetime import datetime

FOOTER_TEMPLATE = "\n\n---\n\n**Last updated:** {date}\n"

def has_last_updated(content: str) -> bool:
    """Check if file already has 'Last updated' footer."""
    return "**Last updated:**" in content or "Last updated:" in content

def add_last_updated_footer(file_path: Path, date: str = None) -> bool:
    """Add 'Last updated' footer to a markdown file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if has_last_updated(content):
            print(f"  ⏭️  Skipped (already has footer): {file_path.name}")
            return False

        # Use provided date or today's date
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")

        # Remove trailing whitespace and add footer
        content = content.rstrip() + FOOTER_TEMPLATE.format(date=date)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"  ✅ Added footer: {file_path.name}")
        return True
    except Exception as e:
        print(f"  ❌ Error processing {file_path.name}: {e}")
        return False

def main():
    """Main function to add footers to documentation files."""
    project_root = Path(__file__).parent.parent
    today = datetime.now().strftime("%Y-%m-%d")

    # Files to process with their dates
    doc_files = {
        # Root level
        project_root / "readme.md": today,
        project_root / "CHANGELOG.md": today,
        project_root / "CONTRIBUTING.md": today,
        project_root / "SECURITY.md": today,

        # Core docs (use today for consistency)
        project_root / "docs" / "architecture.md": today,
        project_root / "docs" / "configuration.md": today,
        project_root / "docs" / "deployment.md": today,
        project_root / "docs" / "examples.md": today,
    }

    print(f"Adding 'Last updated' footers to documentation files (date: {today})...\n")

    processed = 0
    skipped = 0

    for file_path, date in doc_files.items():
        if file_path.exists():
            if add_last_updated_footer(file_path, date):
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
