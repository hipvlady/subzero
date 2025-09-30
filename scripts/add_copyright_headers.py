"""
Script to add copyright headers to all Python files
Follows enterprise standards with proper license information
"""

import os
from pathlib import Path
from datetime import datetime


COPYRIGHT_HEADER = '''"""
Copyright (c) {year} Subzero Contributors
SPDX-License-Identifier: MIT

{description}
"""

'''

SHORT_COPYRIGHT = '''"""
Copyright (c) {year} Subzero Contributors
SPDX-License-Identifier: MIT
"""

'''


def extract_module_description(content: str) -> str:
    """Extract existing module docstring if present"""
    # Check if file starts with a docstring
    lines = content.strip().split('\n')

    if not lines:
        return ""

    # Look for triple-quoted docstring
    if lines[0].strip().startswith('"""') or lines[0].strip().startswith("'''"):
        quote = '"""' if lines[0].strip().startswith('"""') else "'''"

        # Single line docstring
        if lines[0].strip().endswith(quote) and len(lines[0].strip()) > 6:
            return lines[0].strip()[3:-3].strip()

        # Multi-line docstring
        docstring_lines = []
        in_docstring = True
        for i in range(1, len(lines)):
            if quote in lines[i]:
                break
            docstring_lines.append(lines[i])

        return '\n'.join(docstring_lines).strip()

    return ""


def has_copyright_header(content: str) -> bool:
    """Check if file already has copyright header"""
    first_lines = '\n'.join(content.split('\n')[:5])
    return 'Copyright' in first_lines or 'SPDX-License-Identifier' in first_lines


def remove_old_docstring(content: str) -> str:
    """Remove old module docstring to replace with copyright + description"""
    lines = content.strip().split('\n')

    if not lines:
        return content

    # Check if starts with docstring
    if lines[0].strip().startswith('"""') or lines[0].strip().startswith("'''"):
        quote = '"""' if lines[0].strip().startswith('"""') else "'''"

        # Single line docstring
        if lines[0].strip().endswith(quote) and len(lines[0].strip()) > 6:
            return '\n'.join(lines[1:]).lstrip('\n')

        # Multi-line docstring
        for i in range(1, len(lines)):
            if quote in lines[i]:
                return '\n'.join(lines[i+1:]).lstrip('\n')

    return content


def add_copyright_to_file(file_path: Path, year: int = None) -> bool:
    """Add copyright header to a Python file"""
    if year is None:
        year = datetime.now().year

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Error reading {file_path}: {e}")
        return False

    # Skip if already has copyright
    if has_copyright_header(content):
        print(f"⏭️  Skipped (has copyright): {file_path}")
        return True

    # Extract description from existing docstring
    description = extract_module_description(content)

    # Remove old docstring
    content_without_docstring = remove_old_docstring(content)

    # Create new header with description if available
    if description:
        header = COPYRIGHT_HEADER.format(year=year, description=description)
    else:
        header = SHORT_COPYRIGHT.format(year=year)

    # Combine header with rest of content
    new_content = header + content_without_docstring

    # Write back
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"✅ Added copyright: {file_path}")
        return True
    except Exception as e:
        print(f"❌ Error writing {file_path}: {e}")
        return False


def process_directory(directory: Path, year: int = None):
    """Process all Python files in directory recursively"""
    python_files = list(directory.rglob('*.py'))

    print(f"\n📁 Processing directory: {directory}")
    print(f"   Found {len(python_files)} Python files\n")

    success_count = 0
    skip_count = 0
    error_count = 0

    for py_file in python_files:
        result = add_copyright_to_file(py_file, year)
        if result:
            if has_copyright_header(open(py_file).read()):
                success_count += 1
        else:
            error_count += 1

    print(f"\n📊 Summary:")
    print(f"   Total files: {len(python_files)}")
    print(f"   ✅ Updated: {success_count}")
    print(f"   ❌ Errors: {error_count}")
    print(f"   ⏭️  Skipped: {len(python_files) - success_count - error_count}")


def main():
    """Main entry point"""
    subzero_dir = Path('subzero')

    if not subzero_dir.exists():
        print("❌ Error: subzero/ directory not found")
        return 1

    print("=" * 70)
    print("📄 Adding Copyright Headers to Subzero Package")
    print("=" * 70)

    process_directory(subzero_dir, year=2025)

    print("\n" + "=" * 70)
    print("✅ Copyright header addition complete!")
    print("=" * 70)

    return 0


if __name__ == '__main__':
    exit(main())