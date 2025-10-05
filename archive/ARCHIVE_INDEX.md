<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Archive Index

This directory contains archived files that are not part of the core open source distribution but are preserved for historical reference and potential future use.

## Archive Date
- **Archived:** 2025-10-05
- **Archived by:** Development Team
- **Reason:** Preparing for open source release

---

## Archived Scripts

### Development Tools (`/archive/scripts/development/`)

Scripts used during development for documentation maintenance and project setup. These are not needed for normal product usage but are preserved for maintenance purposes.

| File | Original Location | Archive Date | Reason | Notes |
|------|------------------|--------------|---------|-------|
| `add_copyright_headers.py` | `scripts/` | 2025-10-05 | Development-only utility | One-time script for adding copyright headers to documentation files. Task completed, no longer needed in production. |
| `add_last_updated.py` | `scripts/` | 2025-10-05 | Development-only utility | One-time script for adding "Last updated" footers to documentation. Task completed, no longer needed in production. |

#### Details: Development Tools

**add_copyright_headers.py**
- **Purpose:** Automated addition of copyright headers to Markdown documentation files
- **Usage:** One-time execution to ensure compliance with license requirements
- **Status:** Task completed on 2025-10-02 (see DOCUMENTATION_COMPLIANCE_SUMMARY.md)
- **Restoration:** Can be restored if bulk copyright header updates are needed in the future
- **Dependencies:** Python 3.11+, pathlib, datetime

**add_last_updated.py**
- **Purpose:** Automated addition of "Last updated" footers to documentation files
- **Usage:** One-time execution to add version footers to docs
- **Status:** Task completed on 2025-10-02 (see DOCUMENTATION_COMPLIANCE_SUMMARY.md)
- **Restoration:** Can be restored if bulk footer updates are needed
- **Dependencies:** Python 3.11+, pathlib, datetime

---

## Restoration Instructions

If you need to restore any archived file:

```bash
# Restore a specific file
git mv archive/scripts/development/filename.py scripts/filename.py

# Or copy without git history
cp archive/scripts/development/filename.py scripts/filename.py
```

---

## Archive Structure

```
archive/
├── ARCHIVE_INDEX.md           # This file
└── scripts/
    ├── deprecated/             # Replaced or obsolete scripts
    ├── development/            # Development-only utilities
    ├── legacy/                 # Old version compatibility scripts
    └── experimental/           # Proof-of-concept scripts
```

---

## Contributing

When archiving new files:

1. Move files using `git mv` to preserve history
2. Update this ARCHIVE_INDEX.md with:
   - File name and original location
   - Archive date
   - Reason for archival
   - Restoration instructions if applicable
3. Specify which archive subdirectory is appropriate
4. Note any dependencies or special considerations

---

**Last updated:** 2025-10-05
