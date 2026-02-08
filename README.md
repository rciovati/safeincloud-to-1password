# README — Safe In Cloud XML → 1Password importer

This script reads an XML export containing `<card>` records and creates one 1Password item per card using the 1Password CLI.
It also base64-decodes embedded `<image>` payloads, saves them locally, and attaches them to the created item as file attachments.

## Requirements
- Python 3.10+ (tested with `python3`).  
- 1Password CLI (`op`) installed and already authenticated (for example via the 1Password app), since the script calls `op item create`.

## Usage
Dry run (prints the commands it would execute):
```bash
python3 import.py export.xml --vault "Private" --dry-run
```

Create items:
```bash
python3 import.py export.xml --vault "Private"
```

## What gets imported
- Title → `--title`  
- Website/URL → `--url` (if present)
- Built-in login fields: username/password (if present)
- Notes → `notesPlain` (if present)
- Remaining `<field>` elements become custom fields:
  - Field name contains “email” → `fieldType=email`
  - Field name contains “password” or “pin” → `fieldType=password` (concealed)
  - Otherwise → `fieldType=text`
- Attachments:
  - `<image>` base64 payloads are decoded to files and attached using `fieldType=file`.

## Options
- `--vault VAULT`: Target vault name/ID.
- `--category CATEGORY`: Item category (default `login`).
- `--attachments-dir DIR`: Where decoded attachments are written (default: a temporary directory).  
- `--tag-groups`: Adds the XML group/label as a 1Password tag.
- `--dry-run`: Print commands without creating items.