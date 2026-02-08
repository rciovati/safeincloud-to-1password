#!/usr/bin/env python3
"""
Import Safe In Cloud XMLs into 1Password via `op item create`.

- Creates one 1Password item per <card>.
- Decodes each <image> tag (base64) into a file and attaches it to the item.

Requires:
  - 1Password CLI (`op`) installed and authenticated.

Inspired by https://gitlab.com/bdeeming/safe-in-cloud-to-csv
"""

import argparse
import base64
import binascii
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

def custom_field_type_for(name: str) -> str:
    n = (name or "").strip().lower()

    if "email" in n:
        return "email"

    if ("password" in n) or re.search(r"(^|[^a-z0-9])pin([^a-z0-9]|$)", n) or ("secret" in n):
        return "password"

    if ("website" in n):
        return "url"

    return "text"

def is_blank(s: str | None) -> bool:
    return s is None or str(s).strip() == ""

def escape_assignment_name(s: str) -> str:
    # 1Password CLI assignment statements require escaping periods, equal signs, and backslashes in names.
    # (Value must NOT be escaped.)
    return s.replace("\\", "\\\\").replace(".", "\\.").replace("=", "\\=")

def safe_filename(s: str, max_len: int = 80) -> str:
    s = re.sub(r"[^\w.\-]+", "_", s.strip())
    return (s[:max_len] or "attachment")

def guess_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif"
    if data.startswith(b"%PDF-"):
        return ".pdf"
    return ".png"

def decode_base64_payload(b64: str) -> bytes:
    """Decode base64 payload with fallback for non-strict padding."""
    b64_compact = "".join(b64.split())
    try:
        return base64.b64decode(b64_compact, validate=True)
    except binascii.Error:
        # Fallback: some exports aren't strictly padded/validated
        return base64.b64decode(b64_compact + "===")

def process_attachment(
    attachments_dir: Path,
    element: ET.Element,
    assignments: list[str],
    filename: str | None = None,
    auto_detect_ext: bool = False,
    prefix: str = "",
    index: int = 1
) -> bool:
    """
    Decode base64 from element, save to file, and create assignment.

    Returns True if successful, False if element had no base64 content.
    """
    b64 = (element.text or "").strip()
    if not b64:
        return False

    data = decode_base64_payload(b64)

    # Determine output filename
    if filename:
        # Use provided filename, sanitize it
        safe_name = safe_filename(filename)
    else:
        # Generate filename with extension detection
        ext = guess_extension(data) if auto_detect_ext else ""
        base = safe_filename(f"{prefix}_{index}")
        safe_name = f"{base}{ext}"

    out_path = attachments_dir / safe_name
    out_path.write_bytes(data)

    attach_name = escape_assignment_name(safe_name)
    assignments.append(f"{attach_name}[file]={str(out_path)}")

    return True


def run_op_create_item(vault: str | None, category: str, title: str, url: str | None,
                       tags: list[str], assignments: list[str], dry_run: bool) -> None:
    cmd = ["op", "item", "create", "--category", category, "--title", title]

    if vault:
        cmd += ["--vault", vault]
    if url:
        cmd += ["--url", url]
    if tags:
        cmd += ["--tags", ",".join(tags)]

    cmd += assignments

    if dry_run:
        print("DRY RUN:", " ".join(cmd))
        return

    # Note: assignment statements include secrets on the command line.
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"op item create failed for '{title}'.\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    # CLI output varies; printing stdout helps with debugging / getting item IDs.
    if res.stdout.strip():
        print(res.stdout.strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_xml", help="Path to the XML export file")
    ap.add_argument("--vault", help="1Password vault name or ID (optional)")
    ap.add_argument("--category", default="login", help="1Password item category (default: login)")
    ap.add_argument("--attachments-dir", default=None,
                    help="Directory to write decoded images into (default: temp dir)")
    ap.add_argument("--tag-groups", action="store_true",
                    help="If set, map the XML Group name to a 1Password tag")
    ap.add_argument("--dry-run", action="store_true", help="Print op commands; don't create items")
    args = ap.parse_args()

    input_path = Path(args.input_xml)
    root = ET.parse(input_path).getroot()

    # Remove deleted cards
    for card in root.findall("./card[@deleted='true']"):
        root.remove(card)
        print("Removed:", card.attrib.get("title", "<no title>"))

    # Groups (labels)
    groups = {label.attrib["id"]: label.attrib.get("name", "") for label in root.findall("./label")}

    # Attachment output location
    temp_dir_ctx = None
    if args.attachments_dir:
        attachments_dir = Path(args.attachments_dir)
        attachments_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir_ctx = tempfile.TemporaryDirectory(prefix="op_import_")
        attachments_dir = Path(temp_dir_ctx.name)

    try:
        for card in root.findall("./card"):
            # Skip template cards
            if card.get("template") == "true":
                title = (card.attrib.get("title") or "Untitled").strip()
                print("Skipping template card:", title)
                continue

            title = card.attrib.get("title", "").strip() or "Untitled"
            print("Importing card:", title)

            login = card.find("./field[@type='login']")
            password = card.find("./field[@type='password']")
            website = card.find("./field[@type='website']")
            notes = card.find("./notes")
            group_id = card.find("./label_id")

            # Collect ALL <image> tags (not just one)
            images = card.findall("./image")

            # Collect ALL <file> tags with base64 payloads
            files = card.findall("./file")

            # Build op assignment statements
            assignments: list[str] = []

            if login is not None and login.text:
                assignments.append(f"username={login.text}")
                card.remove(login)

            if password is not None and password.text:
                assignments.append(f"password={password.text}")
                card.remove(password)

            if notes is not None and notes.text:
                # notesPlain is the built-in notes field for templates/assignments on many item types
                assignments.append(f"notesPlain={notes.text}")

            url_value = website.text.strip() if (website is not None and website.text) else None
            if website is not None:
                card.remove(website)

            # Remaining <field> entries become custom text fields
            for field in card.findall("./field"):
                name = field.attrib.get("name", "").strip()
                value = field.text or ""
                if not name or is_blank(value):
                    continue
                # Prefix to avoid collisions like the original script did
                label = "S:" + name
                escaped_label = escape_assignment_name(label)
                field_type = custom_field_type_for(name)
                assignments.append(f"{escaped_label}[{field_type}]={value}")

            # Template cards: tag them and fill empty fields with "-"
            tags: list[str] = []
            if card.get("template") == "true":
                tags.append("Templates")
                for field in card.findall("./field"):
                    name = field.attrib.get("name", "").strip()
                    if not name:
                        continue
                    label = "S:" + name
                    escaped_label = escape_assignment_name(label)
                    assignments.append(f"{escaped_label}[text]=-")

            # Optionally map group/label to a tag
            if args.tag_groups and group_id is not None and group_id.text in groups:
                gname = (groups.get(group_id.text) or "").strip()
                if gname:
                    tags.append(gname)

            # Decode & attach each image (auto-detect format)
            for idx, img in enumerate(images, start=1):
                if process_attachment(
                    attachments_dir=attachments_dir,
                    element=img,
                    assignments=assignments,
                    auto_detect_ext=True,
                    prefix=title,
                    index=idx
                ):
                    # Remove the tag to avoid duplicating base64 into text fields
                    card.remove(img)

            # Decode & attach each file (use provided filename)
            for idx, file_elem in enumerate(files, start=1):
                filename = file_elem.attrib.get("name", "").strip() or f"file_{idx}"
                if process_attachment(
                    attachments_dir=attachments_dir,
                    element=file_elem,
                    assignments=assignments,
                    filename=filename
                ):
                    # Remove the tag to avoid duplicating base64 into text fields
                    card.remove(file_elem)

            run_op_create_item(
                vault=args.vault,
                category=args.category,
                title=title,
                url=url_value,
                tags=tags,
                assignments=assignments,
                dry_run=args.dry_run,
            )

        print("Complete")
        return 0
    finally:
        if temp_dir_ctx is not None:
            temp_dir_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
