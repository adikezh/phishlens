"""Validate static add-in artifacts without requiring Office or Apps Script."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"add-in validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    outlook = ROOT / "addins" / "outlook"
    gmail_manifest = ROOT / "addins" / "gmail" / "appsscript.json"
    for name in ("icon-64.png", "icon-128.png", "manifest.xml", "taskpane.html", "taskpane.js"):
        path = outlook / name
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing or empty Outlook artifact: {path.relative_to(ROOT)}")

    try:
        ET.parse(outlook / "manifest.xml")
    except ET.ParseError as exc:
        fail(f"invalid Outlook manifest XML: {exc}")

    manifest = json.loads(gmail_manifest.read_text(encoding="utf-8"))
    logo = manifest["addOns"]["common"]["logoUrl"]
    parsed = urlparse(logo)
    if parsed.scheme != "https" or not parsed.netloc or "example.invalid" in logo:
        fail(f"Gmail logoUrl must be a real HTTPS URL: {logo}")

    for name in ("Code.gs", "appsscript.json"):
        if not (ROOT / "addins" / "gmail" / name).is_file():
            fail(f"missing Gmail artifact: addins/gmail/{name}")

    print("add-in artifacts: OK")


if __name__ == "__main__":
    main()
