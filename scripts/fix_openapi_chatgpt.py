#!/usr/bin/env python3
"""Fix the live OpenAPI schema for ChatGPT Actions.

The original schema used OpenAPI 3.0.3 and incorrectly put the list of
required JSON properties in requestBody.required. ChatGPT's importer expects
OpenAPI 3.1.x and requestBody.required must be a boolean.

Run from the repository root:
    python3 scripts/fix_openapi_chatgpt.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "bridge.py"
text = BRIDGE.read_text(encoding="utf-8")

old = '"required": required,\n            "content": {"application/json": {"schema": {'
new = '"required": True,\n            "content": {"application/json": {"schema": {'
if old not in text:
    raise SystemExit("Could not find requestBody.required block; bridge.py may already be fixed or changed.")
text = text.replace(old, new, 1)

old_version = '"openapi": "3.0.3",'
new_version = '"openapi": "3.1.0",'
if old_version not in text:
    raise SystemExit("Could not find OpenAPI version; bridge.py may already be fixed or changed.")
text = text.replace(old_version, new_version, 1)

BRIDGE.write_text(text, encoding="utf-8")
print("Fixed bridge.py: OpenAPI 3.1.0 + boolean requestBody.required")
