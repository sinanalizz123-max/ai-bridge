#!/usr/bin/env python3
"""
Export the ai-bridge OpenAPI 3.0 schema to openapi/example.json.

The live server mounts the same schema at  GET /<token>/openapi.json  with the
real token embedded in the server URL. This exporter writes an auditable copy
using a placeholder token so no secret ever lands in the repository.

Usage:
    python3 scripts/export_openapi.py [output_path]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge  # noqa: E402  (module-level config dirs are harmless)

HOST_PLACEHOLDER = "your-tunnel-host:443"
TOKEN_PLACEHOLDER = "TOKEN_PLACEHOLDER"


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "openapi", "example.json")
    cfg = dict(bridge.get_config())
    cfg["token"] = TOKEN_PLACEHOLDER
    spec = bridge._openapi(cfg, HOST_PLACEHOLDER)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2)
    print("wrote %s" % out)
    print("server URL: %s" % spec["servers"][0]["url"])


if __name__ == "__main__":
    main()