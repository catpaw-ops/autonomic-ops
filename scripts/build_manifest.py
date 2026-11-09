#!/usr/bin/env python3
"""Rebuild the scheduler-core hash manifest (run after an upgrade, never at runtime)."""
import argparse
import os
import sys

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("src", "lib"):
    _path = os.path.join(_here, _sub)
    if os.path.isdir(os.path.join(_path, "autonomic")):
        sys.path.insert(0, _path)
        break

from autonomic.config import load_config
from autonomic.policy import CoreIntegrity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    payload = CoreIntegrity(config).build_manifest()
    print(f"manifest built: {len(payload['files'])} files -> {config.get('codegen.core_manifest')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
