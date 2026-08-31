#!/usr/bin/env python3
import base64
import gzip
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
payload = "".join(
    (root / f"v0221_patch_{index}.b64").read_text(encoding="utf-8").strip()
    for index in range(1, 5)
)
patch = gzip.decompress(base64.b64decode(payload))

with tempfile.NamedTemporaryFile(delete=False, suffix=".patch") as handle:
    handle.write(patch)
    patch_path = handle.name

try:
    forward = subprocess.run(["git", "apply", "--check", patch_path])
    if forward.returncode == 0:
        subprocess.run(["git", "apply", patch_path], check=True)
        print("v0.22.1 analysis progress/cancel patch applied")
    else:
        reverse = subprocess.run(["git", "apply", "--reverse", "--check", patch_path])
        if reverse.returncode == 0:
            print("v0.22.1 analysis progress/cancel patch already applied")
        else:
            raise SystemExit("v0.22.1 patch state mismatch")
finally:
    os.unlink(patch_path)
