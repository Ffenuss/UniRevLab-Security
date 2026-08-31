#!/usr/bin/env python3
import base64
import gzip
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
repo_root = root.parent
main_activity = repo_root / "app/src/main/java/org/unirevlab/security/MainActivity.kt"

BAD_INIT = "remember(context.applicationContext) { AnalysisManager.initialize(context.applicationContext) }"
GOOD_INIT = "remember(context.applicationContext) { AnalysisManager.apply { initialize(context.applicationContext) } }"


def normalize_main_activity() -> bool:
    if not main_activity.is_file():
        return False
    text = main_activity.read_text(encoding="utf-8")
    if BAD_INIT in text:
        main_activity.write_text(text.replace(BAD_INIT, GOOD_INIT, 1), encoding="utf-8")
        print("fixed Compose remember return type in MainActivity")
        return True
    return GOOD_INIT in text


# After a successful CI run the verified app/src patch is committed back to this branch.
# Treat that state as already integrated instead of requiring the original patch to reverse-apply
# byte-for-byte; MainActivity intentionally contains the lint-safe initialization above.
if main_activity.is_file():
    current = main_activity.read_text(encoding="utf-8")
    if "org.unirevlab.security.analysis.AnalysisManager" in current and "AnalysisProgressDialog" in current:
        normalize_main_activity()
        print("v0.22.1 analysis progress/cancel patch already integrated")
        raise SystemExit(0)

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
        normalize_main_activity()
        print("v0.22.1 analysis progress/cancel patch applied")
    else:
        reverse = subprocess.run(["git", "apply", "--reverse", "--check", patch_path])
        if reverse.returncode == 0:
            normalize_main_activity()
            print("v0.22.1 analysis progress/cancel patch already applied")
        else:
            raise SystemExit("v0.22.1 patch state mismatch")
finally:
    os.unlink(patch_path)
