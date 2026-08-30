#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
printf 'synthetic-apk\n' > "$TMP/app-release.apk"
printf 'synthetic-aab\n' > "$TMP/app-release.aab"
cat > "$TMP/signer.txt" <<'SIGNER'
Signer #1 certificate SHA-256 digest: 0000000000000000000000000000000000000000000000000000000000000000
SIGNER
cat > "$TMP/toolchain.json" <<'JSON'
{
  "generatedAt": "1970-01-01T00:00:00Z",
  "schemaVersion": "1.0",
  "sourceDateEpoch": 0,
  "toolchain": {
    "androidBuildTools": "36.0.0",
    "androidNdk": "28.2.13676358",
    "androidPlatform": "37",
    "apksigner": "synthetic",
    "cargo": "synthetic",
    "cargoNdk": "synthetic",
    "ghidra": "12.1.3",
    "gradle": "9.5.0",
    "java": "17",
    "rustc": "synthetic",
    "sdkmanager": "synthetic"
  }
}
JSON
SOURCE_DATE_EPOCH=0 python "$ROOT/scripts/make_release_manifest.py" \
  --root "$ROOT" \
  --apk "$TMP/app-release.apk" \
  --aab "$TMP/app-release.aab" \
  --signer-report "$TMP/signer.txt" \
  --toolchain-report "$TMP/toolchain.json" \
  --commit 0000000000000000000000000000000000000000 \
  --out "$TMP/release-manifest.json"
python - "$ROOT" "$TMP" <<'PY'
import json, pathlib, sys
from jsonschema import Draft202012Validator
root = pathlib.Path(sys.argv[1])
tmp = pathlib.Path(sys.argv[2])
for schema_name, payload_name in [
    ("release-toolchain.schema.json", "toolchain.json"),
    ("release-manifest.schema.json", "release-manifest.json"),
]:
    schema = json.loads((root / "schemas" / schema_name).read_text(encoding="utf-8"))
    payload = json.loads((tmp / payload_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)
manifest = json.loads((tmp / "release-manifest.json").read_text(encoding="utf-8"))
assert manifest["schemaVersion"] == "1.1"
assert manifest["signing"]["certificateSha256"] == "0" * 64
assert manifest["requiredConnectedGates"] == ["ANDROID_SIGNED_RELEASE", "GHIDRA_MULTIABI_IL2CPP"]
assert {a["kind"] for a in manifest["artifacts"]} == {"APK", "AAB"}
print("v0.20 release evidence smoke: PASS")
PY
