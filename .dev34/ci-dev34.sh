#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev33 first. This leaves sources in /tmp/modkit-dev25.
bash .dev33/ci-dev33.sh

# ASCII-only, checksum-verified dev34 transport.
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.00)" = "d8b6b9f004b6b6639138038ea502202b40a88f59"
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.01)" = "56310e594a19db1ab5ca937f7dcb19fd8fdee9dd"
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.02)" = "62f0f9d85335324ec6ddae45ee2d2fa97feebcd7"
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.03)" = "4d000f73bea4c168dd1dcabdad536d65af2bf414"
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.04)" = "48c77fe06b05eb3a2ea4367642351395c1a88c19"
test "$(git hash-object --no-filters .dev34/dev34.patch.gz.b64.05)" = "28d88f25aa282247ba93551f61c094d45a5e6d89"
cat .dev34/dev34.patch.gz.b64.00 .dev34/dev34.patch.gz.b64.01 .dev34/dev34.patch.gz.b64.02 .dev34/dev34.patch.gz.b64.03 .dev34/dev34.patch.gz.b64.04 .dev34/dev34.patch.gz.b64.05 > /tmp/dev34.patch.gz.b64
echo '284681e2d6a15abd044ce77889138381d752b2e6c6b4f626be6b1dbfff971b75  /tmp/dev34.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev34.patch.gz.b64 > /tmp/dev34.patch.gz
echo 'ddd3c59a50bc54b29d66d6ceef0da7c4dae3a6c4eb011b8ca414991b7d95f520  /tmp/dev34.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev34.patch.gz > /tmp/dev34.patch
echo '7d1a27007b7c0cf77841ccdf07e639708210ef2932df46156f0ce8f64ea5d397  /tmp/dev34.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev34.patch
git apply /tmp/dev34.patch

grep -q "versionCode 39" android/app/build.gradle
grep -q "versionName '0.9.0-dev34'" android/app/build.gradle
grep -q 'version = "0.9.0.dev34"' pyproject.toml
grep -q '__version__ = "0.9.0-dev34"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV34-RU.md
test -s VALIDATION-DEV34.json
test -s modkit/reworkspace/artifact_scan.py
test -s modkit/mobile/metadata_catalog.py
grep -q '_scan_items_bounded' modkit/reworkspace/correlate.py
grep -q 'nativeSynchronous' modkit/reworkspace/correlate.py
grep -q 'analysis.methods.jsonl.search.idx' android/app/src/main/java/dev/modkit/mobile/MainActivity.java
grep -q 'searchDebounce' android/app/src/main/java/dev/modkit/mobile/MainActivity.java
grep -q '"tests": 323' VALIDATION-DEV34.json
grep -q '"searchIndexDoesNotPromoteRuntimeTruth": true' VALIDATION-DEV34.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
