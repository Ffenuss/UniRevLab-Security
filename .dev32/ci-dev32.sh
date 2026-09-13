#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev31 first. This leaves the source tree in /tmp/modkit-dev25.
bash .dev31/ci-dev31.sh

# ASCII-only, checksum-verified transport for the dev32 patch.
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.00)" = "2e11b858825636ca36f9fe9337bb4356e5a948ba"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.01)" = "c9085da8b6846306fcb0a3b8aff731b8bf97cad9"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.02)" = "e8482683f75b21d2049918d825cd60fee845c455"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.03)" = "442967d6869dc8ec5337330e1fafbc56bfd2d8de"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.04)" = "c5abaac3b340fac828f000fe19fbd157645c49bd"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.05)" = "40ce68d2bf392961b5210f13184bc3b4b6e70b16"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.06)" = "0b16e405490cf190c135d3a3fef2747ddc5eb9bd"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.07)" = "9c366ff06a1e292d0d2c6b3432b6691b4484cb0e"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.08)" = "0b2473afa1f281cf701ef26f9fee047a511cda9a"
test "$(git hash-object --no-filters .dev32/dev32.patch.gz.b64.09)" = "138bae691f12103437adaf612d977d29ca0978fb"
cat .dev32/dev32.patch.gz.b64.00 .dev32/dev32.patch.gz.b64.01 .dev32/dev32.patch.gz.b64.02 .dev32/dev32.patch.gz.b64.03 .dev32/dev32.patch.gz.b64.04 .dev32/dev32.patch.gz.b64.05 .dev32/dev32.patch.gz.b64.06 .dev32/dev32.patch.gz.b64.07 .dev32/dev32.patch.gz.b64.08 .dev32/dev32.patch.gz.b64.09 > /tmp/dev32.patch.gz.b64
echo '9b6ad496a9c3dbbf8a3991454d4ae51cd7f9fa829e9638a5894c0fd573a794a2  /tmp/dev32.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev32.patch.gz.b64 > /tmp/dev32.patch.gz
echo '67d568c001a89b26f6aac197b888e3985d7ad79a847f9c20641151fea8d63902  /tmp/dev32.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev32.patch.gz > /tmp/dev32.patch
echo 'a1d14bf0af37df3ae8583e801147727aa72e27c9130c0acba0fde78282893a60  /tmp/dev32.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev32.patch
git apply /tmp/dev32.patch

grep -q "versionCode 37" android/app/build.gradle
grep -q "versionName '0.9.0-dev32'" android/app/build.gradle
grep -q 'version = "0.9.0.dev32"' pyproject.toml
grep -q '__version__ = "0.9.0-dev32"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV32-RU.md
test -s VALIDATION-DEV32.json
test -s modkit/mobile/app_discovery.py
test -s modkit/mobile/target_profile.py
grep -q 'modkit-dex-trust-2' modkit/reworkspace/trust.py
grep -q 'Theme.Material3.DayNight.NoActionBar' android/app/src/main/res/values/styles.xml
grep -q 'classify_apkset_scan_json' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'scan_trust' modkit/mobile/apkset.py
grep -q 'APPLICATION' modkit/mobile/target_profile.py
grep -q 'NOT_FOUND_LOCAL' modkit/mobile/app_discovery.py
grep -q 'modkit-package-target-1.1' modkit/mobile/package_target.py

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
