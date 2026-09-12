#!/usr/bin/env bash
set -euo pipefail

# Reconstruct exact released dev29 first. This leaves the source tree in /tmp/modkit-dev25.
bash .dev29/ci-dev29.sh

# Exact ASCII transport for dev30. Verify every chunk before decoding.
test "$(git hash-object --no-filters .dev30/dev30.patch.gz.b64.00)" = "a4b8c391c056ef3f3b95cf2ef3dbc553096fe0e8"
test "$(git hash-object --no-filters .dev30/dev30.patch.gz.b64.01)" = "a82db08c74c99a018a87bc1f88c9ff018032b970"
test "$(git hash-object --no-filters .dev30/dev30.patch.gz.b64.02)" = "b270728ccc9365eb6ad14bedf9adced184f9938c"
test "$(git hash-object --no-filters .dev30/dev30.patch.gz.b64.03)" = "25e2a14cb176b26edd4dbb8291a7aff352b78e09"
test "$(git hash-object --no-filters .dev30/dev30.patch.gz.b64.04)" = "fb6ad9761641c82292781aca6b84e646b5e0b9e3"
cat .dev30/dev30.patch.gz.b64.00 .dev30/dev30.patch.gz.b64.01 .dev30/dev30.patch.gz.b64.02 .dev30/dev30.patch.gz.b64.03 .dev30/dev30.patch.gz.b64.04 > /tmp/dev30.patch.gz.b64
echo 'e8e61a8650cf7c8e8554c368863b98011cbd4f2eb735fb6bac11ba83d91bd8ac  /tmp/dev30.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev30.patch.gz.b64 > /tmp/dev30.patch.gz
echo 'b77ab432ab43cf8d62f41811338e176b5f2b951be7057b70b0cfaabd942a5136  /tmp/dev30.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev30.patch.gz > /tmp/dev30.patch
echo '8a403b458a75ea3ff759c791c5d51399f263aad2001ab26b5c28e22305a7c538  /tmp/dev30.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev30.patch
git apply /tmp/dev30.patch

grep -q "versionCode 35" android/app/build.gradle
grep -q "versionName '0.9.0-dev30'" android/app/build.gradle
grep -q 'version = "0.9.0.dev30"' pyproject.toml
grep -q '__version__ = "0.9.0-dev30"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV30-RU.md
test -s VALIDATION-DEV30.json
test -s modkit/mobile/apkset.py

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
