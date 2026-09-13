#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev30 first. This leaves the source tree in /tmp/modkit-dev25.
bash .dev30/ci-dev30.sh

# ASCII-only, checksum-verified transport for the dev31 binary-safe patch.
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.00)" = "2a3391c1d5b6dc532e59bb0eec56c73687dd294e"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.01)" = "12effec8ecbd31d3e1100faed5fbc3e416cf7bc7"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.02)" = "a799cb5b652d7e4a4a99607f433e50ce4bd77ea8"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.03)" = "d53c08d3f1aeb84ad80cfa508d2cf187c520dcea"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.04)" = "d341c002cd1c3e155677b12d19f3fe196dc2f9ca"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.05)" = "a50805ced3711c5ae27aae91e0a8eab5b7c8b379"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.06)" = "2fee95a65d0f43df2de7837e4747c69901b13d87"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.07)" = "92ce9e9b08f73dbec45601d7f0701bc16ac0e945"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.08)" = "0e71352270a78bcdb7e4e5ee71e4f7ece2a74f80"
test "$(git hash-object --no-filters .dev31/dev31.patch.gz.b64.09)" = "1c539afde90bc9fb8294305aa91aa95ded28f7dc"
cat .dev31/dev31.patch.gz.b64.00 .dev31/dev31.patch.gz.b64.01 .dev31/dev31.patch.gz.b64.02 .dev31/dev31.patch.gz.b64.03 .dev31/dev31.patch.gz.b64.04 .dev31/dev31.patch.gz.b64.05 .dev31/dev31.patch.gz.b64.06 .dev31/dev31.patch.gz.b64.07 .dev31/dev31.patch.gz.b64.08 .dev31/dev31.patch.gz.b64.09 > /tmp/dev31.patch.gz.b64
echo '59220e02837a0c1bcf3d6e87bc629320f25a434571039c10d1bb4d44f5aa3ef3  /tmp/dev31.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev31.patch.gz.b64 > /tmp/dev31.patch.gz
echo 'a0d6460927bf00d134116e9248fc8b92888f9576b3a56a56dc24a8e04e563785  /tmp/dev31.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev31.patch.gz > /tmp/dev31.patch
echo '92e1966faee65e2d6280af5467c3dca59e4f46f52fe43deb6e6e43a9d157aabd  /tmp/dev31.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev31.patch
git apply /tmp/dev31.patch

grep -q "versionCode 36" android/app/build.gradle
grep -q "versionName '0.9.0-dev31'" android/app/build.gradle
grep -q 'version = "0.9.0.dev31"' pyproject.toml
grep -q '__version__ = "0.9.0-dev31"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV31-RU.md
test -s VALIDATION-DEV31.json
test -s modkit/mobile/package_target.py
test -s android/app/src/main/java/dev/modkit/mobile/SigningKeyManager.java
test ! -e android/app/src/main/assets/modkit-test-signing.p12
grep -q 'AndroidKeyStore' android/app/src/main/java/dev/modkit/mobile/SigningKeyManager.java
grep -q 'build_output_plan' modkit/mobile/package_target.py

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
