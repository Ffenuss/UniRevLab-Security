#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev35 first. This leaves sources in /tmp/modkit-dev25.
bash .dev35/ci-dev35.sh

# Corrected dev36 transport. The first attempt used `git diff` and therefore omitted
# new files; this transport is generated from `git diff --cached --binary` and
# includes the complete Decompiler Workspace.
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.00)" = "27fcd7909f02011064578ec5ace22e04d140419d"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.01)" = "3ae63f94d132a1a07ddba2b4275acec382370a85"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.02)" = "cabcbe081bdb60490080f386819681ba467cb134"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.03)" = "5e885fa7acceca50677a323807ab5808dea96973"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.04)" = "3c314ec57408195bf7c0712f590f0f85d43220ba"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.05)" = "9f3cf373e4fe1102b5308ac27419503512e494a1"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.06)" = "1c4f758eacb92d8fe755e50f9ae085657767b517"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.07)" = "aa1449fa1fbdbf548e8242c37f4d9480d6be50ac"
test "$(git hash-object --no-filters .dev36/dev36.fixed.b64.08)" = "daee902460d3d048c5b47052621fdc663a277036"
cat .dev36/dev36.fixed.b64.{00,01,02,03,04,05,06,07,08} > /tmp/dev36.patch.gz.b64
echo 'f3e44cbeda5073dd24752efc2d556913c61097447fdc8c1ac384724d0551bbc3  /tmp/dev36.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev36.patch.gz.b64 > /tmp/dev36.patch.gz
echo '29b5c6d4b9dd2922960bbad8fe66f89c8c887b30c826158f21028a6fb0bdae55  /tmp/dev36.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev36.patch.gz > /tmp/dev36.patch
echo '30c785ef1654d20b0d6c7fb81b5198329ad9935b4806ee70520e3db4714c548c  /tmp/dev36.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev36.patch
git apply /tmp/dev36.patch

grep -q "versionCode 41" android/app/build.gradle
grep -q "versionName '0.9.0-dev36'" android/app/build.gradle
grep -q 'version = "0.9.0.dev36"' pyproject.toml
grep -q '__version__ = "0.9.0-dev36"' modkit/__init__.py
grep -q "io.github.skylot:jadx-core:1.5.6" android/app/build.gradle
grep -q "io.github.skylot:jadx-dex-input:1.5.6" android/app/build.gradle
grep -q 'DecompilerActivity' android/app/src/main/AndroidManifest.xml
grep -q 'class DecompilerEngine' android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java
grep -q 'installed-target.json' android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java
grep -q 'getSmali()' android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java
grep -q 'setThreadsCount(1)' android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java
! grep -q 'android.permission.INTERNET' android/app/src/main/AndroidManifest.xml
test -s DECOMPILER-RESEARCH-DEV36.md
test -s RELEASE-0.9.0-DEV36-RU.md
test -s VALIDATION-DEV36.json
grep -q '"tests": 334' VALIDATION-DEV36.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
