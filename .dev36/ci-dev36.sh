#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev35 first. This leaves sources in /tmp/modkit-dev25.
bash .dev35/ci-dev35.sh

# ASCII-only, checksum-verified dev36 transport.
test "$(git hash-object --no-filters .dev36/dev36.patch.gz.b64)" = "eb937cc2040db8589b5324820c190de1a27dfb25"
cp .dev36/dev36.patch.gz.b64 /tmp/dev36.patch.gz.b64
echo 'd4915c16e0a8170dcefc231e7e8c441e93dfe87ac77bd61ddc510e77e7904239  /tmp/dev36.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev36.patch.gz.b64 > /tmp/dev36.patch.gz
echo '8ffb98e43556ab7ce7c6ec4ac9cf1215c91c98667bfd09966f35a944f9987489  /tmp/dev36.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev36.patch.gz > /tmp/dev36.patch
echo '58c37e68b84135ce448d354b3a63ab48e7897e2ca6bdbcddc0b749dc11277389  /tmp/dev36.patch' | sha256sum -c -

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
