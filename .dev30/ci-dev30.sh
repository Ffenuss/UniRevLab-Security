#!/usr/bin/env bash
set -euo pipefail

# Reconstruct exact released dev29 first. This leaves the source tree in /tmp/modkit-dev25.
bash .dev29/ci-dev29.sh

cat \
  .dev30/dev30.patch.part00 \
  .dev30/p01.00 .dev30/p01.01 .dev30/p01.02 .dev30/p01.03 \
  .dev30/p02.00 .dev30/p02.01 .dev30/p02.02 .dev30/p02.03 \
  .dev30/p03.00 .dev30/p03.01 .dev30/p03.02 .dev30/p03.03 \
  > /tmp/dev30.patch

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
