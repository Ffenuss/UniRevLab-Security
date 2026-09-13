#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev34 first. This leaves sources in /tmp/modkit-dev25.
bash .dev34/ci-dev34.sh

# ASCII-only, checksum-verified dev35 transport.
test "$(git hash-object --no-filters .dev35/dev35.patch.gz.b64.00)" = "d72643c660769693ea3178d45166f03545d4e830"
test "$(git hash-object --no-filters .dev35/dev35.patch.gz.b64.01)" = "d8a3b7950edeed84143bda83c9caa087346d0190"
test "$(git hash-object --no-filters .dev35/dev35.patch.gz.b64.02)" = "2a248c096b0c3449e096e4456959bdb2ea8da849"
cat .dev35/dev35.patch.gz.b64.00 .dev35/dev35.patch.gz.b64.01 .dev35/dev35.patch.gz.b64.02 > /tmp/dev35.patch.gz.b64
echo '41baa879601c8536ad0f9d956d9f255bf1278921d081f9a989bd88c7ab0995e0  /tmp/dev35.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev35.patch.gz.b64 > /tmp/dev35.patch.gz
echo '8e1b2a66365aa764846c03a75bf9feb26f3fcb0feef9fd5e216249aca93527be  /tmp/dev35.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev35.patch.gz > /tmp/dev35.patch
echo '0960e8853893def8ceda68a60b157534fe5c9ce82f17b151646ec36c9980db94  /tmp/dev35.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev35.patch
git apply /tmp/dev35.patch

grep -q "versionCode 40" android/app/build.gradle
grep -q "versionName '0.9.0-dev35'" android/app/build.gradle
grep -q 'version = "0.9.0.dev35"' pyproject.toml
grep -q '__version__ = "0.9.0-dev35"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV35-RU.md
test -s VALIDATION-DEV35.json
grep -q 'dex-method-string-xref' modkit/reworkspace/artifact_scan.py
grep -Fq 'o.optBoolean("selectable",false)' android/app/src/main/java/dev/modkit/mobile/MainActivity.java
grep -q 'menu_smart_prepare' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'menu_smart_build_apk' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'hasIl2cppPath' android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java
grep -q 'evidenceOnlyDex' android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java
grep -q 'com.datadog.' modkit/reworkspace/trust.py
grep -q 'com.revenuecat.' modkit/reworkspace/trust.py
grep -q '"tests": 330' VALIDATION-DEV35.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
