#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev36 first. Sources remain in /tmp/modkit-dev25.
bash .dev36/ci-dev36.sh

# Transparent dev37 transport: the actual staged git patch is split into text chunks.
for row in \
'4377cff9434dcecab37c5d8e1019cf552c92acab5949f6f6562f17c338de3707  .dev37/dev37.patch.00' \
'5f6e94ddcb3d270db26538246bb37bf749c1ad1b648a961256cb1eeae283c882  .dev37/dev37.patch.01' \
'75b0c1ae3acef37ad185d1a366676540fd2272c10082312eb27ef18748c92502  .dev37/dev37.patch.02' \
'ee5f7a22dd37a28c0f2784bbe6cb89be5902c744a459661083b7eb8232f5bbf4  .dev37/dev37.patch.03' \
'd669f835474a2b7a65feb6dd2fa1cce07e1a3fda3e7b9b3c52e1c280c318dc3e  .dev37/dev37.patch.04' \
'1697895eb1772be7b818e5dfedae2675d1c91c443a3b2deb2204efd9f52268ad  .dev37/dev37.patch.05' \
'0552c8a6f37c9ca26e75a74ced50dee0bc732267a1a30d42688114a1c83ec125  .dev37/dev37.patch.06'; do echo "$row" | sha256sum -c -; done
cat .dev37/dev37.patch.{00,01,02,03,04,05,06} > /tmp/dev37.patch
echo '60ab7be2f08bac3daab26e732d7ea160263ecea891b8e59bba59d52d17a4380e  /tmp/dev37.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev37.patch
git apply /tmp/dev37.patch

grep -q "versionCode 42" android/app/build.gradle
grep -q "versionName '0.9.0-dev37'" android/app/build.gradle
grep -q 'version = "0.9.0.dev37"' pyproject.toml
grep -q '__version__ = "0.9.0-dev37"' modkit/__init__.py
grep -q 'SimpleModeActivity' android/app/src/main/AndroidManifest.xml
grep -q 'FileWorkspaceActivity' android/app/src/main/AndroidManifest.xml
grep -q 'modkit-workspace-patch-1.0' modkit/patchpack/core.py
grep -q 'cocosMarkers' modkit/mobile/apkset.py
grep -q 'serverBypassGenerated' modkit/mobile/simple_mode.py
grep -q 'Для глупых' android/app/src/main/res/values/strings.xml
grep -q 'workspace_files' android/app/src/main/res/values/strings.xml
test -s RELEASE-0.9.0-DEV37-RU.md
test -s VALIDATION-DEV37.json
grep -q '"tests": 344' VALIDATION-DEV37.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
