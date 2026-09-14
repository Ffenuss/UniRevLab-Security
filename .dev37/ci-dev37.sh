#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev36 first. Sources remain in /tmp/modkit-dev25.
bash .dev36/ci-dev36.sh

# dev37 transport is stored as ordinary Git-tracked text chunks. Git already protects
# each blob by content hash; the authoritative integrity check here is whether the
# reconstructed patch applies cleanly to the exact validated dev36 tree.
for part in .dev37/dev37.patch.{00,01,02,03,04,05,06}; do
  test -s "$part"
done
cat .dev37/dev37.patch.{00,01,02,03,04,05,06} > /tmp/dev37.patch

test -s /tmp/dev37.patch
cd /tmp/modkit-dev25
git apply --check /tmp/dev37.patch
git apply /tmp/dev37.patch

# The historical dev34 regression follows the current release version to ensure the
# reconstructed source tree is the expected release. dev37 bumps 41/dev36 -> 42/dev37.
python - <<'PY'
from pathlib import Path
p = Path('tests/test_project_docs.py')
s = p.read_text(encoding='utf-8')
old = "assert 'versionCode 41' in gradle and \"versionName '0.9.0-dev36'\" in gradle"
new = "assert 'versionCode 42' in gradle and \"versionName '0.9.0-dev37'\" in gradle"
if old not in s:
    raise SystemExit('expected stale dev36 version assertion was not found')
p.write_text(s.replace(old, new, 1), encoding='utf-8')
PY

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
