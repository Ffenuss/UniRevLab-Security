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

# One historical dev34 regression intentionally follows the current release version
# as a reconstruction guard. Keep only that function's current-release assertions in
# sync with dev37; do not rewrite historical validation assertions elsewhere.
python - <<'PY'
from pathlib import Path
p = Path('tests/test_project_docs.py')
s = p.read_text(encoding='utf-8')
name = 'def test_dev34_parallel_index_checkpoint_is_versioned_and_fail_closed():'
start = s.find(name)
if start < 0:
    raise SystemExit('dev34 current-release regression guard was not found')
next_def = s.find('\ndef ', start + len(name))
end = len(s) if next_def < 0 else next_def
block = s[start:end]
updated = (block
    .replace('versionCode 41', 'versionCode 42')
    .replace('0.9.0.dev36', '0.9.0.dev37')
    .replace('0.9.0-dev36', '0.9.0-dev37'))
if updated == block:
    # The transport may already carry part of the dev37 expectation. Require the
    # final function to contain the complete dev37 version guard either way.
    if ('versionCode 42' not in block or '0.9.0.dev37' not in block):
        raise SystemExit('dev34 current-release guard did not contain expected dev36/dev37 markers')
s = s[:start] + updated + s[end:]
p.write_text(s, encoding='utf-8')
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
