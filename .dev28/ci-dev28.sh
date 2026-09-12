#!/usr/bin/env bash
set -euo pipefail
python -m pip install --disable-pip-version-check pyyaml pytest
python - <<'PY'
import os, subprocess, yaml
from pathlib import Path
wf = yaml.safe_load(Path('.github/workflows/dev27-bootstrap.yml').read_text())
build = wf['jobs']['build']
env = os.environ.copy()
env.update({str(k): str(v) for k, v in (build.get('env') or {}).items()})
wanted = {'Reconstruct exact dev26', 'Verify and apply exact dev27'}
found = []
for step in build['steps']:
    if step.get('name') not in wanted:
        continue
    found.append(step['name'])
    subprocess.run(['bash', '-euo', 'pipefail', '-c', step['run']], check=True, env=env)
assert set(found) == wanted, found
PY
grep -q "versionCode 32" /tmp/modkit-dev25/android/app/build.gradle
grep -q "versionName '0.9.0-dev27'" /tmp/modkit-dev25/android/app/build.gradle
test "$(git hash-object --no-filters .dev28/dev28.patch.part00)" = "5911802ea92e7d5a32d9b4d8316edb889de15138"
test "$(git hash-object --no-filters .dev28/dev28.patch.part01)" = "a563e4200d95915b3196c68f164df2ddf50cd985"
test "$(git hash-object --no-filters .dev28/dev28.patch.part02)" = "8de96623d6f21dc45fae95b9c98a46e8d1a6f0ef"
test "$(git hash-object --no-filters .dev28/dev28.patch.part03)" = "d50c41526147c0525eb784c9bd4682dbed7bbc3d"
cat .dev28/dev28.patch.part00 .dev28/dev28.patch.part01 .dev28/dev28.patch.part02 .dev28/dev28.patch.part03 > /tmp/dev28.patch
echo '1ab8dee0c9bb547640ff200a5a2912ce949c66e29d487a7816d720c5e400593a  /tmp/dev28.patch' | sha256sum -c -
cd /tmp/modkit-dev25
git apply --check /tmp/dev28.patch
git apply /tmp/dev28.patch
grep -q "versionCode 33" android/app/build.gradle
grep -q "versionName '0.9.0-dev28'" android/app/build.gradle
grep -q 'version = "0.9.0.dev28"' pyproject.toml
grep -q '__version__ = "0.9.0-dev28"' modkit/__init__.py
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
