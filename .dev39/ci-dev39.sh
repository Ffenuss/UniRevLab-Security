#!/usr/bin/env bash
set -euo pipefail

# Start from the exact validated dev37 reconstruction, then apply dev38 and dev39.
bash .dev37/ci-dev37.sh
python .dev38/apply-dev38.py /tmp/modkit-dev25
python .dev39/apply-dev39.py /tmp/modkit-dev25
cd /tmp/modkit-dev25

grep -q 'versionCode 44' android/app/build.gradle
grep -q "versionName '0.9.0-dev39'" android/app/build.gradle
grep -q 'version = "0.9.0.dev39"' pyproject.toml
grep -q '__version__ = "0.9.0-dev39"' modkit/__init__.py
grep -q 'for method_count in (direct, virtual)' modkit/reworkspace/dex.py
grep -q 'ownershipKind' modkit/reworkspace/trust.py
grep -q 'READY_DEX' modkit/mobile/simple_mode.py
grep -q 'frameworkNoise' modkit/mobile/simple_mode.py
grep -q 'Network / API Endpoints' modkit/mobile/simple_mode.py
grep -q 'keyValueExtraction' modkit/mobile/security_scan.py
grep -q 'Технические доказательства JSON' android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java
grep -q 'Важное' android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java
test -s RELEASE-0.9.0-DEV39-RU.md
test -s VALIDATION-DEV39.json

python -m pytest tests/test_dev39_precision.py tests/test_dev39_simple_mode.py tests/test_dev39_architecture.py -q
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
