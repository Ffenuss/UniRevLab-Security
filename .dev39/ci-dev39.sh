#!/usr/bin/env bash
set -euo pipefail

# Reconstruct transparent dev39 source chunks and verify exact authoring bytes.
cat .dev39/simple_mode.py.{00,01,02,03} > .dev39/simple_mode.py
cat .dev39/security_scan.py.{00,01} > .dev39/security_scan.py
cat .dev39/SimpleModeActivity.java.{00,01} > .dev39/SimpleModeActivity.java
cat .dev39/apply-dev39.py.{00,01,02} > .dev39/apply-dev39.py

echo 'e71d65eac4d3d1d10570493b9d16b4a5615b397dca453cc42263252173d48d4c  .dev39/simple_mode.py' | sha256sum -c -
echo '1c603b4ee77c767603115c828db89fbe7f06d676d374f63e6ee5891bfe531cfd  .dev39/security_scan.py' | sha256sum -c -
echo '6942fbdcd4557a90a105ae6f2c37cbdda94b661a3bdc86f270a52111d9623ac9  .dev39/SimpleModeActivity.java' | sha256sum -c -
echo '8151d68c7114d353bb48702bfb5c5531e16e3c099e5f8c3b06f243c65ef6df93  .dev39/apply-dev39.py' | sha256sum -c -
python -m py_compile .dev39/simple_mode.py .dev39/security_scan.py .dev39/apply-dev39.py

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
