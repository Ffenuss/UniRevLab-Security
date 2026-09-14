#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate the exact green dev39 baseline first.
bash .dev39/ci-dev39.sh

python -m py_compile .dev40/simple_cache.py .dev40/apply-dev40.py
python .dev40/apply-dev40.py /tmp/modkit-dev25
cd /tmp/modkit-dev25

grep -q 'versionCode 45' android/app/build.gradle
grep -q "versionName '0.9.0-dev40'" android/app/build.gradle
grep -q 'version = "0.9.0.dev40"' pyproject.toml
grep -q '__version__ = "0.9.0-dev40"' modkit/__init__.py
grep -q 'modkit-simple-mode-1.3' modkit/mobile/simple_mode.py
grep -q 'PATCH_READY' modkit/mobile/simple_mode.py
grep -q 'FLOW_CONFIRMED' modkit/mobile/simple_mode.py
grep -q 'gameplayDomain' modkit/mobile/simple_mode.py
grep -q 'modkit-simple-cache-1.0' modkit/mobile/simple_cache.py
grep -q 'plan_workspace' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'simpleStage(1,6' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'Отменить анализ' android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java
grep -q 'Framework noise' android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java
grep -q 'Открыть в Decompiler' android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java
test -s RELEASE-0.9.0-DEV40-RU.md
test -s VALIDATION-DEV40.json

python -m pytest tests/test_dev40_simple_pipeline.py tests/test_dev40_architecture.py -q
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
