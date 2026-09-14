#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and fully validate released dev37 first. Sources remain in /tmp/modkit-dev25.
bash .dev37/ci-dev37.sh

python .dev38/apply-dev38.py /tmp/modkit-dev25
cd /tmp/modkit-dev25

grep -q "versionCode 43" android/app/build.gradle
grep -q "versionName '0.9.0-dev38'" android/app/build.gradle
grep -q 'version = "0.9.0.dev38"' pyproject.toml
grep -q '__version__ = "0.9.0-dev38"' modkit/__init__.py
grep -q 'READY_DEX' modkit/mobile/simple_mode.py
grep -q 'READY_SCRIPT' modkit/mobile/simple_mode.py
grep -q 'READY_RESOURCE' modkit/mobile/simple_mode.py
grep -q 'READY_NATIVE' modkit/mobile/simple_mode.py
grep -q 'security-surfaces.json' android/app/src/main/java/dev/modkit/mobile/WorkerService.java
grep -q 'credentialValueExtraction' modkit/mobile/security_scan.py
grep -q 'activeConnectionAttempted' modkit/mobile/security_scan.py

test -s RELEASE-0.9.0-DEV38-RU.md

# Focused passive scanner smoke test: local APK only, no network I/O.
python - <<'PY'
from pathlib import Path
import tempfile, zipfile
from modkit.mobile.security_scan import scan_apk_paths
with tempfile.TemporaryDirectory() as d:
    apk=Path(d)/'base.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('classes.dex', b'dex\n035\x00 https://api.example.test/v1/profile wss://socket.example.test/live Retrofit io.grpc')
        z.writestr('assets/config.txt', 'AES/GCM encryption_key marker')
    out=scan_apk_paths([apk])
    kinds={x['kind'] for x in out['findings']}
    assert 'API_ENDPOINT' in kinds
    assert 'WEBSOCKET_ENDPOINT' in kinds
    assert 'NETWORK_STACK' in kinds
    assert 'CRYPTO_PRIMITIVE' in kinds
    assert 'KEY_CONFIG_MARKER' in kinds
    assert out['activeConnectionAttempted'] is False
    assert out['credentialValueExtraction'] is False
print('dev38 security scan smoke: OK')
PY

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
