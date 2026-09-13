#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact released dev32 first. This leaves sources in /tmp/modkit-dev25.
bash .dev32/ci-dev32.sh

# ASCII-only, checksum-verified dev33 transport.
test "$(git hash-object --no-filters .dev33/dev33.patch.gz.b64.00)" = "86c3c8fec9ed717de19ecd4dd08d63117f2d7a88"
test "$(git hash-object --no-filters .dev33/dev33.patch.gz.b64.01)" = "0a55517d3a0e1e0f7a052a848e05c9c9428c551c"
test "$(git hash-object --no-filters .dev33/dev33.patch.gz.b64.02)" = "2a7a3dc28cc9a7aaceb14073bcb4162df2a43b60"
test "$(git hash-object --no-filters .dev33/dev33.patch.gz.b64.03)" = "5e2a44d774597787f8975c1e5e6c3b835dc51c43"
test "$(git hash-object --no-filters .dev33/dev33.patch.gz.b64.04)" = "92daa461fccfe74f20d5e1f55f35c3c8c835ef15"
cat .dev33/dev33.patch.gz.b64.00 .dev33/dev33.patch.gz.b64.01 .dev33/dev33.patch.gz.b64.02 .dev33/dev33.patch.gz.b64.03 .dev33/dev33.patch.gz.b64.04 > /tmp/dev33.patch.gz.b64
echo '463c8d6f42f997c671d51ea7bd865e7697444a0e8171cdbdfd4c0f10d2a199da  /tmp/dev33.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev33.patch.gz.b64 > /tmp/dev33.patch.gz
echo '5bd1083b0b6ffb633d8c39115c281d73b11a116977a2dfa11d521e92eb160e37  /tmp/dev33.patch.gz' | sha256sum -c -
gzip -dc /tmp/dev33.patch.gz > /tmp/dev33.patch
echo '9658aa05632134c308be62748338832f570352ad7b5acbf1831dada8621641d4  /tmp/dev33.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev33.patch
git apply /tmp/dev33.patch

grep -q "versionCode 38" android/app/build.gradle
grep -q "versionName '0.9.0-dev33'" android/app/build.gradle
grep -q 'version = "0.9.0.dev33"' pyproject.toml
grep -q '__version__ = "0.9.0-dev33"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV33-RU.md
test -s VALIDATION-DEV33.json
test -s modkit/reworkspace/schema.py
test -s modkit/reworkspace/cache.py
test -s modkit/reworkspace/pipeline.py
grep -q 'modkit-re-report-typed-1' modkit/reworkspace/schema.py
grep -q 'SpooledTemporaryFile' modkit/reworkspace/correlate.py
grep -q 'mmap.mmap' modkit/reworkspace/correlate.py
grep -q 'open_mmap' modkit/elf/reader.py
grep -q 'memoryview(elf.blob)' modkit/reworkspace/native.py
grep -q 'CorrelationCache' modkit/mobile/engine.py
grep -q 'genericCorrelationCacheHit' modkit/mobile/engine.py
grep -q '"tests": 318' VALIDATION-DEV33.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
