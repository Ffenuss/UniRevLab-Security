#!/usr/bin/env bash
set -euo pipefail

# Reconstruct and validate exact dev28 first. This leaves the project in /tmp/modkit-dev25.
bash .dev28/ci-dev28.sh

# Verify the staged dev29 delta byte-for-byte before applying it.
test "$(git hash-object --no-filters .dev29/dev29.patch.part00)" = "12536a54210f94bdb1d3d6ae421df03089be3487"
test "$(git hash-object --no-filters .dev29/dev29.patch.part01)" = "d1142cf24e924617498fc91fa6247572b6863097"
test "$(git hash-object --no-filters .dev29/dev29.patch.part02)" = "c38546dc0abeacb80ee3da35220081584d52afb9"
test "$(git hash-object --no-filters .dev29/dev29.patch.part03)" = "0248c7ed323586938d96a35e756bf9aa51fde9ae"
cat .dev29/dev29.patch.part00 .dev29/dev29.patch.part01 .dev29/dev29.patch.part02 .dev29/dev29.patch.part03 > /tmp/dev29.patch
echo '51fef40705978d03c8d65e4fa6e923acdde3d76907c1271c23893a8bd07583a0  /tmp/dev29.patch' | sha256sum -c -

cd /tmp/modkit-dev25
git apply --check /tmp/dev29.patch
git apply /tmp/dev29.patch

grep -q "versionCode 34" android/app/build.gradle
grep -q "versionName '0.9.0-dev29'" android/app/build.gradle
grep -q 'version = "0.9.0.dev29"' pyproject.toml
grep -q '__version__ = "0.9.0-dev29"' modkit/__init__.py
test -s RELEASE-0.9.0-DEV29-RU.md
test -s VALIDATION-DEV29.json

python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check
cd android
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:lintDebug
