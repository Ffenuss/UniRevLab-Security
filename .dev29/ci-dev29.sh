#!/usr/bin/env bash
set -euo pipefail

# Reconstruct the exact released dev28 tree using the already-validated chain.
bash .dev28/ci-dev28.sh

# Verify every staged dev29 transport part, then the assembled payload and raw patch.
for pair in \
  '32750aea2a6eb2af232625da82b29b1f577bbf0180b61d4961e4b7a393c3b4ef .dev29/dev29.patch.gz.b64.00' \
  '90992d839b055d5f6f7ecfe488e8dd74bd41b9442e3f609de35e112e856b496a .dev29/dev29.patch.gz.b64.01' \
  '8557f7ea7600b6441aadce0d1efe07680cd3f42f9f80115c36d9e64eb38f85d1 .dev29/dev29.patch.gz.b64.02' \
  'c42f15ac430fc6b2c13c96cc11be2c4996601369b4feffe55f874a7d1a2cd114 .dev29/dev29.patch.gz.b64.03'
do
  echo "$pair" | sha256sum -c -
done

cat .dev29/dev29.patch.gz.b64.00 \
    .dev29/dev29.patch.gz.b64.01 \
    .dev29/dev29.patch.gz.b64.02 \
    .dev29/dev29.patch.gz.b64.03 > /tmp/dev29.patch.gz.b64

echo '702028cfd536df0a25bd02468cb3ce4bcf00fd8b48fdd08111d652180c4036fe  /tmp/dev29.patch.gz.b64' | sha256sum -c -
base64 -d /tmp/dev29.patch.gz.b64 | gzip -d > /tmp/dev29.patch
echo '077a29404380eb9f161d45409a409518c44ec915827c048e4e1bc72bbbfcc7f6  /tmp/dev29.patch' | sha256sum -c -

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
