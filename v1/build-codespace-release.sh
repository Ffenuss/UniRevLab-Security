#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "Modkit1" ]; then
  echo "ERROR: expected branch Modkit1, got: $BRANCH" >&2
  exit 2
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: tracked source changes are present. Commit/revert them before producing a release build." >&2
  exit 2
fi

FULL_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short=12 HEAD)"
VERSION="1.1.0-dev1"
TAG="modkit-${VERSION}-${SHORT_SHA}"
APK_SRC="$ROOT/v1/android/app/build/outputs/apk/debug/app-debug.apk"
APK_OUT="$ROOT/v1/ModKit-Android-${VERSION}-${SHORT_SHA}-debug.apk"
SHA_OUT="$APK_OUT.sha256"
SIG_OUT="$ROOT/v1/apk-signature-${SHORT_SHA}.txt"
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"

if [ -z "$SDK_ROOT" ]; then
  echo "ERROR: ANDROID_HOME/ANDROID_SDK_ROOT is not set. Open this branch in its GitHub Codespace." >&2
  exit 2
fi

for cmd in python java gradle sdkmanager unzip sha256sum gh; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 2; }
done

ZIPALIGN="$SDK_ROOT/build-tools/34.0.0/zipalign"
APKSIGNER="$SDK_ROOT/build-tools/34.0.0/apksigner"
test -x "$ZIPALIGN" || { echo "ERROR: zipalign 34.0.0 is missing" >&2; exit 2; }
test -x "$APKSIGNER" || { echo "ERROR: apksigner 34.0.0 is missing" >&2; exit 2; }

printf '\n== ModKit Codespaces validation ==\ncommit: %s\nversion: %s\n\n' "$FULL_SHA" "$VERSION"
python --version
java -version
gradle --version | sed -n '1,12p'

cd "$ROOT/v1"
python -m pip install -U pip pytest
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check

cd "$ROOT/v1/android"
gradle --no-daemon :app:testDebugUnitTest
gradle --no-daemon :app:compileDebugJavaWithJavac
gradle --no-daemon :app:lintDebug
gradle --no-daemon :app:assembleDebug

cd "$ROOT"
test -s "$APK_SRC"
unzip -t "$APK_SRC" >/dev/null
"$ZIPALIGN" -c -p -v 4 "$APK_SRC" >/dev/null
"$APKSIGNER" verify --verbose --print-certs "$APK_SRC" | tee "$SIG_OUT"
cp "$APK_SRC" "$APK_OUT"
sha256sum "$APK_OUT" | tee "$SHA_OUT"
test "$(unzip -p "$APK_OUT" AndroidManifest.xml | wc -c)" -gt 0

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "ERROR: GITHUB_TOKEN is unavailable. Run this inside the repository Codespace." >&2
  exit 2
fi

NOTES="$(cat <<EOF
ModKit Android ${VERSION} validated Codespaces build.

Source commit: ${FULL_SHA}
Branch: Modkit1

Validation gate completed before publishing:
- Python pytest suite
- modkit selftest
- modkit runtime-check
- Android testDebugUnitTest
- compileDebugJavaWithJavac
- lintDebug
- assembleDebug
- APK unzip validation
- zipalign verification
- apksigner verification
- SHA-256 generation

This is a debug-signed test APK, not a production/store-signed package.
EOF
)"

export GH_TOKEN="$GITHUB_TOKEN"
if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh release upload "$TAG" "$APK_OUT" "$SHA_OUT" "$SIG_OUT" \
    --repo "$GITHUB_REPOSITORY" --clobber
else
  gh release create "$TAG" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$FULL_SHA" \
    --title "ModKit Android ${VERSION} (${SHORT_SHA})" \
    --notes "$NOTES" \
    "$APK_OUT" "$SHA_OUT" "$SIG_OUT"
fi

printf '\nSUCCESS\nRelease tag: %s\nAPK: %s\nSHA256 file: %s\n' "$TAG" "$APK_OUT" "$SHA_OUT"
