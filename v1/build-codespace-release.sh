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
GRADLE_VERSION="8.9"
TOOLS_DIR="${HOME}/.cache/modkit-build-tools"
GRADLE_HOME="$TOOLS_DIR/gradle-${GRADLE_VERSION}"
GRADLE_BIN="$GRADLE_HOME/bin/gradle"

if [ -z "$SDK_ROOT" ]; then
  echo "ERROR: ANDROID_HOME/ANDROID_SDK_ROOT is not set. Open this branch in its GitHub Codespace." >&2
  exit 2
fi

for cmd in python java sdkmanager unzip sha256sum curl gh git; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 2; }
done

# Make the build independent from whatever Gradle version the VS Code extension
# discovers in other/legacy Android projects in this repository.
if [ ! -x "$GRADLE_BIN" ]; then
  mkdir -p "$TOOLS_DIR"
  ZIP="$TOOLS_DIR/gradle-${GRADLE_VERSION}-bin.zip"
  SUM="$ZIP.sha256"
  echo "Installing Gradle ${GRADLE_VERSION} for canonical v1 build..."
  curl -fL --retry 3 --retry-delay 2 \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    -o "$ZIP"
  curl -fL --retry 3 --retry-delay 2 \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip.sha256" \
    -o "$SUM"
  printf '%s  %s\n' "$(tr -d '[:space:]' < "$SUM")" "$ZIP" | sha256sum -c -
  rm -rf "$GRADLE_HOME"
  unzip -q "$ZIP" -d "$TOOLS_DIR"
  rm -f "$ZIP" "$SUM"
fi

# Self-heal the Android toolchain in an existing Codespace as well as a fresh one.
yes | sdkmanager --licenses >/dev/null 2>&1 || true
sdkmanager \
  "platform-tools" \
  "platforms;android-34" \
  "build-tools;34.0.0" \
  "ndk;26.1.10909125" \
  "cmake;3.22.1"

ZIPALIGN="$SDK_ROOT/build-tools/34.0.0/zipalign"
APKSIGNER="$SDK_ROOT/build-tools/34.0.0/apksigner"
test -x "$ZIPALIGN" || { echo "ERROR: zipalign 34.0.0 is missing" >&2; exit 2; }
test -x "$APKSIGNER" || { echo "ERROR: apksigner 34.0.0 is missing" >&2; exit 2; }

printf '\n== ModKit Codespaces validation ==\ncommit: %s\nversion: %s\n\n' "$FULL_SHA" "$VERSION"
python --version
java -version
"$GRADLE_BIN" --version | sed -n '1,12p'

cd "$ROOT/v1"
python -m pip install -U pip pytest
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check

cd "$ROOT/v1/android"
"$GRADLE_BIN" --no-daemon :app:testDebugUnitTest
"$GRADLE_BIN" --no-daemon :app:compileDebugJavaWithJavac
"$GRADLE_BIN" --no-daemon :app:lintDebug
"$GRADLE_BIN" --no-daemon :app:assembleDebug

cd "$ROOT"
test -s "$APK_SRC"
unzip -t "$APK_SRC" >/dev/null
"$ZIPALIGN" -c -p -v 4 "$APK_SRC" >/dev/null
"$APKSIGNER" verify --verbose --print-certs "$APK_SRC" | tee "$SIG_OUT"
cp "$APK_SRC" "$APK_OUT"
sha256sum "$APK_OUT" | tee "$SHA_OUT"
test "$(unzip -p "$APK_OUT" AndroidManifest.xml | wc -c)" -gt 0

REPO_SLUG="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO_SLUG" ]; then
  REMOTE_URL="$(git remote get-url origin)"
  REPO_SLUG="$(printf '%s' "$REMOTE_URL" | sed -E 's#^https://github.com/##; s#^git@github.com:##; s#\.git$##')"
fi
case "$REPO_SLUG" in
  */*) ;;
  *) echo "ERROR: could not determine GitHub repository slug" >&2; exit 2 ;;
esac

# Codespaces normally authenticates gh automatically. If a token is exposed,
# prefer it, but don't require an Actions-only environment variable.
if [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="$GITHUB_TOKEN"
fi
gh auth status >/dev/null 2>&1 || {
  echo "ERROR: GitHub CLI is not authenticated in this Codespace." >&2
  exit 2
}

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

if gh release view "$TAG" --repo "$REPO_SLUG" >/dev/null 2>&1; then
  gh release upload "$TAG" "$APK_OUT" "$SHA_OUT" "$SIG_OUT" \
    --repo "$REPO_SLUG" --clobber
else
  gh release create "$TAG" \
    --repo "$REPO_SLUG" \
    --target "$FULL_SHA" \
    --title "ModKit Android ${VERSION} (${SHORT_SHA})" \
    --notes "$NOTES" \
    "$APK_OUT" "$SHA_OUT" "$SIG_OUT"
fi

printf '\nSUCCESS\nRelease tag: %s\nAPK: %s\nSHA256 file: %s\n' "$TAG" "$APK_OUT" "$SHA_OUT"
