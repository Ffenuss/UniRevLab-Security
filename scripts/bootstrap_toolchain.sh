#!/usr/bin/env bash
set -euo pipefail

ANDROID_CMDLINE_BUILD="15859902"
ANDROID_CMDLINE_SHA256="4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583"
GRADLE_VERSION="9.5.0"
GRADLE_SHA256="553c78f50dafcd54d65b9a444649057857469edf836431389695608536d6b746"
ANDROID_PLATFORM="37"
ANDROID_BUILD_TOOLS="36.0.0"
ANDROID_NDK="28.2.13676358"
CARGO_NDK_VERSION="4.1.2"

PREFIX="${UNIREVLAB_TOOLCHAIN_PREFIX:-$HOME/.unirevlab-toolchain}"
ANDROID_HOME="${ANDROID_HOME:-$PREFIX/android-sdk}"
GRADLE_HOME="$PREFIX/gradle/gradle-$GRADLE_VERSION"
DOWNLOADS="$PREFIX/downloads"
mkdir -p "$DOWNLOADS" "$ANDROID_HOME/cmdline-tools" "$PREFIX/gradle"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing prerequisite: $1" >&2; exit 1; }; }
need curl
need unzip
need sha256sum
need java

fetch_verify() {
  local url="$1" out="$2" expected="$3"
  if [[ ! -f "$out" ]]; then
    curl --fail --location --retry 4 --retry-all-errors --proto '=https' --tlsv1.2 "$url" -o "$out"
  fi
  echo "$expected  $out" | sha256sum -c -
}

# Android command-line tools.
ANDROID_ZIP="$DOWNLOADS/commandlinetools-linux-${ANDROID_CMDLINE_BUILD}_latest.zip"
fetch_verify \
  "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_BUILD}_latest.zip" \
  "$ANDROID_ZIP" "$ANDROID_CMDLINE_SHA256"
if [[ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]]; then
  rm -rf "$ANDROID_HOME/cmdline-tools/latest" "$PREFIX/android-cmdline-unpack"
  mkdir -p "$PREFIX/android-cmdline-unpack"
  unzip -q "$ANDROID_ZIP" -d "$PREFIX/android-cmdline-unpack"
  mv "$PREFIX/android-cmdline-unpack/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
  rm -rf "$PREFIX/android-cmdline-unpack"
fi

export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Google SDK license acceptance is intentionally explicit in this bootstrap invocation.
yes | sdkmanager --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
sdkmanager --sdk_root="$ANDROID_HOME" \
  "platform-tools" \
  "platforms;android-${ANDROID_PLATFORM}" \
  "build-tools;${ANDROID_BUILD_TOOLS}" \
  "ndk;${ANDROID_NDK}"

# Gradle.
GRADLE_ZIP="$DOWNLOADS/gradle-${GRADLE_VERSION}-bin.zip"
fetch_verify \
  "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
  "$GRADLE_ZIP" "$GRADLE_SHA256"
if [[ ! -x "$GRADLE_HOME/bin/gradle" ]]; then
  rm -rf "$GRADLE_HOME"
  unzip -q "$GRADLE_ZIP" -d "$PREFIX/gradle"
fi
export GRADLE_HOME
export PATH="$GRADLE_HOME/bin:$PATH"

# Rust/Cargo via rustup.
export CARGO_HOME="${CARGO_HOME:-$PREFIX/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$PREFIX/rustup}"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
  RUSTUP_INIT="$DOWNLOADS/rustup-init"
  RUSTUP_SHA="$DOWNLOADS/rustup-init.sha256"
  curl --fail --location --retry 4 --retry-all-errors --proto '=https' --tlsv1.2 \
    "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init" -o "$RUSTUP_INIT"
  curl --fail --location --retry 4 --retry-all-errors --proto '=https' --tlsv1.2 \
    "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256" -o "$RUSTUP_SHA"
  expected="$(awk '{print $1}' "$RUSTUP_SHA")"
  echo "$expected  $RUSTUP_INIT" | sha256sum -c -
  chmod +x "$RUSTUP_INIT"
  "$RUSTUP_INIT" -y --profile minimal --default-toolchain stable --no-modify-path
fi
export PATH="$CARGO_HOME/bin:$PATH"

rustup default stable
rustup target add \
  aarch64-linux-android \
  armv7-linux-androideabi \
  x86_64-linux-android \
  i686-linux-android

if ! command -v cargo-ndk >/dev/null 2>&1; then
  cargo install cargo-ndk --version "$CARGO_NDK_VERSION" --locked
fi

ENV_FILE="$PREFIX/env.sh"
cat > "$ENV_FILE" <<ENV
export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export GRADLE_HOME="$GRADLE_HOME"
export CARGO_HOME="$CARGO_HOME"
export RUSTUP_HOME="$RUSTUP_HOME"
export PATH="$CARGO_HOME/bin:$GRADLE_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:\$PATH"
ENV

printf '\n=== installed toolchain ===\n'
java -version 2>&1 | head -n 3
sdkmanager --version
gradle --version | sed -n '1,12p'
rustup --version
rustc --version
cargo --version
cargo ndk --version || cargo-ndk --version
printf '\nEnvironment file: %s\n' "$ENV_FILE"
