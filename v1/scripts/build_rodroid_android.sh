#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "$0")/.." && pwd)"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK 26.3.11579264}"
rodroid_commit="8bfb90229539833999e725c5cf6402a435b47f15"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

git clone https://github.com/rodroidmods/il2cpp-dumper-rs.git "$work_dir/rodroid"
git -C "$work_dir/rodroid" checkout "$rodroid_commit"
rustup target add aarch64-linux-android x86_64-linux-android

toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$toolchain/aarch64-linux-android26-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$toolchain/x86_64-linux-android26-clang"
cargo build --manifest-path "$work_dir/rodroid/Cargo.toml" --release --locked --target aarch64-linux-android
cargo build --manifest-path "$work_dir/rodroid/Cargo.toml" --release --locked --target x86_64-linux-android

install -Dm755 "$work_dir/rodroid/target/aarch64-linux-android/release/il2cpp_dumper" \
  "$project_root/android/app/src/main/jniLibs/arm64-v8a/librodroid.so"
install -Dm755 "$work_dir/rodroid/target/x86_64-linux-android/release/il2cpp_dumper" \
  "$project_root/android/app/src/main/jniLibs/x86_64/librodroid.so"
