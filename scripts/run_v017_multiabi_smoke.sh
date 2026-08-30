#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/test-corpus/native/multiabi"
(cd "$DIR" && sha256sum -c SHA256SUMS)
check_machine() {
  local file="$1" expected="$2"
  readelf -h "$file" | grep -F "Machine:" | grep -F "$expected" >/dev/null
  readelf -Ws "$file" | grep -F "unirevlab_fixture_add" >/dev/null
  readelf -Ws "$file" | grep -F "unirevlab_fixture_magic" >/dev/null
}
check_machine "$DIR/libfixture-arm64-v8a.so" "AArch64"
check_machine "$DIR/libfixture-armeabi-v7a.so" "ARM"
check_machine "$DIR/libfixture-x86_64.so" "Advanced Micro Devices X86-64"
echo "v0.17 multi-ABI native fixtures PASS"
