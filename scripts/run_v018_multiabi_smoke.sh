#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/test-corpus/ghidra/multiabi"
"$DIR/build-fixtures.sh"
(cd "$DIR" && sha256sum -c SHA256SUMS)
check() {
  local file="$1" machine="$2"
  readelf -h "$file" | grep -F "$machine" >/dev/null
  for symbol in g_CodeRegistration g_MetadataRegistration il2cpp_codegen_register Managed_Method_One Managed_Method_Two fixture_registration_call; do
    readelf -Ws "$file" | grep -F "$symbol" >/dev/null
  done
  strings "$file" | grep -F 'Assembly-CSharp.dll' >/dev/null
}
check "$DIR/libil2cpp-fixture-arm64-v8a.so" 'AArch64'
check "$DIR/libil2cpp-fixture-armeabi-v7a.so" 'ARM'
check "$DIR/libil2cpp-fixture-x86_64.so" 'Advanced Micro Devices X86-64'
python3 -m py_compile "$ROOT/scripts/make_ghidra_multiabi_job.py" "$ROOT/scripts/assert_ghidra_multiabi_result.py"
echo 'v0.18 multi-ABI structural IL2CPP fixture smoke PASS'
