#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/test-corpus/ghidra/out"
mkdir -p "$OUT"
gcc -shared -fPIC -O0 -g -fno-inline -Wl,--build-id -o "$OUT/libunirevlab_ghidra_fixture.so" "$ROOT/test-corpus/ghidra/ghidra_fixture.c"
printf '%s\n' "$OUT/libunirevlab_ghidra_fixture.so"
