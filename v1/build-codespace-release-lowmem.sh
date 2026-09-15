#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CANON="$ROOT/v1/build-codespace-release.sh"
TMP="$(mktemp -t modkit-release-lowmem.XXXXXX.sh)"
trap 'rm -f "$TMP"' EXIT

python - "$CANON" "$TMP" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
out = Path(sys.argv[2])
old = '''cd "$ROOT/v1/android"
"$GRADLE_BIN" --no-daemon :app:testDebugUnitTest
"$GRADLE_BIN" --no-daemon :app:compileDebugJavaWithJavac
"$GRADLE_BIN" --no-daemon :app:lintDebug
"$GRADLE_BIN" --no-daemon :app:assembleDebug
'''
new = '''cd "$ROOT/v1/android"
# Codespaces can kill Android lint when several JVM/worker processes overlap.
# Keep the canonical tasks and ordering, but serialize Gradle work and cap the
# single-use daemon heap for this constrained environment.
"$GRADLE_BIN" --stop >/dev/null 2>&1 || true
GRADLE_LOW_MEM=(--no-daemon --max-workers=1 "-Dorg.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8")
"$GRADLE_BIN" "${GRADLE_LOW_MEM[@]}" :app:testDebugUnitTest
"$GRADLE_BIN" "${GRADLE_LOW_MEM[@]}" :app:compileDebugJavaWithJavac
"$GRADLE_BIN" "${GRADLE_LOW_MEM[@]}" :app:lintDebug
"$GRADLE_BIN" "${GRADLE_LOW_MEM[@]}" :app:assembleDebug
'''
if source.count(old) != 1:
    raise SystemExit("canonical Gradle block changed; refusing low-memory rewrite")
out.write_text(source.replace(old, new), encoding="utf-8")
PY

exec bash "$TMP"
