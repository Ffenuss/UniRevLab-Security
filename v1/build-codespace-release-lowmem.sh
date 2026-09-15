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
old = '''cd "$ROOT/v1"
python -m pip install -U pip pytest
python -m pytest tests -q
python -m modkit selftest
python -m modkit runtime-check

cd "$ROOT/v1/android"
"$GRADLE_BIN" --no-daemon :app:testDebugUnitTest
"$GRADLE_BIN" --no-daemon :app:compileDebugJavaWithJavac
"$GRADLE_BIN" --no-daemon :app:lintDebug
"$GRADLE_BIN" --no-daemon :app:assembleDebug
'''
new = r'''STATE_DIR="${HOME}/.cache/modkit-codespace-state/${FULL_SHA}"
mkdir -p "$STATE_DIR"

mark_done(){ touch "$STATE_DIR/$1.ok"; }
is_done(){ test -f "$STATE_DIR/$1.ok"; }

run_plain_stage(){
  local name="$1"; shift
  if is_done "$name"; then
    echo "== checkpoint: $name already passed for $FULL_SHA =="
    return 0
  fi
  echo "== stage: $name =="
  "$@"
  mark_done "$name"
}

run_gradle_stage(){
  local name="$1" task="$2"; shift 2
  if is_done "$name"; then
    echo "== checkpoint: $name already passed for $FULL_SHA =="
    return 0
  fi

  local heaps=(1536 1280 1024 896)
  local heap log rc
  for heap in "${heaps[@]}"; do
    echo "== stage: $name ($task), heap=${heap}m, workers=1 =="
    "$GRADLE_BIN" --stop >/dev/null 2>&1 || true
    log="$STATE_DIR/${name}-${heap}m.log"
    set +e
    "$GRADLE_BIN" --no-daemon --max-workers=1 \
      "-Dorg.gradle.jvmargs=-Xmx${heap}m -Dfile.encoding=UTF-8" \
      -Dorg.gradle.vfs.watch=false \
      -Dkotlin.compiler.execution.strategy=in-process \
      "$task" "$@" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -eq 0 ]; then
      mark_done "$name"
      return 0
    fi
    if grep -Eqi 'daemon disappeared unexpectedly|may have been killed|daemon has disappeared|process was killed' "$log"; then
      echo "Gradle infrastructure crash detected for $name; retrying with smaller heap..."
      sleep 4
      continue
    fi
    echo "Gradle task $task failed with a real build error; not retrying as infrastructure noise." >&2
    return "$rc"
  done
  echo "Gradle task $task kept losing its daemon even at the smallest heap." >&2
  return 86
}

cd "$ROOT/v1"
run_plain_stage pip python -m pip install -U pip pytest
run_plain_stage pytest python -m pytest tests -q
run_plain_stage selftest python -m modkit selftest
run_plain_stage runtime-check python -m modkit runtime-check

cd "$ROOT/v1/android"
run_gradle_stage android-unit :app:testDebugUnitTest
run_gradle_stage javac :app:compileDebugJavaWithJavac
run_gradle_stage lint :app:lintDebug
run_gradle_stage assemble :app:assembleDebug
'''
if source.count(old) != 1:
    raise SystemExit("canonical validation block changed; refusing checkpoint rewrite")
out.write_text(source.replace(old, new), encoding="utf-8")
PY

exec bash "$TMP"
