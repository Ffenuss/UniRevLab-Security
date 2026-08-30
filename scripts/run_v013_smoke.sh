#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v013-smoke"
rm -rf "$OUT" && mkdir -p "$OUT"
kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentDiffModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/AssessmentDiffEngine.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ReBrowserIndex.kt" \
  "$ROOT/test-corpus/smoke/V013ReDiffSmoke.kt" \
  -include-runtime -d "$OUT/v013.jar"
java -jar "$OUT/v013.jar"
