#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-m24-smoke.jar"
kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ArchiveClassifier.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ApkArchiveIndex.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ManagedMetadataReconstructor.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/RuntimeArtifactScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/SupplyChainScanner.kt" \
  "$ROOT/test-corpus/smoke/M24RuntimeMetadataSmoke.kt" \
  -include-runtime -d "$OUT"
java -jar "$OUT"
