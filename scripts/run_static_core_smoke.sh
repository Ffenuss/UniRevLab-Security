#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${TMPDIR:-/tmp}/unirevlab-static-core-smoke"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ArchiveClassifier.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ApkArchiveIndex.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/SensitiveStringClassifier.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/DexRuleEngine.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ElfNativeScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/JniBridgeCorrelator.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/NativeRuleEngine.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/Il2CppScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/Il2CppRuleEngine.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/RuntimeProfileScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ManagedMetadataReconstructor.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/RuntimeArtifactScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ReportJsonExporter.kt" \
  "$ROOT/test-corpus/smoke/StaticCoreSmoke.kt" \
  -include-runtime -d "$OUT_DIR/static-core-smoke.jar"

java -jar "$OUT_DIR/static-core-smoke.jar" "$ROOT" "$OUT_DIR/report.json"
python3 - "$ROOT/schemas/static-analysis-report.schema.json" "$OUT_DIR/report.json" <<'PY'
import json
import sys
from jsonschema import Draft202012Validator
schema = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
Draft202012Validator(schema).validate(report)
print("static-core report schema validation: PASS")
PY
