#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v014-smoke"
rm -rf "$OUT" && mkdir -p "$OUT"
kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentDiffModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ReBrowserIndex.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ReportJsonExporter.kt" \
  "$ROOT/test-corpus/smoke/V014GhidraIntegrationSmoke.kt" \
  -include-runtime -d "$OUT/v014.jar"
java -jar "$OUT/v014.jar" "$OUT"
python3 - "$ROOT" "$OUT/static-analysis-report.json" <<'PY'
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator
root = Path(sys.argv[1])
report = json.loads(Path(sys.argv[2]).read_text())
schema = json.loads((root / "schemas/static-analysis-report.schema.json").read_text())
Draft202012Validator(schema).validate(report)
print("static report schema 1.19: PASS")
PY
