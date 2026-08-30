#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v021-smoke"
rm -rf "$OUT" && mkdir -p "$OUT"
kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/EcosystemVersionRangeResolver.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/VulnerabilityAdvisoryCorrelator.kt" \
  "$ROOT/test-corpus/smoke/V021RangeRbacAttestationSmoke.kt" \
  -include-runtime -d "$OUT/v021.jar"
java -jar "$OUT/v021.jar"
python3 - "$ROOT" <<'PY'
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator
root=Path(sys.argv[1])
for name in ('static-analysis-report.schema.json','signed-feed-envelope.schema.json','release-manifest.schema.json'):
    Draft202012Validator.check_schema(json.loads((root/'schemas'/name).read_text()))
assert json.loads((root/'schemas/static-analysis-report.schema.json').read_text())['properties']['schemaVersion']['const']=='1.19'
print('v0.21 schema smoke PASS')
PY
