#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v020-smoke"
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
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ReportJsonExporter.kt" \
  "$ROOT/test-corpus/smoke/V020AuthFeedEvidenceSmoke.kt" \
  -include-runtime -d "$OUT/v020.jar"
java -jar "$OUT/v020.jar"
python3 - "$ROOT" <<'PY'
import json, re, sys
from pathlib import Path
from jsonschema import Draft202012Validator
root=Path(sys.argv[1])
Draft202012Validator.check_schema(json.loads((root/'schemas/static-analysis-report.schema.json').read_text()))
assert '"const": "1.19"' in (root/'schemas/static-analysis-report.schema.json').read_text()
workflow=(root/'.github/workflows/release.yml').read_text()
assert re.search(r'needs:\s*ghidra-release-gate', workflow)
assert 'release-signing-evidence.txt' in workflow
assert 'capture_release_toolchain.py' in workflow
print('v0.20 schema/release contract smoke PASS')
PY
