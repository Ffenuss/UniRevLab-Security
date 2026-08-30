#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v012-smoke"
rm -rf "$OUT" && mkdir -p "$OUT"

kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/AxmlManifestOverlayModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/KotlinAxmlManifestParser.kt" \
  "$ROOT/test-corpus/smoke/KotlinAxmlSmoke.kt" \
  -include-runtime -d "$OUT/axml.jar"
java -jar "$OUT/axml.jar"

kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ApkSigningSchemeScanner.kt" \
  "$ROOT/test-corpus/smoke/ApkSigningSmoke.kt" \
  -include-runtime -d "$OUT/signing.jar"
java -jar "$OUT/signing.jar"

kotlinc \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/AxmlManifestOverlayModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/KotlinAxmlManifestParser.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/NetworkSecurityConfigScanner.kt" \
  "$ROOT/test-corpus/smoke/NetworkSecurityConfigSmoke.kt" \
  -include-runtime -d "$OUT/network-security.jar"
java -jar "$OUT/network-security.jar"

python3 "$ROOT/scripts/validate_schemas.py"
python3 "$ROOT/scripts/check_secrets.py" "$ROOT"
echo "v0.12 installed-source/AXML/signing/network-security smoke: PASS"
