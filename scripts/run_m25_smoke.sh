#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${TMPDIR:-/tmp}/unirevlab-m25-smoke"
rm -rf "$OUT_DIR" && mkdir -p "$OUT_DIR"
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
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/Il2CppScanner.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/SbomExporter.kt" \
  "$ROOT/test-corpus/smoke/M25DeepMetadataSbomSmoke.kt" \
  -include-runtime -d "$OUT_DIR/m25.jar"
java -jar "$OUT_DIR/m25.jar" "$OUT_DIR"
python3 - "$OUT_DIR/bom.cdx.json" "$OUT_DIR/bom.spdx.jsonld" <<'PY'
import json,sys
cdx=json.load(open(sys.argv[1],encoding='utf-8'))
spdx=json.load(open(sys.argv[2],encoding='utf-8'))
assert cdx['bomFormat']=='CycloneDX' and cdx['specVersion']=='1.6'
assert any(c.get('purl')=='pkg:maven/com.squareup.okhttp3/okhttp@4.12.0' for c in cdx['components'])
assert spdx['@context']=='https://spdx.org/rdf/3.0.1/spdx-context.jsonld'
graph=spdx['@graph']
assert sum(1 for x in graph if x.get('type')=='SpdxDocument')==1
assert any(x.get('type')=='software_Sbom' for x in graph)
assert any(x.get('type')=='Relationship' and x.get('relationshipType')=='dependsOn' for x in graph)
print('M2.5 SBOM JSON structural validation: PASS')
PY
