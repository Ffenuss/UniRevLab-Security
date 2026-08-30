#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v020-adapter-compile"
rm -rf "$OUT" && mkdir -p "$OUT/org/json"
cat > "$OUT/org/json/JSONObject.kt" <<'KOT'
package org.json
class JSONObject {
    constructor(text: String)
    constructor()
    fun optString(key: String): String = ""
    fun optString(key: String, fallback: String): String = fallback
    fun getString(key: String): String = ""
    fun has(key: String): Boolean = false
    fun optJSONArray(key: String): JSONArray? = null
    fun getJSONArray(key: String): JSONArray = JSONArray()
    fun optJSONObject(key: String): JSONObject? = null
    fun getJSONObject(key: String): JSONObject = JSONObject()
    fun optBoolean(key: String, fallback: Boolean): Boolean = fallback
    fun put(key: String, value: Any?): JSONObject = this
}
KOT
cat > "$OUT/org/json/JSONArray.kt" <<'KOT'
package org.json
class JSONArray {
    constructor()
    constructor(text: String)
    fun length(): Int = 0
    fun optJSONObject(index: Int): JSONObject? = null
    fun getJSONObject(index: Int): JSONObject = JSONObject()
    fun optString(index: Int): String = ""
    fun getString(index: Int): String = ""
    fun put(value: Any?): JSONArray = this
}
KOT
cat > "$OUT/org/json/JSONTokener.kt" <<'KOT'
package org.json
class JSONTokener(text: String) { fun nextValue(): Any = JSONObject() }
KOT
kotlinc \
  "$OUT/org/json/JSONObject.kt" "$OUT/org/json/JSONArray.kt" "$OUT/org/json/JSONTokener.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/AssessmentScope.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ArtifactSummary.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/ResourceTableModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/GhidraAnalysisModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/EcosystemVersionRangeResolver.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/VulnerabilityAdvisoryCorrelator.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/AdvisoryFeedJsonParser.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/ExternalAdvisoryFeedImporter.kt" \
  "$ROOT/app/src/main/java/org/unirevlab/security/analysis/SignedFeedEnvelopeVerifier.kt" \
  -d "$OUT/adapter-check.jar" >/dev/null
printf '%s\n' 'v0.20 external advisory adapter Kotlin compile: PASS'
