package org.unirevlab.security.data

import android.content.Context
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.analysis.TrustedBaselineComparator
import org.unirevlab.security.model.AssessmentHistoryEntry
import org.unirevlab.security.model.BaselineComparison
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport

class AssessmentHistoryStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun list(): List<AssessmentHistoryEntry> = decodeEntries(prefs.getString(KEY_ENTRIES, null))
        .sortedByDescending { it.analyzedAtEpochMs }

    fun record(report: StaticAnalysisReport): AssessmentHistoryEntry {
        val manifest = report.manifest
        val entry = AssessmentHistoryEntry(
            id = UUID.randomUUID().toString(),
            assessmentId = report.assessment.assessmentId,
            analyzedAtEpochMs = System.currentTimeMillis(),
            projectName = report.assessment.projectName,
            organization = report.assessment.organization,
            artifactDisplayName = report.artifact.displayName,
            packageName = manifest?.packageName ?: report.artifact.sourcePackageName,
            versionName = manifest?.versionName,
            versionCode = manifest?.versionCode,
            artifactSha256 = report.artifact.sha256,
            sizeBytes = report.artifact.sizeBytes,
            sourceKind = report.artifact.sourceKind,
            splitApkCount = report.artifact.splitApkCount,
            signingCertificateSha256 = manifest?.signingCertificateSha256.orEmpty().distinct().sorted(),
            findingCount = report.findings.size,
            criticalCount = report.findings.count { it.severity == Severity.CRITICAL },
            highCount = report.findings.count { it.severity == Severity.HIGH },
            mediumCount = report.findings.count { it.severity == Severity.MEDIUM },
            lowCount = report.findings.count { it.severity == Severity.LOW },
            informationalCount = report.findings.count { it.severity == Severity.INFORMATIONAL },
            dexFiles = report.artifact.dexFiles,
            methodsIndexed = report.dex?.methodsIndexed,
            nativeLibraries = report.artifact.nativeLibraries,
            engineVersion = report.engineVersion,
            schemaVersion = report.schemaVersion,
        )
        val updated = buildList {
            add(entry)
            addAll(list().filterNot { it.assessmentId == entry.assessmentId })
        }.take(MAX_ENTRIES)
        persistEntries(updated)
        pruneBaselines(updated)
        return entry
    }

    fun baselineEntryIds(): Set<String> {
        val validIds = list().mapTo(mutableSetOf()) { it.id }
        return baselineMap().values.filterTo(mutableSetOf()) { it in validIds }
    }

    fun setBaseline(entryId: String) {
        val entry = list().firstOrNull { it.id == entryId }
            ?: throw IllegalArgumentException("Историческая запись не найдена")
        val packageName = entry.packageName?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("Baseline требует определённый package name")
        val map = baselineMap().toMutableMap()
        map[packageName] = entry.id
        persistBaselineMap(map)
    }

    fun clearBaseline(packageName: String) {
        val map = baselineMap().toMutableMap()
        map.remove(packageName)
        persistBaselineMap(map)
    }

    fun remove(entryId: String) {
        val updated = list().filterNot { it.id == entryId }
        persistEntries(updated)
        pruneBaselines(updated)
    }

    fun baselineFor(report: StaticAnalysisReport): AssessmentHistoryEntry? {
        val packageName = report.manifest?.packageName ?: report.artifact.sourcePackageName ?: return null
        val id = baselineMap()[packageName] ?: return null
        return list().firstOrNull { it.id == id }
    }

    fun compare(report: StaticAnalysisReport): BaselineComparison =
        TrustedBaselineComparator.compare(baselineFor(report), report)

    private fun persistEntries(entries: List<AssessmentHistoryEntry>) {
        val array = JSONArray()
        entries.forEach { array.put(encodeEntry(it)) }
        prefs.edit().putString(KEY_ENTRIES, array.toString()).apply()
    }

    private fun baselineMap(): Map<String, String> = runCatching {
        val objectValue = JSONObject(prefs.getString(KEY_BASELINES, "{}") ?: "{}")
        buildMap {
            val keys = objectValue.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                objectValue.optString(key).takeIf { it.isNotBlank() }?.let { put(key, it) }
            }
        }
    }.getOrDefault(emptyMap())

    private fun persistBaselineMap(values: Map<String, String>) {
        val objectValue = JSONObject()
        values.toSortedMap().forEach { (packageName, entryId) -> objectValue.put(packageName, entryId) }
        prefs.edit().putString(KEY_BASELINES, objectValue.toString()).apply()
    }

    private fun pruneBaselines(entries: List<AssessmentHistoryEntry>) {
        val valid = entries.mapTo(mutableSetOf()) { it.id }
        val pruned = baselineMap().filterValues { it in valid }
        persistBaselineMap(pruned)
    }

    private fun decodeEntries(raw: String?): List<AssessmentHistoryEntry> = runCatching {
        val array = JSONArray(raw ?: "[]")
        buildList {
            for (index in 0 until array.length()) {
                val value = array.optJSONObject(index) ?: continue
                decodeEntry(value)?.let(::add)
            }
        }
    }.getOrDefault(emptyList())

    private fun encodeEntry(value: AssessmentHistoryEntry): JSONObject = JSONObject().apply {
        put("id", value.id)
        put("assessmentId", value.assessmentId)
        put("analyzedAtEpochMs", value.analyzedAtEpochMs)
        put("projectName", value.projectName)
        put("organization", value.organization)
        put("artifactDisplayName", value.artifactDisplayName)
        putNullable("packageName", value.packageName)
        putNullable("versionName", value.versionName)
        if (value.versionCode == null) put("versionCode", JSONObject.NULL) else put("versionCode", value.versionCode)
        put("artifactSha256", value.artifactSha256)
        if (value.sizeBytes == null) put("sizeBytes", JSONObject.NULL) else put("sizeBytes", value.sizeBytes)
        put("sourceKind", value.sourceKind)
        put("splitApkCount", value.splitApkCount)
        put("signingCertificateSha256", JSONArray(value.signingCertificateSha256))
        put("findingCount", value.findingCount)
        put("criticalCount", value.criticalCount)
        put("highCount", value.highCount)
        put("mediumCount", value.mediumCount)
        put("lowCount", value.lowCount)
        put("informationalCount", value.informationalCount)
        if (value.dexFiles == null) put("dexFiles", JSONObject.NULL) else put("dexFiles", value.dexFiles)
        if (value.methodsIndexed == null) put("methodsIndexed", JSONObject.NULL) else put("methodsIndexed", value.methodsIndexed)
        if (value.nativeLibraries == null) put("nativeLibraries", JSONObject.NULL) else put("nativeLibraries", value.nativeLibraries)
        put("engineVersion", value.engineVersion)
        put("schemaVersion", value.schemaVersion)
    }

    private fun decodeEntry(value: JSONObject): AssessmentHistoryEntry? {
        val id = value.optString("id").takeIf { it.isNotBlank() } ?: return null
        val sha = value.optString("artifactSha256").takeIf { it.isNotBlank() } ?: return null
        return AssessmentHistoryEntry(
            id = id,
            assessmentId = value.optString("assessmentId"),
            analyzedAtEpochMs = value.optLong("analyzedAtEpochMs", 0L),
            projectName = value.optString("projectName"),
            organization = value.optString("organization"),
            artifactDisplayName = value.optString("artifactDisplayName"),
            packageName = value.optNullableString("packageName"),
            versionName = value.optNullableString("versionName"),
            versionCode = value.optNullableLong("versionCode"),
            artifactSha256 = sha,
            sizeBytes = value.optNullableLong("sizeBytes"),
            sourceKind = value.optString("sourceKind", "FILE"),
            splitApkCount = value.optInt("splitApkCount", 0),
            signingCertificateSha256 = value.optJSONArray("signingCertificateSha256")?.let { array ->
                buildList {
                    for (index in 0 until array.length()) array.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                }
            }.orEmpty(),
            findingCount = value.optInt("findingCount", 0),
            criticalCount = value.optInt("criticalCount", 0),
            highCount = value.optInt("highCount", 0),
            mediumCount = value.optInt("mediumCount", 0),
            lowCount = value.optInt("lowCount", 0),
            informationalCount = value.optInt("informationalCount", 0),
            dexFiles = value.optNullableInt("dexFiles"),
            methodsIndexed = value.optNullableLong("methodsIndexed"),
            nativeLibraries = value.optNullableInt("nativeLibraries"),
            engineVersion = value.optString("engineVersion"),
            schemaVersion = value.optString("schemaVersion"),
        )
    }

    private fun JSONObject.putNullable(key: String, value: String?) {
        if (value == null) put(key, JSONObject.NULL) else put(key, value)
    }

    private fun JSONObject.optNullableString(key: String): String? =
        if (!has(key) || isNull(key)) null else optString(key).takeIf { it.isNotBlank() }

    private fun JSONObject.optNullableLong(key: String): Long? =
        if (!has(key) || isNull(key)) null else optLong(key)

    private fun JSONObject.optNullableInt(key: String): Int? =
        if (!has(key) || isNull(key)) null else optInt(key)

    private companion object {
        const val PREFS_NAME = "unirevlab_assessment_history_v1"
        const val KEY_ENTRIES = "entries_json"
        const val KEY_BASELINES = "trusted_baselines_json"
        const val MAX_ENTRIES = 120
    }
}
