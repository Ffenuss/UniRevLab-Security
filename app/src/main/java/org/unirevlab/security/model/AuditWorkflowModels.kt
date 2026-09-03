package org.unirevlab.security.model

import org.json.JSONArray
import org.json.JSONObject

enum class AuditSourceKind { FILE_URI, INSTALLED_APP }

enum class AuditStage(
    val code: String,
    val title: String,
    val defaultProgress: Int,
) {
    QUEUED("queued", "В очереди", 0),
    PREPARING("preparing", "Подготовка входных данных", 4),
    ARCHIVE("archive", "Структура APK и подпись", 12),
    MANIFEST("manifest", "Manifest и ресурсы", 22),
    DEX("dex", "DEX, вызовы и поверхности доверия", 38),
    NATIVE("native", "Native ELF и JNI", 58),
    IL2CPP("il2cpp", "IL2CPP и runtime-метаданные", 72),
    SUPPLY_CHAIN("supply_chain", "Компоненты и зависимости", 80),
    GRADLE_MODULES("gradle_modules", "Gradle и модули приложения", 86),
    REPORT("report", "Отчёт и рекомендации", 90),
    ARTIFACTS("artifacts", "Пакет артефактов и RVA", 94),
    SIGNING("signing", "Подпись evidence-пакета", 98),
    COMPLETE("complete", "Готово", 100),
    CANCELLED("cancelled", "Отменено", 0),
    FAILED("failed", "Ошибка", 0),
    ;

    companion object {
        fun fromCode(code: String?): AuditStage = entries.firstOrNull { it.code == code } ?: QUEUED
    }
}

data class AuditProfile(
    val projectName: String,
    val organization: String,
    val purpose: String,
    val staticAnalysis: Boolean = true,
    val reverseEngineering: Boolean = true,
    val dynamicAnalysis: Boolean = false,
    val networkTesting: Boolean = false,
) {
    val isValid: Boolean
        get() = projectName.isNotBlank() && organization.isNotBlank() && purpose.isNotBlank()

    fun createScope(): AssessmentScope = AssessmentScope(
        projectName = projectName.trim(),
        organization = organization.trim(),
        purpose = purpose.trim(),
        confirmsAuthority = true,
        staticAnalysis = staticAnalysis,
        reverseEngineering = reverseEngineering,
        dynamicAnalysis = dynamicAnalysis,
        networkTesting = networkTesting,
    )
}

data class AuditSourceSpec(
    val kind: AuditSourceKind,
    val displayName: String,
    val uri: String? = null,
    val packageName: String? = null,
    val baseApkPath: String? = null,
    val splitApkPaths: List<String> = emptyList(),
    val versionName: String? = null,
    val versionCode: Long? = null,
    val installerPackageName: String? = null,
)

data class AuditJobSpec(
    val schemaVersion: String = "1.0",
    val jobId: String,
    val createdAtEpochMs: Long,
    val scope: AssessmentScope,
    val source: AuditSourceSpec,
)

data class AuditJobSummary(
    val schemaVersion: String = "1.0",
    val jobId: String,
    val completedAtEpochMs: Long,
    val displayName: String,
    val packageName: String?,
    val artifactSha256: String,
    val runtimeLabels: List<String>,
    val findings: Int,
    val critical: Int,
    val high: Int,
    val medium: Int,
    val dexMethods: Long,
    val nativeLibraries: Int,
    val il2cppDetected: Boolean,
    val il2cppMetadataVersion: Int?,
    val exportedArtifactCount: Int,
    val outputFiles: List<String>,
)

data class PersistedAuditState(
    val jobId: String,
    val stage: AuditStage,
    val progress: Int,
    val message: String,
    val updatedAtEpochMs: Long,
    val error: String? = null,
)

object AuditWorkflowJson {
    fun encodeProfile(value: AuditProfile): String = JSONObject()
        .put("projectName", value.projectName)
        .put("organization", value.organization)
        .put("purpose", value.purpose)
        .put("staticAnalysis", value.staticAnalysis)
        .put("reverseEngineering", value.reverseEngineering)
        .put("dynamicAnalysis", value.dynamicAnalysis)
        .put("networkTesting", value.networkTesting)
        .toString()

    fun decodeProfile(value: String): AuditProfile = JSONObject(value).let { json ->
        AuditProfile(
            projectName = json.getString("projectName"),
            organization = json.getString("organization"),
            purpose = json.getString("purpose"),
            staticAnalysis = json.optBoolean("staticAnalysis", true),
            reverseEngineering = json.optBoolean("reverseEngineering", true),
            dynamicAnalysis = json.optBoolean("dynamicAnalysis", false),
            networkTesting = json.optBoolean("networkTesting", false),
        )
    }

    fun encodeSpec(value: AuditJobSpec): String = JSONObject()
        .put("schemaVersion", value.schemaVersion)
        .put("jobId", value.jobId)
        .put("createdAtEpochMs", value.createdAtEpochMs)
        .put("scope", encodeScope(value.scope))
        .put("source", encodeSource(value.source))
        .toString(2)

    fun decodeSpec(value: String): AuditJobSpec = JSONObject(value).let { json ->
        AuditJobSpec(
            schemaVersion = json.optString("schemaVersion", "1.0"),
            jobId = json.getString("jobId"),
            createdAtEpochMs = json.getLong("createdAtEpochMs"),
            scope = decodeScope(json.getJSONObject("scope")),
            source = decodeSource(json.getJSONObject("source")),
        )
    }

    fun encodeSummary(value: AuditJobSummary): String = JSONObject()
        .put("schemaVersion", value.schemaVersion)
        .put("jobId", value.jobId)
        .put("completedAtEpochMs", value.completedAtEpochMs)
        .put("displayName", value.displayName)
        .putNullable("packageName", value.packageName)
        .put("artifactSha256", value.artifactSha256)
        .put("runtimeLabels", JSONArray(value.runtimeLabels))
        .put("findings", value.findings)
        .put("critical", value.critical)
        .put("high", value.high)
        .put("medium", value.medium)
        .put("dexMethods", value.dexMethods)
        .put("nativeLibraries", value.nativeLibraries)
        .put("il2cppDetected", value.il2cppDetected)
        .putNullable("il2cppMetadataVersion", value.il2cppMetadataVersion)
        .put("exportedArtifactCount", value.exportedArtifactCount)
        .put("outputFiles", JSONArray(value.outputFiles))
        .toString(2)

    fun decodeSummary(value: String): AuditJobSummary = JSONObject(value).let { json ->
        AuditJobSummary(
            schemaVersion = json.optString("schemaVersion", "1.0"),
            jobId = json.getString("jobId"),
            completedAtEpochMs = json.getLong("completedAtEpochMs"),
            displayName = json.getString("displayName"),
            packageName = json.stringOrNull("packageName"),
            artifactSha256 = json.getString("artifactSha256"),
            runtimeLabels = json.getJSONArray("runtimeLabels").strings(),
            findings = json.getInt("findings"),
            critical = json.getInt("critical"),
            high = json.getInt("high"),
            medium = json.getInt("medium"),
            dexMethods = json.getLong("dexMethods"),
            nativeLibraries = json.getInt("nativeLibraries"),
            il2cppDetected = json.getBoolean("il2cppDetected"),
            il2cppMetadataVersion = json.intOrNull("il2cppMetadataVersion"),
            exportedArtifactCount = json.getInt("exportedArtifactCount"),
            outputFiles = json.getJSONArray("outputFiles").strings(),
        )
    }

    fun encodeState(value: PersistedAuditState): String = JSONObject()
        .put("jobId", value.jobId)
        .put("stage", value.stage.code)
        .put("progress", value.progress.coerceIn(0, 100))
        .put("message", value.message)
        .put("updatedAtEpochMs", value.updatedAtEpochMs)
        .putNullable("error", value.error)
        .toString(2)

    fun decodeState(value: String): PersistedAuditState = JSONObject(value).let { json ->
        PersistedAuditState(
            jobId = json.getString("jobId"),
            stage = AuditStage.fromCode(json.getString("stage")),
            progress = json.getInt("progress").coerceIn(0, 100),
            message = json.getString("message"),
            updatedAtEpochMs = json.getLong("updatedAtEpochMs"),
            error = json.stringOrNull("error"),
        )
    }

    private fun encodeScope(value: AssessmentScope): JSONObject = JSONObject()
        .put("assessmentId", value.assessmentId)
        .put("createdAtEpochMs", value.createdAtEpochMs)
        .put("projectName", value.projectName)
        .put("organization", value.organization)
        .put("purpose", value.purpose)
        .put("confirmsAuthority", value.confirmsAuthority)
        .put("staticAnalysis", value.staticAnalysis)
        .put("reverseEngineering", value.reverseEngineering)
        .put("dynamicAnalysis", value.dynamicAnalysis)
        .put("networkTesting", value.networkTesting)

    private fun decodeScope(json: JSONObject): AssessmentScope = AssessmentScope(
        assessmentId = json.getString("assessmentId"),
        createdAtEpochMs = json.getLong("createdAtEpochMs"),
        projectName = json.getString("projectName"),
        organization = json.getString("organization"),
        purpose = json.getString("purpose"),
        confirmsAuthority = json.getBoolean("confirmsAuthority"),
        staticAnalysis = json.optBoolean("staticAnalysis", true),
        reverseEngineering = json.optBoolean("reverseEngineering", true),
        dynamicAnalysis = json.optBoolean("dynamicAnalysis", false),
        networkTesting = json.optBoolean("networkTesting", false),
    )

    private fun encodeSource(value: AuditSourceSpec): JSONObject = JSONObject()
        .put("kind", value.kind.name)
        .put("displayName", value.displayName)
        .putNullable("uri", value.uri)
        .putNullable("packageName", value.packageName)
        .putNullable("baseApkPath", value.baseApkPath)
        .put("splitApkPaths", JSONArray(value.splitApkPaths))
        .putNullable("versionName", value.versionName)
        .putNullable("versionCode", value.versionCode)
        .putNullable("installerPackageName", value.installerPackageName)

    private fun decodeSource(json: JSONObject): AuditSourceSpec = AuditSourceSpec(
        kind = AuditSourceKind.valueOf(json.getString("kind")),
        displayName = json.getString("displayName"),
        uri = json.stringOrNull("uri"),
        packageName = json.stringOrNull("packageName"),
        baseApkPath = json.stringOrNull("baseApkPath"),
        splitApkPaths = json.optJSONArray("splitApkPaths")?.strings().orEmpty(),
        versionName = json.stringOrNull("versionName"),
        versionCode = json.longOrNull("versionCode"),
        installerPackageName = json.stringOrNull("installerPackageName"),
    )

    private fun JSONObject.putNullable(key: String, value: Any?): JSONObject = put(key, value ?: JSONObject.NULL)

    private fun JSONObject.stringOrNull(key: String): String? =
        if (!has(key) || isNull(key)) null else optString(key).takeIf { it.isNotBlank() }

    private fun JSONObject.longOrNull(key: String): Long? =
        if (!has(key) || isNull(key)) null else getLong(key)

    private fun JSONObject.intOrNull(key: String): Int? =
        if (!has(key) || isNull(key)) null else getInt(key)

    private fun JSONArray.strings(): List<String> = List(length()) { index -> getString(index) }
}
