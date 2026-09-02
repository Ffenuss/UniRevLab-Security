package org.unirevlab.security.model

enum class BaselineVerdict {
    NO_BASELINE,
    SAME_ARTIFACT,
    MODIFIED,
    SIGNER_CHANGED,
    NOT_COMPARABLE,
    INCOMPLETE_IDENTITY,
}

data class AssessmentHistoryEntry(
    val id: String,
    val assessmentId: String,
    val analyzedAtEpochMs: Long,
    val projectName: String,
    val organization: String,
    val artifactDisplayName: String,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val artifactSha256: String,
    val sizeBytes: Long?,
    val sourceKind: String,
    val splitApkCount: Int,
    val signingCertificateSha256: List<String>,
    val findingCount: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val informationalCount: Int,
    val dexFiles: Int?,
    val methodsIndexed: Long?,
    val nativeLibraries: Int?,
    val engineVersion: String,
    val schemaVersion: String,
)

data class BaselineComparison(
    val verdict: BaselineVerdict,
    val baseline: AssessmentHistoryEntry?,
    val currentPackageName: String?,
    val currentSha256: String,
    val signerContinuity: Boolean?,
    val versionChanged: Boolean?,
    val sizeDeltaBytes: Long?,
) {
    val hasTrustedBaseline: Boolean get() = baseline != null
}
