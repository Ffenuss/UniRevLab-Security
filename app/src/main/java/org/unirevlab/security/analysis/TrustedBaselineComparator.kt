package org.unirevlab.security.analysis

import org.unirevlab.security.model.AssessmentHistoryEntry
import org.unirevlab.security.model.BaselineComparison
import org.unirevlab.security.model.BaselineVerdict
import org.unirevlab.security.model.StaticAnalysisReport

object TrustedBaselineComparator {
    fun compare(baseline: AssessmentHistoryEntry?, current: StaticAnalysisReport): BaselineComparison {
        val currentPackage = current.manifest?.packageName ?: current.artifact.sourcePackageName
        val currentSigners = current.manifest?.signingCertificateSha256.orEmpty()
            .map { it.lowercase() }
            .toSet()
        val baselineSigners = baseline?.signingCertificateSha256.orEmpty()
            .map { it.lowercase() }
            .toSet()

        val signerContinuity = when {
            baseline == null -> null
            baselineSigners.isEmpty() || currentSigners.isEmpty() -> null
            else -> baselineSigners.intersect(currentSigners).isNotEmpty()
        }
        val currentVersionCode = current.manifest?.versionCode
        val versionChanged = baseline?.versionCode?.let { old -> currentVersionCode?.let { old != it } }
        val sizeDelta = baseline?.sizeBytes?.let { old -> current.artifact.sizeBytes?.let { it - old } }

        val verdict = when {
            baseline == null -> BaselineVerdict.NO_BASELINE
            baseline.packageName.isNullOrBlank() || currentPackage.isNullOrBlank() -> BaselineVerdict.INCOMPLETE_IDENTITY
            baseline.packageName != currentPackage -> BaselineVerdict.NOT_COMPARABLE
            baseline.artifactSha256.equals(current.artifact.sha256, ignoreCase = true) -> BaselineVerdict.SAME_ARTIFACT
            signerContinuity == false -> BaselineVerdict.SIGNER_CHANGED
            else -> BaselineVerdict.MODIFIED
        }

        return BaselineComparison(
            verdict = verdict,
            baseline = baseline,
            currentPackageName = currentPackage,
            currentSha256 = current.artifact.sha256,
            signerContinuity = signerContinuity,
            versionChanged = versionChanged,
            sizeDeltaBytes = sizeDelta,
        )
    }
}
