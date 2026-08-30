package org.unirevlab.security.analysis

import org.unirevlab.security.model.GhidraLibraryAnalysis
import org.unirevlab.security.model.StaticAnalysisReport

/** Validates remote/worker deep-native results before attaching them to a local assessment report. */
object GhidraResultIntegrator {
    fun attach(report: StaticAnalysisReport, results: List<GhidraLibraryAnalysis>): StaticAnalysisReport {
        require(report.assessment.reverseEngineering) { "Assessment does not authorize reverse engineering" }
        results.forEach { result ->
            require(result.schemaVersion in setOf("1.1", "1.2", "1.3")) { "Unsupported Ghidra result schema: ${result.schemaVersion}" }
            require(result.assessmentId == report.assessment.assessmentId) { "Ghidra assessment identity mismatch" }
            require(result.artifactSha256.equals(report.artifact.sha256, ignoreCase = true)) { "Ghidra artifact identity mismatch" }
        }
        val normalized = results
            .distinctBy { it.libraryEntry }
            .sortedBy { it.libraryEntry }
        val correlations = CrossRuntimeCorrelator.correlate(report.dex, report.il2cpp, normalized)
        return report.copy(ghidra = normalized, correlations = correlations)
    }
}
