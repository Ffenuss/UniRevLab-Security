package org.unirevlab.security.analysis

import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Customer-facing synthesis over evidence already collected by the static-analysis pipeline.
 *
 * The summary intentionally does not invent a universal "security score". Risk is derived from the
 * highest-priority finding, while analysis coverage is reported separately so a sparse/partial scan
 * cannot look deceptively clean.
 */
object ExecutiveSummaryEngine {
    enum class RiskBand { CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, NO_FINDINGS }
    enum class CoverageState { COMPLETE, PARTIAL, MISSING, NOT_APPLICABLE }

    data class CoverageCheck(
        val title: String,
        val state: CoverageState,
        val detail: String,
    )

    data class Summary(
        val riskBand: RiskBand,
        val critical: Int,
        val high: Int,
        val medium: Int,
        val low: Int,
        val informational: Int,
        val coverageChecks: List<CoverageCheck>,
        val coveragePassed: Int,
        val coverageExpected: Int,
        val exportedComponents: Int,
        val dangerousPermissions: Int,
        val deepLinks: Int,
        val providers: Int,
        val cleartextTraffic: Boolean?,
        val protectionPresent: Int,
        val protectionNotDetected: Int,
        val protectionUnknown: Int,
        val obfuscationScore: Int?,
        val likelyObfuscated: Boolean?,
        val deserializationSurfaces: Int,
        val highRiskDeserialization: Int,
        val externallyReachableDeserialization: Int,
        val topFindings: List<Finding>,
        val recommendations: List<String>,
    ) {
        val totalFindings: Int get() = critical + high + medium + low + informational
        val coverageLabel: String get() = if (coverageExpected == 0) "N/A" else "$coveragePassed/$coverageExpected"
    }

    fun summarize(report: StaticAnalysisReport): Summary {
        val findings = report.findings.sortedWith(FINDING_ORDER)
        val manifest = report.manifest
        val dex = report.dex
        val native = report.native

        val coverage = buildList {
            if (report.artifact.hasAndroidManifest) {
                add(
                    CoverageCheck(
                        title = "AndroidManifest",
                        state = if (manifest != null) CoverageState.COMPLETE else CoverageState.MISSING,
                        detail = if (manifest != null) "Manifest parsed" else "Manifest expected but parser result is unavailable",
                    ),
                )
            } else {
                add(CoverageCheck("AndroidManifest", CoverageState.NOT_APPLICABLE, "Manifest not present in selected artifact"))
            }

            if (report.artifact.dexFiles > 0) {
                val complete = dex != null && !dex.truncated && dex.parseErrors == 0 && dex.dexFilesScanned >= dex.dexFilesDiscovered
                val state = when {
                    dex == null -> CoverageState.MISSING
                    complete -> CoverageState.COMPLETE
                    else -> CoverageState.PARTIAL
                }
                val detail = if (dex == null) {
                    "DEX files expected but index is unavailable"
                } else {
                    "${dex.dexFilesScanned}/${dex.dexFilesDiscovered} DEX · parse errors ${dex.parseErrors} · truncated=${dex.truncated}"
                }
                add(CoverageCheck("DEX / code index", state, detail))
            } else {
                add(CoverageCheck("DEX / code index", CoverageState.NOT_APPLICABLE, "No DEX files discovered"))
            }

            if (report.artifact.nativeLibraries > 0) {
                val complete = native != null && !native.truncated && native.parseErrors == 0 && native.librariesScanned >= native.librariesDiscovered
                val state = when {
                    native == null -> CoverageState.MISSING
                    complete -> CoverageState.COMPLETE
                    else -> CoverageState.PARTIAL
                }
                val detail = if (native == null) {
                    "Native libraries expected but ELF index is unavailable"
                } else {
                    "${native.librariesScanned}/${native.librariesDiscovered} libraries · parse errors ${native.parseErrors} · truncated=${native.truncated}"
                }
                add(CoverageCheck("Native / ELF", state, detail))
            } else {
                add(CoverageCheck("Native / ELF", CoverageState.NOT_APPLICABLE, "No native libraries discovered"))
            }

            if (manifest != null) {
                val signingOk = manifest.signingParseError == null &&
                    (manifest.signingSchemes.isNotEmpty() || manifest.signingCertificates.isNotEmpty() || manifest.v1SignatureFiles.isNotEmpty())
                add(
                    CoverageCheck(
                        "APK signing",
                        if (signingOk) CoverageState.COMPLETE else CoverageState.PARTIAL,
                        manifest.signingParseError ?: "Schemes ${manifest.signingSchemes.joinToString().ifBlank { "not identified" }} · certs ${manifest.signingCertificates.size}",
                    ),
                )

                val nsc = manifest.networkSecurity
                val networkState = when {
                    nsc == null && manifest.networkSecurityConfigConfigured == true -> CoverageState.MISSING
                    nsc == null -> CoverageState.COMPLETE
                    nsc.parseErrors == 0 && !nsc.truncated -> CoverageState.COMPLETE
                    else -> CoverageState.PARTIAL
                }
                add(
                    CoverageCheck(
                        "Network security metadata",
                        networkState,
                        when {
                            nsc == null && manifest.networkSecurityConfigConfigured == true -> "Network Security Config declared but could not be resolved"
                            nsc == null -> "No custom Network Security Config required"
                            else -> "parse errors ${nsc.parseErrors} · truncated=${nsc.truncated} · pin-set=${nsc.pinSetPresent}"
                        },
                    ),
                )
            }
        }

        val expected = coverage.count { it.state != CoverageState.NOT_APPLICABLE }
        val passed = coverage.count { it.state == CoverageState.COMPLETE }

        val posture = ProtectionPostureEngine.scan(report)
        val serialization = SerializationInspector.scan(report)
        val deobfuscation = if (dex != null) DeobfuscationEngine.analyze(report) else null

        return Summary(
            riskBand = riskBand(findings),
            critical = findings.count { it.severity == Severity.CRITICAL },
            high = findings.count { it.severity == Severity.HIGH },
            medium = findings.count { it.severity == Severity.MEDIUM },
            low = findings.count { it.severity == Severity.LOW },
            informational = findings.count { it.severity == Severity.INFORMATIONAL },
            coverageChecks = coverage,
            coveragePassed = passed,
            coverageExpected = expected,
            exportedComponents = manifest?.components?.count { it.exported } ?: 0,
            dangerousPermissions = manifest?.dangerousPermissions?.size ?: 0,
            deepLinks = manifest?.deepLinks?.size ?: 0,
            providers = manifest?.providers?.size ?: 0,
            cleartextTraffic = manifest?.usesCleartextTraffic,
            protectionPresent = posture.presentCount,
            protectionNotDetected = posture.notDetectedCount,
            protectionUnknown = posture.unknownCount,
            obfuscationScore = deobfuscation?.score,
            likelyObfuscated = deobfuscation?.likelyObfuscated,
            deserializationSurfaces = serialization.surfaces.size,
            highRiskDeserialization = serialization.highRiskCount,
            externallyReachableDeserialization = serialization.externallyReachableCount,
            topFindings = findings.take(6),
            recommendations = findings.asSequence()
                .filter { it.remediation.isNotBlank() }
                .map { it.remediation.trim() }
                .distinct()
                .take(5)
                .toList(),
        )
    }

    fun toMarkdown(report: StaticAnalysisReport, summary: Summary): String = buildString {
        val manifest = report.manifest
        appendLine("# UniRevLab Security — Executive Summary")
        appendLine()
        appendLine("- Artifact: ${report.artifact.displayName}")
        appendLine("- Package: ${manifest?.packageName ?: report.artifact.sourcePackageName ?: "unknown"}")
        appendLine("- SHA-256: ${report.artifact.sha256}")
        appendLine("- Risk band: ${summary.riskBand}")
        appendLine("- Analysis coverage: ${summary.coverageLabel}")
        appendLine("- Findings: ${summary.totalFindings} (Critical ${summary.critical}, High ${summary.high}, Medium ${summary.medium}, Low ${summary.low}, Info ${summary.informational})")
        appendLine()
        appendLine("## Attack surface")
        appendLine("- Exported components: ${summary.exportedComponents}")
        appendLine("- Dangerous permissions: ${summary.dangerousPermissions}")
        appendLine("- Deep links: ${summary.deepLinks}")
        appendLine("- Content providers: ${summary.providers}")
        appendLine("- Cleartext traffic allowed: ${summary.cleartextTraffic ?: "unknown"}")
        appendLine()
        appendLine("## Protection / resilience")
        appendLine("- Detected checks: ${summary.protectionPresent}")
        appendLine("- Not detected: ${summary.protectionNotDetected}")
        appendLine("- Unknown: ${summary.protectionUnknown}")
        appendLine("- Obfuscation score: ${summary.obfuscationScore?.let { "$it/100" } ?: "N/A"}")
        appendLine("- Deserialization surfaces: ${summary.deserializationSurfaces}; high-risk ${summary.highRiskDeserialization}; exported-graph reachable ${summary.externallyReachableDeserialization}")
        appendLine()
        appendLine("## Coverage")
        summary.coverageChecks.forEach { appendLine("- ${it.state}: ${it.title} — ${it.detail}") }
        appendLine()
        appendLine("## Priority findings")
        if (summary.topFindings.isEmpty()) {
            appendLine("No rule-based findings were produced. This is not proof that the application is vulnerability-free.")
        } else {
            summary.topFindings.forEachIndexed { index, finding ->
                appendLine("### ${index + 1}. [${finding.severity}] ${finding.title}")
                appendLine(finding.description)
                appendLine()
                appendLine("Remediation: ${finding.remediation}")
                appendLine()
            }
        }
        appendLine("## Recommended next actions")
        if (summary.recommendations.isEmpty()) appendLine("- Perform manual review of trust boundaries and externally reachable flows.")
        else summary.recommendations.forEach { appendLine("- $it") }
        appendLine()
        appendLine("> Scope note: this summary synthesizes the collected static-analysis evidence. It is not a certification and does not claim runtime exploitability unless separately validated.")
    }

    private fun riskBand(findings: List<Finding>): RiskBand = when {
        findings.any { it.severity == Severity.CRITICAL } -> RiskBand.CRITICAL
        findings.any { it.severity == Severity.HIGH } -> RiskBand.HIGH
        findings.any { it.severity == Severity.MEDIUM } -> RiskBand.MEDIUM
        findings.any { it.severity == Severity.LOW } -> RiskBand.LOW
        findings.any { it.severity == Severity.INFORMATIONAL } -> RiskBand.INFORMATIONAL
        else -> RiskBand.NO_FINDINGS
    }

    private val FINDING_ORDER = compareBy<Finding> {
        when (it.severity) {
            Severity.CRITICAL -> 0
            Severity.HIGH -> 1
            Severity.MEDIUM -> 2
            Severity.LOW -> 3
            Severity.INFORMATIONAL -> 4
        }
    }.thenBy {
        when (it.confidence.name) {
            "CONFIRMED" -> 0
            "HIGH" -> 1
            "MEDIUM" -> 2
            else -> 3
        }
    }.thenBy { it.id }
}
