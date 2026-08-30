package org.unirevlab.security.smoke

import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.VulnerabilityAdvisoryCorrelator
import org.unirevlab.security.model.AdvisoryFeedProvenance
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DependencyComponentSummary
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.model.SupplyChainSummary

fun main() {
    val supply = SupplyChainSummary(
        components = listOf(
            DependencyComponentSummary(
                id = "maven:com.squareup.okhttp3:okhttp",
                name = "OkHttp",
                ecosystem = "MAVEN",
                version = "4.12.0",
                confidence = "HIGH",
                evidence = listOf("META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties"),
            )
        ),
        nativeDependencies = emptyList(),
        truncated = false,
    )
    val feed = VulnerabilityAdvisoryCorrelator.Feed(
        provenance = AdvisoryFeedProvenance(
            schemaVersion = "1.0",
            feedId = "osv:fixture",
            source = "OSV",
            generatedAt = "2026-08-30T00:00:00Z",
            sha256 = "a".repeat(64),
            advisoryCount = 1,
            format = "OSV",
            adapterVersion = "1.0",
            skippedAdvisoryCount = 2,
        ),
        advisories = listOf(
            VulnerabilityAdvisoryCorrelator.Advisory(
                id = "GHSA-fixture",
                aliases = listOf("CVE-2099-0001"),
                componentId = "maven:com.squareup.okhttp3:okhttp",
                affectedVersions = setOf("4.12.0"),
                severity = "HIGH",
                summary = "Synthetic explicit-version advisory",
                source = "OSV",
            )
        ),
    )
    val base = StaticAnalysisReport(
        engineVersion = "0.20.0-dev-auth-feed-evidence",
        assessment = AssessmentScope(
            assessmentId = "11111111-2222-3333-4444-555555555555",
            createdAtEpochMs = 1L,
            projectName = "v020-smoke",
            organization = "Example",
            purpose = "authorized regression",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary("fixture.apk", 1L, "b".repeat(64), 1, 0, 0, true, 0, false),
        manifest = null,
        supplyChain = supply,
        findings = emptyList(),
    )
    val report = VulnerabilityAdvisoryCorrelator.attach(base, feed)
    check(report.schemaVersion == "1.19")
    check(report.supplyChain?.vulnerabilities?.single()?.matchBasis == "EXACT_COMPONENT_VERSION")
    check(report.supplyChain?.advisoryFeed?.format == "OSV")
    check(report.supplyChain?.advisoryFeed?.adapterVersion == "1.0")
    check(report.supplyChain?.advisoryFeed?.skippedAdvisoryCount == 2)
    val json = ReportJsonExporter.export(report)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("\"format\": \"OSV\""))
    check(json.contains("\"skippedAdvisoryCount\": 2"))
    check(json.contains("SUPPLY-ADVISORY-CVE-2099-0001"))
    println("v0.20 auth/feed/evidence smoke PASS")
}
