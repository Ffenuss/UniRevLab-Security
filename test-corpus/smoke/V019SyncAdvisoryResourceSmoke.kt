package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.ResourceTableResolver
import org.unirevlab.security.analysis.SbomExporter
import org.unirevlab.security.analysis.VulnerabilityAdvisoryCorrelator
import org.unirevlab.security.model.*

fun main(args: Array<String>) {
    val out = File(args[1]).also { it.mkdirs() }
    val config = "1".repeat(64)
    val base = ResourceTableSummary(
        packages = listOf("com.example"),
        resolutions = listOf(
            ResourceResolutionSummary(
                resourceId = 0x7f010000, packageId = 0x7f, typeId = 1, entryId = 0,
                packageName = "com.example", typeName = "xml", entryName = "network_security_config",
                dataType = 0x01, dataValue = 0x7f010001, sourceArchive = "base.apk", configurationSha256 = config,
            )
        ),
        sources = listOf(ResourceTableSourceSummary("base.apk", listOf("com.example"), 1, 1)),
    )
    val split = ResourceTableSummary(
        packages = listOf("com.example"),
        resolutions = listOf(
            ResourceResolutionSummary(
                resourceId = 0x7f010001, packageId = 0x7f, typeId = 1, entryId = 1,
                packageName = "com.example", typeName = "xml", entryName = "network_security_config_impl",
                dataType = 0x03, dataValue = 5, stringValue = "res/xml/network_security_config.xml",
                fileEntry = "res/xml/network_security_config.xml", sourceArchive = "split:config.en.apk", configurationSha256 = config,
            )
        ),
        sources = listOf(ResourceTableSourceSummary("split:config.en.apk", listOf("com.example"), 1, 1)),
    )
    val merged = checkNotNull(ResourceTableResolver.merge(listOf(base, split)))
    check(merged.sources.map { it.sourceArchive } == listOf("base.apk", "split:config.en.apk"))
    val resolved = checkNotNull(ResourceTableResolver.resolveReference(merged, "@0x7f010000"))
    check(resolved.fileEntry == "res/xml/network_security_config.xml")
    check(resolved.sourceArchive == "split:config.en.apk")
    val chain = merged.referenceChains.single { it.requestedResourceId == 0x7f010000L }
    check(chain.terminalFileEntry == "res/xml/network_security_config.xml")

    val supply = SupplyChainSummary(
        components = listOf(
            DependencyComponentSummary(
                id = "maven:com.squareup.okhttp3:okhttp", name = "OkHttp", ecosystem = "MAVEN",
                version = "4.12.0", purl = "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
                confidence = "HIGH", evidence = listOf("META-INF/maven/.../pom.properties"), versionEvidence = "pom.properties",
            ),
            DependencyComponentSummary(
                id = "maven:com.google.code.gson:gson", name = "Gson", ecosystem = "MAVEN",
                version = "2.11.0", confidence = "HIGH", evidence = listOf("pom.properties"), versionEvidence = "pom.properties",
            ),
        ),
        nativeDependencies = emptyList(),
        truncated = false,
    )
    val provenance = AdvisoryFeedProvenance(
        schemaVersion = "1.0", feedId = "smoke-feed", source = "https://example.invalid/feed",
        generatedAt = "2026-08-30T00:00:00Z", sha256 = "a".repeat(64), advisoryCount = 2,
    )
    val feed = VulnerabilityAdvisoryCorrelator.Feed(
        provenance,
        listOf(
            VulnerabilityAdvisoryCorrelator.Advisory(
                id = "GHSA-example", aliases = listOf("CVE-2099-0001"),
                componentId = "maven:com.squareup.okhttp3:okhttp", affectedVersions = setOf("4.12.0"),
                severity = "HIGH", summary = "Benign synthetic advisory", source = "fixture",
            ),
            VulnerabilityAdvisoryCorrelator.Advisory(
                id = "GHSA-no-match", componentId = "maven:com.google.code.gson:gson", affectedVersions = setOf("2.10.0"),
                severity = "MEDIUM", summary = "Must not match", source = "fixture",
            ),
        ),
    )
    val correlated = VulnerabilityAdvisoryCorrelator.correlate(supply, feed)
    check(correlated.vulnerabilities.size == 1)
    check(correlated.vulnerabilities.single().componentVersion == "4.12.0")
    check(correlated.advisoryFeed?.sha256 == "a".repeat(64))

    val baseReport = StaticAnalysisReport(
        engineVersion = "0.19.0-dev-sync-advisory-release",
        assessment = AssessmentScope("v019-smoke", 1L, "v019", "Example", "authorized regression", true),
        artifact = ArtifactSummary("fixture.apk", 1L, "b".repeat(64), 1, 0, 0, true, 0, false, splitApkCount = 1),
        manifest = null,
        resources = merged,
        supplyChain = supply,
        findings = emptyList(),
    )
    val report = VulnerabilityAdvisoryCorrelator.attach(baseReport, feed)
    check(report.findings.single().id == "SUPPLY-ADVISORY-CVE-2099-0001")
    val json = ReportJsonExporter.export(report)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("\"sourceArchive\": \"split:config.en.apk\""))
    check(json.contains("\"advisoryFeed\""))
    check(json.contains("CVE-2099-0001"))
    File(out, "static-analysis-report.json").writeText(json)
    val cdx = SbomExporter.exportCycloneDx16(report)
    check(cdx.contains("\"vulnerabilities\""))
    check(cdx.contains("GHSA-example"))
    File(out, "bom.cdx.json").writeText(cdx)
    println("v0.19 sync/advisory/split-resource smoke PASS")
}
