import org.unirevlab.security.analysis.EcosystemVersionRangeResolver
import org.unirevlab.security.analysis.VulnerabilityAdvisoryCorrelator
import org.unirevlab.security.model.AdvisoryFeedProvenance
import org.unirevlab.security.model.DependencyComponentSummary
import org.unirevlab.security.model.SupplyChainSummary

fun main() {
    check(EcosystemVersionRangeResolver.evaluate("NPM", "1.4.5", ">= 1.2.0, < 2.0.0")?.matches == true)
    check(EcosystemVersionRangeResolver.evaluate("NPM", "2.0.0", ">= 1.2.0, < 2.0.0")?.matches == false)
    check(EcosystemVersionRangeResolver.evaluate("NUGET", "3.1.0-beta.2", ">= 3.1.0-beta.1, < 3.1.0")?.matches == true)
    check(EcosystemVersionRangeResolver.evaluate("MAVEN", "4.12.0", ">= 4.0.0, < 4.12.1")?.matches == true)
    check(EcosystemVersionRangeResolver.evaluate("MAVEN", "1.0-final", ">= 1.0, < 2.0") == null)
    check(!EcosystemVersionRangeResolver.isSupportedExpression("NPM", "^1.2.3"))
    check(!EcosystemVersionRangeResolver.isSupportedExpression("NPM", ">= 1.0.0 || < 0.1.0"))

    val summary = SupplyChainSummary(
        components = listOf(
            DependencyComponentSummary(
                id = "npm:fixture",
                name = "fixture",
                ecosystem = "NPM",
                version = "1.4.5",
                confidence = "HIGH",
                evidence = listOf("fixture"),
            )
        ),
        nativeDependencies = emptyList(),
        truncated = false,
    )
    val feed = VulnerabilityAdvisoryCorrelator.Feed(
        provenance = AdvisoryFeedProvenance(
            schemaVersion = "1.0",
            feedId = "fixture",
            source = "fixture",
            generatedAt = "2026-08-30T00:00:00Z",
            sha256 = "a".repeat(64),
            advisoryCount = 1,
            format = "OSV",
            adapterVersion = "1.1",
        ),
        advisories = listOf(
            VulnerabilityAdvisoryCorrelator.Advisory(
                id = "GHSA-fixture",
                componentId = "npm:fixture",
                affectedRanges = listOf(
                    VulnerabilityAdvisoryCorrelator.VersionRange("NPM", ">= 1.2.0, < 2.0.0", "fixture")
                ),
                severity = "HIGH",
                summary = "range fixture",
                source = "fixture",
            )
        )
    )
    val correlated = VulnerabilityAdvisoryCorrelator.correlate(summary, feed)
    check(correlated.vulnerabilities.size == 1)
    check(correlated.vulnerabilities.single().matchBasis.startsWith("ECOSYSTEM_VERSION_RANGE:NPM_SEMVER_SAFE_1"))
    println("v0.21 ecosystem range correlation smoke PASS")
}
