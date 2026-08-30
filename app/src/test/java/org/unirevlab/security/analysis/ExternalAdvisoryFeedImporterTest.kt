package org.unirevlab.security.analysis

import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.DependencyComponentSummary
import org.unirevlab.security.model.SupplyChainSummary

class ExternalAdvisoryFeedImporterTest {
    @Test
    fun osvEnumeratedVersionsMapToMavenComponentAndCorrelateExactly() {
        val json = """
            {
              "schema_version":"1.9.0",
              "id":"GHSA-test-osv",
              "modified":"2026-08-29T12:00:00Z",
              "aliases":["CVE-2099-0001"],
              "summary":"Synthetic OSV exact-version fixture",
              "affected":[{
                "package":{"ecosystem":"Maven","name":"com.squareup.okhttp3:okhttp"},
                "versions":["4.12.0"],
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.0.0"},{"fixed":"4.12.1"}]}]
              }]
            }
        """.trimIndent()
        val feed = ExternalAdvisoryFeedImporter.parse(ByteArrayInputStream(json.toByteArray()))
        assertEquals("OSV", feed.provenance.format)
        assertEquals(1, feed.provenance.advisoryCount)
        assertEquals(0, feed.provenance.skippedAdvisoryCount)
        assertEquals("maven:com.squareup.okhttp3:okhttp", feed.advisories.single().componentId)

        val supply = SupplyChainSummary(
            components = listOf(
                DependencyComponentSummary(
                    id = "maven:com.squareup.okhttp3:okhttp",
                    name = "OkHttp",
                    ecosystem = "MAVEN",
                    version = "4.12.0",
                    confidence = "HIGH",
                    evidence = listOf("pom.properties"),
                )
            ),
            nativeDependencies = emptyList(),
            truncated = false,
        )
        val correlated = VulnerabilityAdvisoryCorrelator.correlate(supply, feed)
        assertEquals(1, correlated.vulnerabilities.size)
        assertEquals("EXACT_COMPONENT_VERSION", correlated.vulnerabilities.single().matchBasis)
    }

    @Test
    fun githubSafeRangesAndExactEqualityAreAccepted() {
        val json = """
          [
            {
              "ghsa_id":"GHSA-range-only",
              "cve_id":"CVE-2099-0002",
              "summary":"Range fixture",
              "severity":"high",
              "updated_at":"2026-08-29T12:00:00Z",
              "vulnerabilities":[{"package":{"ecosystem":"maven","name":"a:b"},"vulnerable_version_range":"< 2.0.0"}]
            },
            {
              "ghsa_id":"GHSA-exact",
              "summary":"Exact fixture",
              "severity":"low",
              "updated_at":"2026-08-29T13:00:00Z",
              "vulnerabilities":[{"package":{"ecosystem":"maven","name":"a:b"},"vulnerable_version_range":"= 1.2.3"}]
            }
          ]
        """.trimIndent()
        val feed = ExternalAdvisoryFeedImporter.parse(ByteArrayInputStream(json.toByteArray()))
        assertEquals("GITHUB_GLOBAL_ADVISORY", feed.provenance.format)
        assertEquals(2, feed.provenance.advisoryCount)
        assertEquals(0, feed.provenance.skippedAdvisoryCount)
        val range = feed.advisories.first { it.id == "GHSA-range-only" }
        assertTrue(range.affectedRanges.any { it.expression == "< 2.0.0" && it.ecosystem == "MAVEN" })
        assertEquals(setOf("1.2.3"), feed.advisories.first { it.id == "GHSA-exact" }.affectedVersions)
    }

    @Test
    fun nvdOnlyAcceptsCpeWithLiteralVersionAndNoBounds() {
        val json = """
          {
            "format":"NVD_CVE",
            "version":"2.0",
            "timestamp":"2026-08-29T14:00:00Z",
            "vulnerabilities":[{
              "cve":{
                "id":"CVE-2099-0003",
                "descriptions":[{"lang":"en","value":"Synthetic NVD fixture"}],
                "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},
                "configurations":[{"nodes":[{
                  "cpeMatch":[
                    {"vulnerable":true,"criteria":"cpe:2.3:a:example:widget:1.2.3:*:*:*:*:*:*:*"},
                    {"vulnerable":true,"criteria":"cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0.0"}
                  ]
                }]}]
              }
            }]
          }
        """.trimIndent()
        val feed = ExternalAdvisoryFeedImporter.parse(ByteArrayInputStream(json.toByteArray()))
        assertEquals("NVD_CVE_2_0", feed.provenance.format)
        assertEquals(1, feed.advisories.size)
        assertEquals("cpe:example:widget", feed.advisories.single().componentId)
        assertEquals(setOf("1.2.3"), feed.advisories.single().affectedVersions)
        assertEquals("HIGH", feed.advisories.single().severity)
    }

    @Test
    fun normalizedFeedRemainsBackwardsCompatible() {
        val json = """
          {"schemaVersion":"1.0","feedId":"fixture","source":"fixture","generatedAt":"2026-08-29T00:00:00Z","advisories":[
            {"id":"ADV-1","componentId":"maven:a:b","affectedVersions":["1.0"],"severity":"MEDIUM","summary":"fixture"}
          ]}
        """.trimIndent()
        val feed = ExternalAdvisoryFeedImporter.parse(ByteArrayInputStream(json.toByteArray()))
        assertEquals("UNIREVLAB_NORMALIZED", feed.provenance.format)
        assertTrue(feed.provenance.adapterVersion == null)
        assertEquals(1, feed.advisories.size)
    }
}
