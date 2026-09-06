package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ComponentExposure
import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.Severity

class ManifestRuleEngineTest {
    @Test
    fun findsSecurityRelevantManifestConfiguration() {
        val manifest = manifest(
            debuggable = true,
            allowBackup = true,
            usesCleartextTraffic = true,
            components = listOf(ComponentExposure("service", "ExampleService", true)),
        )

        val findings = ManifestRuleEngine.evaluate(manifest)

        assertEquals(4, findings.size)
        assertEquals(Severity.HIGH, findings.first().severity)
        assertTrue(findings.any { it.id == "ANDROID-MANIFEST-DEBUGGABLE" })
        assertTrue(findings.any { it.id == "ANDROID-MANIFEST-CLEARTEXT" })
        assertTrue(findings.any { it.id == "ANDROID-MANIFEST-BACKUP" })
        assertTrue(findings.any { it.id == "ANDROID-EXPORTED-UNPROTECTED-REVIEW" && it.requiresManualReview })
    }

    @Test
    fun flagsDangerousPermissionsForManualPrivacyReview() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(dangerousPermissions = listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"))
        )

        val finding = findings.single { it.id == "ANDROID-DANGEROUS-PERMISSIONS" }
        assertEquals(Severity.LOW, finding.severity)
        assertTrue(finding.requiresManualReview)
        assertEquals(2, finding.evidence.size)
    }

    @Test
    fun avoidsCleartextFindingWhenNetworkSecurityConfigExists() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(usesCleartextTraffic = true, networkSecurityConfigConfigured = true, allowBackup = false)
        )
        assertTrue(findings.none { it.id == "ANDROID-MANIFEST-CLEARTEXT" })
    }

    @Test
    fun reportsLiteralAppLinkPlaceholder() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(
                deepLinks = listOf(
                    DeepLinkDeclaration(
                        componentName = "MainActivity",
                        schemes = listOf("https"),
                        hosts = listOf("{link_domain}"),
                        autoVerify = true,
                        browsable = true,
                        viewAction = true,
                    ),
                ),
            ),
        )

        assertTrue(findings.any { it.id == "ANDROID-APP-LINK-PLACEHOLDER-HOST" && it.confidence.name == "CONFIRMED" })
    }

    private fun manifest(
        debuggable: Boolean = false,
        allowBackup: Boolean = false,
        usesCleartextTraffic: Boolean = false,
        networkSecurityConfigConfigured: Boolean = false,
        dangerousPermissions: List<String> = emptyList(),
        components: List<ComponentExposure> = emptyList(),
        deepLinks: List<DeepLinkDeclaration> = emptyList(),
    ) = ManifestSummary(
        packageName = "org.example.target",
        versionName = "1.0",
        versionCode = 1,
        minSdk = 26,
        targetSdk = 36,
        debuggable = debuggable,
        allowBackup = allowBackup,
        fullBackupContentConfigured = false,
        dataExtractionRulesConfigured = false,
        usesCleartextTraffic = usesCleartextTraffic,
        networkSecurityConfigConfigured = networkSecurityConfigConfigured,
        requestedPermissions = emptyList(),
        dangerousPermissions = dangerousPermissions,
        components = components,
        deepLinks = deepLinks,
        signingCertificateSha256 = emptyList(),
    )
}
