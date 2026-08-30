package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ComponentExposure
import org.unirevlab.security.model.DeclaredPermission
import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.Severity

class DeepLinkAndPermissionRuleTest {
    @Test
    fun flagsUnverifiedHttpAppLinks() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(
                deepLinks = listOf(
                    DeepLinkDeclaration(
                        componentName = "org.example.LinkActivity",
                        schemes = listOf("https"),
                        hosts = listOf("example.org"),
                        autoVerify = false,
                        browsable = true,
                        viewAction = true,
                    )
                )
            )
        )

        val finding = findings.single { it.id == "ANDROID-UNVERIFIED-APP-LINKS" }
        assertEquals(Severity.MEDIUM, finding.severity)
        assertTrue(finding.references.any { it.id == "MASTG-TEST-0393" })
    }

    @Test
    fun customSchemeIsReviewFindingNotAutomaticVulnerability() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(
                deepLinks = listOf(
                    DeepLinkDeclaration(
                        componentName = "org.example.LinkActivity",
                        schemes = listOf("exampleapp"),
                        hosts = emptyList(),
                        autoVerify = false,
                        browsable = true,
                        viewAction = true,
                    )
                )
            )
        )

        val finding = findings.single { it.id == "ANDROID-CUSTOM-SCHEME-REVIEW" }
        assertEquals(Severity.INFORMATIONAL, finding.severity)
        assertTrue(finding.requiresManualReview)
    }

    @Test
    fun exportedProviderWithoutPermissionGetsDedicatedFinding() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(
                components = listOf(ComponentExposure("provider", "org.example.Provider", true))
            )
        )

        val finding = findings.single { it.id == "ANDROID-EXPORTED-PROVIDER-UNPROTECTED" }
        assertEquals(Severity.MEDIUM, finding.severity)
        assertTrue(findings.none { it.id == "ANDROID-EXPORTED-UNPROTECTED-REVIEW" })
    }

    @Test
    fun detectsBroadlyGrantableCustomPermissionOnExportedComponent() {
        val findings = ManifestRuleEngine.evaluate(
            manifest(
                declaredPermissions = listOf(
                    DeclaredPermission("org.example.permission.PUBLIC_API", "NORMAL")
                ),
                components = listOf(
                    ComponentExposure(
                        kind = "service",
                        name = "org.example.SyncService",
                        exported = true,
                        permissions = listOf("org.example.permission.PUBLIC_API"),
                    )
                ),
            )
        )

        val finding = findings.single { it.id == "ANDROID-EXPORTED-WEAK-PERMISSION" }
        assertTrue(finding.requiresManualReview)
    }

    private fun manifest(
        declaredPermissions: List<DeclaredPermission> = emptyList(),
        components: List<ComponentExposure> = emptyList(),
        deepLinks: List<DeepLinkDeclaration> = emptyList(),
    ) = ManifestSummary(
        packageName = "org.example.target",
        versionName = "1.0",
        versionCode = 1,
        minSdk = 26,
        targetSdk = 36,
        debuggable = false,
        allowBackup = false,
        fullBackupContentConfigured = false,
        dataExtractionRulesConfigured = false,
        usesCleartextTraffic = false,
        networkSecurityConfigConfigured = false,
        requestedPermissions = emptyList(),
        dangerousPermissions = emptyList(),
        declaredPermissions = declaredPermissions,
        components = components,
        deepLinks = deepLinks,
        signingCertificateSha256 = emptyList(),
    )
}
