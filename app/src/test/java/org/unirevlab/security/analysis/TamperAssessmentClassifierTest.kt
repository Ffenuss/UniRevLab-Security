package org.unirevlab.security.analysis

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TamperAssessmentClassifierTest {
    @Test
    fun substringNoiseDoesNotBecomeSecurityCategory() {
        val noise = listOf(
            "scoreboard",
            "process",
            "professional",
            "profile",
            "protobuf",
            "prepaid",
            "lifestyle",
            "ranking",
            "balanced",
            "configuration",
        )
        noise.forEach { value ->
            assertTrue("$value should not classify", TamperAssessmentEngine.categoriesForTesting(value).isEmpty())
        }
    }

    @Test
    fun camelCaseAndExactSecurityTermsStillClassify() {
        assertTrue("LOCAL_STATE" in TamperAssessmentEngine.categoriesForTesting("getHighScore"))
        assertTrue("LOCAL_STATE" in TamperAssessmentEngine.categoriesForTesting("playerMoney"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("isPro"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("hasPremiumAccess"))
        assertTrue("FEATURE_CONFIG" in TamperAssessmentEngine.categoriesForTesting("remoteConfig"))
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("rootCheck"))
        assertFalse("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("professional"))
    }

    @Test
    fun billingAndLicensingSdkSurfacesClassifyAsEntitlementTrust() {
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("BillingClient queryPurchasesAsync"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("LicenseChecker checkAccess"))
        assertTrue("ENTITLEMENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("com.pairip.licensecheck.LicenseContentProvider"))
    }

    @Test
    fun signingAndIntegrityApisClassifyAsIntegrityTrust() {
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("SigningInfo getApkContentsSigners"))
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("PackageManager checkSignatures"))
        assertTrue("INTEGRITY" in TamperAssessmentEngine.categoriesForTesting("appIntegrity meetsDeviceIntegrity"))
    }

    @Test
    fun securitySensitiveComponentsReceiveDedicatedCoverage() {
        assertTrue("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("LicenseContentProvider"))
        assertTrue("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("IntegrityProvider"))
        assertFalse("COMPONENT_TRUST" in TamperAssessmentEngine.categoriesForTesting("ordinary ContentProvider"))
    }

    @Test
    fun repeatedWeakArchiveSignalsDoNotExplodeOverallScore() {
        val weak = (1..30).map { index ->
            TamperAssessmentEngine.SurfaceHit(
                category = "LOCAL_STATE",
                kind = "ARCHIVE_ENTRY",
                location = "assets/file-$index.txt",
                preview = "score",
                score = 52,
                archiveEntry = "assets/file-$index.txt",
            )
        }
        val strong = listOf(
            TamperAssessmentEngine.SurfaceHit(
                "ENTITLEMENT_TRUST", "DEX_METHOD", "classes.dex:Lapp/A;->isPremium()Z",
                "isPremium", 70, "classes.dex", "Lapp/A;", "isPremium", "()Z",
            ),
            TamperAssessmentEngine.SurfaceHit(
                "ENTITLEMENT_TRUST", "DEX_METHOD", "classes.dex:Lapp/B;->hasAccess()Z",
                "hasAccess", 70, "classes.dex", "Lapp/B;", "hasAccess", "()Z",
            ),
            TamperAssessmentEngine.SurfaceHit(
                "ENTITLEMENT_TRUST", "DEX_METHOD", "classes.dex:Lapp/C;->isOwned()Z",
                "isOwned", 70, "classes.dex", "Lapp/C;", "isOwned", "()Z",
            ),
        )

        val weakScore = TamperAssessmentEngine.assessmentScoreForTesting(weak)
        val strongScore = TamperAssessmentEngine.assessmentScoreForTesting(strong)
        assertTrue("weak repeated archive noise should stay below MEDIUM: $weakScore", weakScore < 45)
        assertTrue("corroborated code evidence should outrank weak archive noise", strongScore > weakScore)
        assertTrue("corroborated code evidence should reach MEDIUM: $strongScore", strongScore >= 45)
    }
}
