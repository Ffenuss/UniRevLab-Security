package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexSummary

class InstallerSourceRuleTest {
    @Test
    fun reportsInstallSourceApisAsResilienceSurface() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 0,
            stringsScanned = 0,
            callXrefs = listOf(
                DexMethodCallXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 7,
                    callerClass = "Lapp/Integrity;",
                    callerName = "checkInstallSource",
                    calleeMethodIndex = 100,
                    calleeClass = "Landroid/content/pm/PackageManager;",
                    calleeName = "getInstallSourceInfo",
                    calleePrototype = "(Ljava/lang/String;)Landroid/content/pm/InstallSourceInfo;",
                    instructionOffsetCodeUnits = 12,
                ),
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )

        val findings = DexRuleEngine.evaluate(dex)
        val finding = findings.single { it.id == "DEX-INSTALL-SOURCE-CHECK" }
        assertEquals("RESILIENCE", finding.category)
        assertTrue(finding.requiresManualReview)
        assertTrue(finding.evidence.single().value.contains("getInstallSourceInfo"))
    }
}
