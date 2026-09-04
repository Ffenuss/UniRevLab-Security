package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexStringReference
import org.unirevlab.security.model.DexSummary

class DexRuleEngineTest {
    @Test
    fun reportsOnlyConcreteCleartextEndpoints() {
        val dex = summary(
            httpUrls = listOf(
                DexStringReference("classes.dex", 1, "http://schemas.android.com/apk/res/android"),
                DexStringReference("classes.dex", 2, "http://localhost:8080/test"),
                DexStringReference("classes.dex", 3, "http://api.example.com/v1"),
            ),
        )

        val finding = DexRuleEngine.evaluate(dex).single { it.id == "DEX-HARDCODED-HTTP-URL" }
        assertEquals(1, finding.evidence.size)
        assertEquals("http://api.example.com/v1", finding.evidence.single().value)
    }

    @Test
    fun ignoresGooglePlayDynamitePathClassLoader() {
        val xref = DexMethodCallXref(
            dexEntry = "classes.dex",
            callerMethodIndex = 10,
            callerClass = "Lcom/google/android/gms/dynamite/DynamiteModule;",
            callerName = "load",
            calleeMethodIndex = 20,
            calleeClass = "Ldalvik/system/PathClassLoader;",
            calleeName = "<init>",
            calleePrototype = "(Ljava/lang/String;Ljava/lang/ClassLoader;)V",
            instructionOffsetCodeUnits = 1,
        )
        val findings = DexRuleEngine.evaluate(summary(callXrefs = listOf(xref)))
        assertFalse(findings.any { it.id == "DEX-DYNAMIC-CODE-LOADING" })
    }

    @Test
    fun keepsApplicationDexClassLoaderAsReviewSignal() {
        val xref = DexMethodCallXref(
            dexEntry = "classes.dex",
            callerMethodIndex = 10,
            callerClass = "Lcom/example/PluginLoader;",
            callerName = "load",
            calleeMethodIndex = 20,
            calleeClass = "Ldalvik/system/DexClassLoader;",
            calleeName = "<init>",
            calleePrototype = "()V",
            instructionOffsetCodeUnits = 1,
        )
        val findings = DexRuleEngine.evaluate(summary(callXrefs = listOf(xref)))
        assertTrue(findings.any { it.id == "DEX-DYNAMIC-CODE-LOADING" && it.requiresManualReview })
    }

    private fun summary(
        httpUrls: List<DexStringReference> = emptyList(),
        callXrefs: List<DexMethodCallXref> = emptyList(),
    ) = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = httpUrls.size.toLong(),
        stringsScanned = httpUrls.size.toLong(),
        callXrefs = callXrefs,
        httpUrls = httpUrls,
        httpsUrls = emptyList(),
        secretCandidates = emptyList(),
        parseErrors = 0,
        truncated = false,
    )
}
