package org.unirevlab.security.analysis

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.NativeSummary

class NativeRuleEngineTest {
    @Test
    fun weakFixtureProducesHardeningFindings() {
        val scan = ElfNativeScanner.scan("lib/x86_64/libjni_weak.so", fixture("libjni_weak.so"))
        val findings = NativeRuleEngine.evaluate(
            NativeSummary(1, 1, listOf(scan), parseErrors = 0, truncated = false),
        )
        assertTrue(findings.any { it.id == "NATIVE-EXECUTABLE-STACK" })
        assertTrue(findings.any { it.id == "NATIVE-RELRO-MISSING" })
        assertTrue(findings.any { it.id == "NATIVE-JNI-ATTACK-SURFACE" })
    }

    @Test
    fun importInventoryProducesReviewSignalsWithoutClaimingExploitability() {
        val base = ElfNativeScanner.scan("assets/libplugin.so", fixture("libjni_hardened.so"))
        val modeled = base.copy(
            importedSymbols = base.importedSymbols + listOf(
                org.unirevlab.security.model.NativeSymbolReference("assets/libplugin.so", "system", "GLOBAL", "FUNC", false),
                org.unirevlab.security.model.NativeSymbolReference("assets/libplugin.so", "dlopen", "GLOBAL", "FUNC", false),
            ),
        )
        val findings = NativeRuleEngine.evaluate(
            NativeSummary(1, 1, listOf(modeled), parseErrors = 0, truncated = false),
        )
        assertTrue(findings.any { it.id == "NATIVE-NONSTANDARD-LOCATION" })
        assertTrue(findings.any { it.id == "NATIVE-PROCESS-EXECUTION-API-REVIEW" && it.requiresManualReview })
        assertTrue(findings.any { it.id == "NATIVE-DYNAMIC-LOADING-API-REVIEW" && it.requiresManualReview })
    }

    private fun fixture(name: String): File {
        javaClass.classLoader?.getResource("fixtures/$name")?.let { return File(it.toURI()) }
        val candidates = listOf(
            File("src/test/resources/fixtures/$name"),
            File("app/src/test/resources/fixtures/$name"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("Missing native test fixture: ${candidates.joinToString { it.absolutePath }}")
    }
}
