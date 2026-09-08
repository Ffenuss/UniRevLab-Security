package org.unirevlab.security.analysis

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary

class PurchaseEntitlementRuleEngineTest {
    @Test
    fun mapsPurchaseLocalGateAndPersistenceWithoutCallingItAProvenBypass() {
        val findings = PurchaseEntitlementRuleEngine.evaluate(dex(includeServerValidation = false), null)

        assertTrue(findings.any { it.id == "PURCHASE-ENTITLEMENT-CHAIN-MAPPED" })
        assertTrue(findings.any { it.id == "PURCHASE-VALIDATION-NOT-EVIDENCED" })
        assertTrue(findings.any { it.id == "PURCHASE-LOCAL-ENTITLEMENT-PERSISTENCE" })
        assertTrue(findings.first { it.id == "PURCHASE-ENTITLEMENT-CHAIN-MAPPED" }.description.contains("does not prove", ignoreCase = true))
    }

    @Test
    fun explicitBackendValidationPreventsValidationGapFinding() {
        val findings = PurchaseEntitlementRuleEngine.evaluate(dex(includeServerValidation = true), null)

        assertTrue(findings.any { it.id == "PURCHASE-ENTITLEMENT-CHAIN-MAPPED" })
        assertFalse(findings.any { it.id == "PURCHASE-VALIDATION-NOT-EVIDENCED" })
    }

    private fun dex(includeServerValidation: Boolean): DexSummary {
        val calls = buildList {
            add(call(1, "Lgame/BillingManager;", "buyFullGame", "Lcom/android/billingclient/api/BillingClient;", "launchBillingFlow"))
            add(call(1, "Lgame/BillingManager;", "buyFullGame", "Landroid/content/SharedPreferences\$Editor;", "putBoolean"))
            add(call(1, "Lgame/BillingManager;", "buyFullGame", "Lcom/android/billingclient/api/Purchase;", "getPurchaseToken"))
            if (includeServerValidation) {
                add(call(1, "Lgame/BillingManager;", "buyFullGame", "Lgame/backend/ServerPurchaseApi;", "validatePurchase"))
            }
        }
        return DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 10,
            stringsScanned = 10,
            methodsDeclared = 2,
            methodsIndexed = 2,
            methods = listOf(
                DexMethodReference("classes.dex", 1, "Lgame/BillingManager;", "buyFullGame", "()V"),
                DexMethodReference("classes.dex", 2, "Lgame/Entitlement;", "isFullVersion", "()Z"),
            ),
            callXrefs = calls,
            fieldXrefs = listOf(
                DexFieldXref("classes.dex", 1, "Lgame/BillingManager;", "buyFullGame", 0, "Lgame/Entitlement;", "isFullVersion", "Z", "WRITE", 8),
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )
    }

    private fun call(
        callerIndex: Int,
        callerClass: String,
        callerName: String,
        calleeClass: String,
        calleeName: String,
    ) = DexMethodCallXref(
        dexEntry = "classes.dex",
        callerMethodIndex = callerIndex,
        callerClass = callerClass,
        callerName = callerName,
        calleeMethodIndex = 100 + callerIndex,
        calleeClass = calleeClass,
        calleeName = calleeName,
        calleePrototype = "()V",
        instructionOffsetCodeUnits = 4,
    )
}
