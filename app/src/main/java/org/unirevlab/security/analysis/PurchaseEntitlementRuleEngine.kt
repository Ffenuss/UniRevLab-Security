package org.unirevlab.security.analysis

import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.Severity

/**
 * Builds a defensive purchase -> proof -> entitlement -> protected-content map from one APK.
 * It never claims that a bypass succeeded and never produces patches, hooks, or modified packages.
 */
object PurchaseEntitlementRuleEngine {
    fun evaluate(dex: DexSummary?, il2cpp: Il2CppSummary?): List<Finding> {
        val purchaseCalls = dex?.callXrefs.orEmpty().filter(::isPurchaseCall).take(MAX_EVIDENCE)
        val proofCalls = dex?.callXrefs.orEmpty().filter(::isPurchaseProofCall).take(MAX_EVIDENCE)
        val validationCalls = dex?.callXrefs.orEmpty().filter(::isValidationCall).take(MAX_EVIDENCE)
        val localGateFields = dex?.fieldXrefs.orEmpty().filter { isEntitlementGate(it.fieldName) }.take(MAX_EVIDENCE)
        val localGateMethods = dex?.methods.orEmpty().filter {
            isEntitlementGate(it.name) || isProtectedContentDecision(it.name)
        }.take(MAX_EVIDENCE)
        val persistenceCalls = dex?.callXrefs.orEmpty().filter(::isLocalPersistenceCall).take(MAX_EVIDENCE)

        val metadata = il2cpp?.metadata
        val il2cppPurchase = metadata?.methodDefinitions.orEmpty().filter {
            isPurchaseTerm("${it.declaringType}.${it.name}")
        }.take(MAX_EVIDENCE)
        val il2cppValidation = metadata?.methodDefinitions.orEmpty().filter {
            isValidationTerm("${it.declaringType}.${it.name}")
        }.take(MAX_EVIDENCE)
        val il2cppGates = buildList {
            metadata?.fieldDefinitions.orEmpty().filter { isEntitlementGate(it.name) }.forEach {
                add("FIELD|${it.declaringType}.${it.name}|token=0x${it.token.toString(16)}")
            }
            metadata?.methodDefinitions.orEmpty().filter {
                isEntitlementGate(it.name) || isProtectedContentDecision(it.name)
            }.forEach {
                add("METHOD|${it.declaringType}.${it.name}|token=0x${it.token.toString(16)}")
            }
        }.distinct().take(MAX_EVIDENCE)

        if (purchaseCalls.isEmpty() && il2cppPurchase.isEmpty()) return emptyList()

        val validationPresent = validationCalls.isNotEmpty() || il2cppValidation.isNotEmpty()
        val localGatePresent = localGateFields.isNotEmpty() || localGateMethods.isNotEmpty() || il2cppGates.isNotEmpty()
        val locallyPersistedGate = correlatedPersistence(persistenceCalls, purchaseCalls, localGateFields, dex)

        return buildList {
            add(
                Finding(
                    id = "PURCHASE-ENTITLEMENT-CHAIN-MAPPED",
                    title = "Purchase and entitlement trust chain requires review",
                    severity = if (localGatePresent) Severity.MEDIUM else Severity.INFORMATIONAL,
                    confidence = Confidence.HIGH,
                    category = "MONETIZATION",
                    description = "The APK contains a purchase surface and the analyzer mapped the statically visible stages of purchase initiation, purchase proof, local entitlement state, validation, and protected-content decisions. Stage presence does not prove secure linkage or a successful bypass; the final authorization sink must be verified.",
                    evidence = buildList {
                        add(Evidence("analysis", "purchase-chain", "purchase=${purchaseCalls.size + il2cppPurchase.size}; proof=${proofCalls.size}; localGate=${localGateFields.size + localGateMethods.size + il2cppGates.size}; localPersistence=${persistenceCalls.size}; validation=${validationCalls.size + il2cppValidation.size}"))
                        purchaseCalls.take(8).mapTo(this) { it.asEvidence("purchase-entry") }
                        proofCalls.take(8).mapTo(this) { it.asEvidence("purchase-proof") }
                        localGateFields.take(8).mapTo(this) {
                            Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "entitlement-field:${it.declaringClass}->${it.fieldName}:${it.fieldType}; access=${it.kind}")
                        }
                        il2cppPurchase.take(6).mapTo(this) {
                            Evidence(metadata?.entryName ?: "global-metadata.dat", "method[${it.index}]", "purchase-entry:${it.declaringType}.${it.name}; token=0x${it.token.toString(16)}")
                        }
                        il2cppGates.take(8).mapTo(this) { Evidence(metadata?.entryName ?: "global-metadata.dat", "entitlement-gate", it) }
                        validationCalls.take(8).mapTo(this) { it.asEvidence("validation-signal") }
                        il2cppValidation.take(6).mapTo(this) {
                            Evidence(metadata?.entryName ?: "global-metadata.dat", "method[${it.index}]", "validation-signal:${it.declaringType}.${it.name}; token=0x${it.token.toString(16)}")
                        }
                    }.take(MAX_EVIDENCE),
                    remediation = "Trace the mapped stages to the final content-unlock or value-granting sink. Make a trusted backend authoritative, validate the store purchase token server-side, bind the grant to account, package, product and transaction, reject replay/stale proofs, and treat local entitlement state only as an expiring display cache.",
                    references = REFERENCES,
                    requiresManualReview = true,
                ),
            )

            if (localGatePresent && !validationPresent) {
                add(
                    Finding(
                        id = "PURCHASE-VALIDATION-NOT-EVIDENCED",
                        title = "No purchase-validation stage was linked to local entitlement gates",
                        severity = Severity.HIGH,
                        confidence = Confidence.MEDIUM,
                        category = "MONETIZATION",
                        description = "Static analysis found purchase handling and local entitlement/content gates but did not recover an explicit receipt, purchase-token, backend, or server-validation stage. This is a high-priority trust-boundary gap for review, not proof that validation is absent: obfuscation, native code, reflection, or an unobserved server path may hide it.",
                        evidence = buildList {
                            add(Evidence("analysis", "coverage", "dexTruncated=${dex?.truncated ?: false}; dexParseErrors=${dex?.parseErrors ?: 0}; il2cppDetected=${il2cpp?.detected == true}; il2cppTruncated=${il2cpp?.truncated ?: false}"))
                            purchaseCalls.take(10).mapTo(this) { it.asEvidence("purchase-entry") }
                            localGateFields.take(10).mapTo(this) {
                                Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "local-gate:${it.declaringClass}->${it.fieldName}:${it.fieldType}")
                            }
                            localGateMethods.take(10).mapTo(this) {
                                Evidence(it.dexEntry, "method[${it.methodIndex}]", "local-gate:${it.declaringClass}->${it.name}${it.prototype}")
                            }
                            il2cppGates.take(10).mapTo(this) { Evidence(metadata?.entryName ?: "global-metadata.dat", "local-gate", it) }
                        }.take(MAX_EVIDENCE),
                        remediation = "Add mandatory backend verification of the platform purchase token before granting the entitlement. Persist the authoritative grant against the account on the server; bind product/package/transaction identifiers, enforce idempotency and replay protection, use short-lived signed client grants, and fail closed when verification is unavailable.",
                        references = REFERENCES,
                        requiresManualReview = true,
                    ),
                )
            }

            if (locallyPersistedGate.isNotEmpty()) {
                add(
                    Finding(
                        id = "PURCHASE-LOCAL-ENTITLEMENT-PERSISTENCE",
                        title = "Purchase-related code can persist entitlement-like state locally",
                        severity = Severity.HIGH,
                        confidence = Confidence.HIGH,
                        category = "MONETIZATION",
                        description = "The same DEX class or method neighborhood contains purchase/entitlement evidence and a local persistence write. A local cache may be legitimate, but it must not independently authorize paid content after reinstall, restore, account change, expiry, or failed backend verification.",
                        evidence = locallyPersistedGate.take(MAX_EVIDENCE),
                        remediation = "Store only a bounded cache locally. On launch, restore, account change and before every protected operation, require a fresh or still-valid server entitlement. Clear the cache on verification failure and test missing, modified, stale, replayed, wrong-account and wrong-product states.",
                        references = REFERENCES,
                        requiresManualReview = true,
                    ),
                )
            }
        }
    }

    private fun correlatedPersistence(
        persistenceCalls: List<DexMethodCallXref>,
        purchaseCalls: List<DexMethodCallXref>,
        localGateFields: List<org.unirevlab.security.model.DexFieldXref>,
        dex: DexSummary?,
    ): List<Evidence> {
        val semanticClasses = buildSet {
            purchaseCalls.forEach { add(it.callerClass) }
            localGateFields.forEach { add(it.callerClass); add(it.declaringClass) }
            dex?.stringXrefs.orEmpty().filter { isPurchaseTerm(it.value) || isEntitlementGate(it.value) }
                .forEach { add(it.callerClass) }
        }
        val semanticMethods = buildSet {
            purchaseCalls.forEach { add("${it.dexEntry}|${it.callerMethodIndex}") }
            localGateFields.forEach { add("${it.dexEntry}|${it.callerMethodIndex}") }
            dex?.stringXrefs.orEmpty().filter { isPurchaseTerm(it.value) || isEntitlementGate(it.value) }
                .forEach { add("${it.dexEntry}|${it.callerMethodIndex}") }
        }
        return persistenceCalls.filter {
            it.callerClass in semanticClasses || "${it.dexEntry}|${it.callerMethodIndex}" in semanticMethods
        }.map { it.asEvidence("local-entitlement-persistence") }
    }

    private fun DexMethodCallXref.asEvidence(stage: String) = Evidence(
        dexEntry,
        "$callerClass->$callerName+$instructionOffsetCodeUnits",
        "$stage:$calleeClass->$calleeName$calleePrototype",
    )

    private fun isPurchaseCall(x: DexMethodCallXref): Boolean {
        val value = normalize("${x.calleeClass}.${x.calleeName}")
        return (BILLING_CLASSES.any(value::contains) && PURCHASE_CALLS.any(value::contains)) ||
            PURCHASE_CALLS.any(normalize(x.calleeName)::contains)
    }

    private fun isPurchaseProofCall(x: DexMethodCallXref): Boolean {
        val value = normalize("${x.calleeClass}.${x.calleeName}")
        return PROOF_MARKERS.any(value::contains) &&
            (BILLING_CLASSES.any(value::contains) || PURCHASE_TERMS.any(value::contains))
    }

    private fun isValidationCall(x: DexMethodCallXref): Boolean =
        isValidationTerm("${x.callerClass}.${x.callerName}.${x.calleeClass}.${x.calleeName}")

    private fun isLocalPersistenceCall(x: DexMethodCallXref): Boolean {
        val value = normalize("${x.calleeClass}.${x.calleeName}")
        return LOCAL_STORAGE_CLASSES.any(value::contains) && LOCAL_WRITE_METHODS.any(value::contains)
    }

    private fun isPurchaseTerm(value: String): Boolean = PURCHASE_TERMS.any(normalize(value)::contains)

    private fun isValidationTerm(value: String): Boolean {
        val normalized = normalize(value)
        val proof = VALIDATION_ACTIONS.any(normalized::contains) &&
            (PURCHASE_TERMS.any(normalized::contains) || PROOF_MARKERS.any(normalized::contains))
        val remote = REMOTE_MARKERS.any(normalized::contains) &&
            (VALIDATION_ACTIONS.any(normalized::contains) || PURCHASE_TERMS.any(normalized::contains))
        return proof || remote
    }

    private fun isEntitlementGate(value: String): Boolean = ENTITLEMENT_GATES.any(normalize(value)::contains)
    private fun isProtectedContentDecision(value: String): Boolean = PROTECTED_CONTENT.any(normalize(value)::contains)
    private fun normalize(value: String): String = value.lowercase().filter(Char::isLetterOrDigit)

    private const val MAX_EVIDENCE = 50
    private val BILLING_CLASSES = listOf("billingclient", "googlebilling", "unitypurchasing", "inapppurchasing", "storecontroller")
    private val PURCHASE_CALLS = listOf("launchbillingflow", "querypurchases", "onpurchasesupdated", "processpurchase", "buypurchase", "restorepurchase", "initiatepurchase")
    private val PURCHASE_TERMS = listOf("purchase", "billing", "checkout", "storeproduct", "iap")
    private val PROOF_MARKERS = listOf("purchasetoken", "receipt", "signature", "originaljson", "transactionid", "orderid")
    private val VALIDATION_ACTIONS = listOf("verify", "validate", "checkentitlement")
    private val REMOTE_MARKERS = listOf("server", "backend", "remote", "cloud")
    private val ENTITLEMENT_GATES = listOf("ispremium", "isfullversion", "fullversion", "hasaccess", "hasentitlement", "isowned", "productowned", "ownsproduct", "featureunlocked", "unlockstate", "ispurchased", "hasbought", "boughtgame")
    private val PROTECTED_CONTENT = listOf("unlockcontent", "grantaccess", "openfullgame", "enablepremium", "activatefullversion")
    private val LOCAL_STORAGE_CLASSES = listOf("sharedpreferenceseditor", "playerprefs", "datastore", "sqlite", "roomdatabase")
    private val LOCAL_WRITE_METHODS = listOf("putboolean", "putint", "putlong", "putstring", "setint", "setstring", "update", "insert", "commit", "apply")
    private val REFERENCES = listOf(
        SecurityReference("OWASP MASVS", "MASVS-AUTH"),
        SecurityReference("OWASP MASVS", "MASVS-RESILIENCE"),
    )
}
