package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Joins customer-facing conclusions to their exact evidence files and remediation owners.
 * It intentionally describes tampering only as a threat class; it never emits patch bytes,
 * hook targets/bodies, response-rewrite rules, injected code, or signing instructions.
 */
object CustomerActionMapExporter {
    fun export(report: StaticAnalysisReport): String = build(report).toString(2)

    fun build(report: StaticAnalysisReport): JSONObject {
        val surfaces = ModificationSurfaceClassifier.analyze(report)
        val trustBoundary = runCatching { Il2CppModdingResistanceEngine.analyze(report) }.getOrNull()
        val items = buildList {
            report.findings
                .filter { it.category != "ANALYSIS" }
                .forEach { add(findingItem(it)) }

            (surfaces.resolvedOffsets + surfaces.unresolvedManagedCandidates).forEach { surface ->
                add(
                    JSONObject()
                        .put("id", "SURFACE-${surface.source}-${stableId(surface.displayName)}")
                        .put("status", if (surface.resolvedRva) "STATIC_COORDINATE_CONFIRMED" else "REVIEW_REQUIRED")
                        .put("subject", surface.displayName)
                        .put("risk", surface.reason)
                        .put("potentialTamperingClass", tamperingClass(surface.category))
                        .put("operationalExploitInstructionsIncluded", false)
                        .put("evidenceSources", JSONArray(surfaceSources(surface)))
                        .put("customerChange", remediation(surface.category))
                        .put("verification", verification(surface.category))
                )
            }

            // The general modification-surface index is useful for navigation, but it does not
            // state which recovered IL2CPP member appears to make the authorization decision.
            // Add that conclusion as a separate, evidence-backed customer handoff item.
            trustBoundary?.targets?.forEach { target ->
                add(
                    JSONObject()
                        .put("id", "TRUST-${stableId(target.managedIdentity + target.category + target.kind)}")
                        .put("status", when (target.authority) {
                            Il2CppModdingResistanceEngine.Authority.CLIENT_AUTHORITATIVE -> "CLIENT_AUTHORITY_RISK"
                            Il2CppModdingResistanceEngine.Authority.MIXED -> "SERVER_ENFORCEMENT_REVIEW_REQUIRED"
                            Il2CppModdingResistanceEngine.Authority.SERVER_GATED -> "SERVER_GATED_STATIC_SIGNAL"
                            Il2CppModdingResistanceEngine.Authority.INCONCLUSIVE -> "REVIEW_REQUIRED"
                        })
                        .put("subject", target.managedIdentity)
                        .put("risk", target.evidence.joinToString(" "))
                        .put("potentialTamperingClass", tamperingClass(target.category.name))
                        .put("operationalExploitInstructionsIncluded", false)
                        .put("authorityAssessment", target.authority.name)
                        .put("priority", target.priority.name)
                        .put("confidence", target.confidence.name)
                        .put("evidenceSources", JSONArray(trustBoundarySources(target)))
                        .put("customerChange", target.hardeningActions.joinToString(" "))
                        .put("verification", trustBoundaryVerification(target.authority))
                )
            }
        }

        return JSONObject()
            .put("schemaVersion", "1.0")
            .put("assessmentId", report.assessment.assessmentId)
            .put("artifactSha256", report.artifact.sha256)
            .put("purpose", "Customer remediation and evidence navigation map")
            .put("interpretation", "Potential tampering classes are threat-model statements, not proof that a working modification was produced.")
            .put("reportGuide", reportGuide())
            .put("items", JSONArray(items.distinctBy { it.getString("id") }))
    }

    private fun findingItem(finding: Finding) = JSONObject()
        .put("id", finding.id)
        .put("status", if (finding.requiresManualReview) "REVIEW_REQUIRED" else "STATIC_FACT_CONFIRMED")
        .put("subject", finding.title)
        .put("risk", finding.description)
        .put("potentialTamperingClass", findingThreatClass(finding))
        .put("operationalExploitInstructionsIncluded", false)
        .put(
            "evidenceSources",
            JSONArray(
                listOf(
                    JSONObject()
                        .put("report", "full-report.json")
                        .put("selector", "findings[id=${finding.id}]")
                        .put("contains", "Exact analyzer evidence, component/location, confidence and coverage status"),
                    JSONObject()
                        .put("report", "customer-report.md")
                        .put("selector", finding.id)
                        .put("contains", "Customer-readable conclusion and remediation"),
                ),
            ),
        )
        .put("customerChange", finding.remediation)
        .put("verification", "Rebuild the owner-controlled release, repeat the same assessment, and verify that finding ${finding.id} is absent or explicitly risk-accepted with new evidence.")

    private fun surfaceSources(surface: ModificationSurfaceClassifier.Candidate): List<JSONObject> = buildList {
        add(
            JSONObject()
                .put("report", if (surface.resolvedRva) "offset-evidence.json" else "il2cpp-dump.cs")
                .put("selector", surface.displayName)
                .put("contains", if (surface.resolvedRva) "Managed/native identity, ABI, library and static RVA" else "Recovered namespace/class/member identity without a confirmed native RVA"),
        )
        add(
            JSONObject()
                .put("report", "full-report.json")
                .put("selector", surface.source)
                .put("contains", "Underlying DEX, ELF, JNI, IL2CPP metadata and correlation evidence"),
        )
        surface.libraryEntry?.let { library ->
            add(
                JSONObject()
                    .put("report", "analysis-artifacts.zip")
                    .put("selector", library)
                    .put("contains", "Bounded source ELF/input retained for expert verification"),
            )
        }
    }

    private fun trustBoundarySources(target: Il2CppModdingResistanceEngine.TargetAssessment): List<JSONObject> = buildList {
        add(
            JSONObject()
                .put("report", "il2cpp-dump.cs")
                .put("selector", target.managedIdentity)
                .put("contains", "Recovered namespace, class, member, declared type and method/field identity"),
        )
        target.metadataToken?.let { token ->
            add(
                JSONObject()
                    .put("report", "full-report.json")
                    .put("selector", "il2cpp.metadata token=0x${token.toString(16)}")
                    .put("contains", "Static metadata evidence used for the authority assessment"),
            )
        }
        target.nativeFunctionName?.let { name ->
            add(
                JSONObject()
                    .put("report", "offset-evidence.json")
                    .put("selector", name)
                    .put("contains", "Native correlation when a completed dump confirms a matching identity"),
            )
        }
    }

    private fun trustBoundaryVerification(authority: Il2CppModdingResistanceEngine.Authority): String = when (authority) {
        Il2CppModdingResistanceEngine.Authority.CLIENT_AUTHORITATIVE ->
            "In the owner-controlled test environment, prove that the protected backend operation rejects a missing, stale, replayed or wrong-account authorization even when the client sends a local success state."
        Il2CppModdingResistanceEngine.Authority.MIXED ->
            "Trace the final authorization sink and prove that every protected operation requires a fresh server decision; local cache, getter and UI state must not authorize it."
        Il2CppModdingResistanceEngine.Authority.SERVER_GATED ->
            "Confirm backend enforcement for rejected receipts, expired grants, replayed requests and account/product mismatches, then retain the automated regression test."
        Il2CppModdingResistanceEngine.Authority.INCONCLUSIVE ->
            "Trace this recovered member to the final authorization sink and record whether the decision is enforced by the backend or only by local client state."
    }

    private fun reportGuide() = JSONArray(
        listOf(
            guide("customer-report.md", "Start here", "Executive conclusion, prioritized findings and remediation."),
            guide("customer-action-map.json", "Implementation handoff", "One row per risk with evidence location, owner change and retest criterion."),
            guide("mod-resistance-validation.md", "Authorized validation", "Step-by-step owner-source QA workflow, per-risk evidence, remediation and acceptance criteria."),
            guide("full-report.json", "Technical evidence", "Complete normalized Manifest, DEX, ELF/JNI, runtime and finding records."),
            guide("il2cpp-dump.cs", "IL2CPP identity", "Recovered namespaces, classes, fields, declared types and methods."),
            guide("offset-evidence.json", "Confirmed coordinates", "Structured ABI/library/RVA/field-offset evidence and managed/native correlations."),
            guide("offsets-readable.html", "Human review", "Searchable view of confirmed dump-derived coordinates."),
            guide("verification-plan.json", "Retest", "Unexecuted defensive test objectives and expected secure outcomes."),
            guide("gradle-module-evidence.json", "Module ownership", "Base, split, dynamic-feature and retained build metadata mapping."),
            guide("analysis-artifacts.zip", "Expert replay", "Bounded DEX/ELF/metadata inputs selected by the analyzer."),
        ),
    )

    private fun guide(name: String, use: String, contains: String) = JSONObject()
        .put("report", name).put("use", use).put("contains", contains)

    private fun tamperingClass(category: String): String = when (category) {
        "ENTITLEMENT", "SUBSCRIPTION", "PREMIUM", "INTEGRITY_LICENSE" -> "A modified client could attempt to alter a local entitlement or success decision."
        "ECONOMY", "CURRENCY", "INVENTORY" -> "A modified client could attempt to alter locally trusted value or transaction state."
        "COMBAT", "COMBAT_RESOURCES", "MOVEMENT", "PROGRESSION" -> "A modified client could attempt to alter client-side state or a calculation result."
        "NETWORK", "REMOTE_CONFIG" -> "An attacker-controlled client could attempt to supply or accept manipulated protocol state."
        else -> "A modified client could attempt to change local control flow, state, or a trust decision."
    }

    private fun findingThreatClass(finding: Finding): String = when (finding.category) {
        "NETWORK" -> "Manipulated transport or untrusted response data may influence client behavior if authenticity and server authority are incomplete."
        "PLATFORM" -> "An external Android caller may attempt to reach an exposed entry point with attacker-controlled input."
        "NATIVE", "NATIVE_HARDENING", "RESILIENCE" -> "A modified or instrumented client may attempt to alter local native execution; no concrete bypass is generated here."
        else -> "Attacker-controlled local state or input may reach the reported trust boundary."
    }

    private fun remediation(category: String): String = when (category) {
        "ENTITLEMENT", "SUBSCRIPTION", "PREMIUM", "INTEGRITY_LICENSE" -> "Make the backend authoritative: validate provider proof server-side, bind the entitlement to account/product/build, use nonce and replay protection, return a short-lived signed grant, and fail closed. Keep the client field as display-only cache."
        "ECONOMY", "CURRENCY", "INVENTORY" -> "Move balance and inventory mutations to an atomic server ledger. Accept intent, not a client-computed result; enforce idempotency keys, monotonic state versions, replay rejection and invariant checks."
        "COMBAT", "COMBAT_RESOURCES", "MOVEMENT", "PROGRESSION" -> "Validate security-relevant gameplay invariants on the authoritative simulation/server. Treat client values as proposals, reject impossible transitions, and log deterministic evidence for review."
        "NETWORK", "REMOTE_CONFIG" -> "Authenticate requests and responses, validate schemas and authorization server-side, bind sensitive responses to session/account/nonces, reject replay/stale state, and fail closed on signature or TLS errors."
        else -> "Trace the member to its authorization sink, remove local-only authority, enforce the decision in a trusted backend where it protects value, and add negative regression tests."
    }

    private fun verification(category: String): String = when (category) {
        "ENTITLEMENT", "SUBSCRIPTION", "PREMIUM", "INTEGRITY_LICENSE" -> "With an owner test account, confirm that missing, stale, replayed, wrong-account and wrong-product proofs are rejected by the backend and do not unlock the protected operation."
        "ECONOMY", "CURRENCY", "INVENTORY" -> "Confirm duplicate, reordered, stale-version and out-of-range operations do not change the authoritative ledger."
        "COMBAT", "COMBAT_RESOURCES", "MOVEMENT", "PROGRESSION" -> "Confirm impossible state transitions are rejected or quarantined by the authoritative validator and appear in telemetry."
        "NETWORK", "REMOTE_CONFIG" -> "Confirm invalid authentication, signatures, schema, nonce, session binding and stale versions are rejected without a permissive fallback."
        else -> "Re-run the static assessment and execute the linked verification-plan objective in the owner's isolated test environment."
    }

    private fun stableId(value: String): String = value.hashCode().toUInt().toString(16)
}
