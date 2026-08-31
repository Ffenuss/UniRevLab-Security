package org.unirevlab.security.analysis

import java.util.Locale
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Authorized demonstration modifier.
 *
 * It only targets methods from the analyzed application's own package, works on an exact SHA-bound
 * Patch Lab workspace, caps the number of behavior-changing edits, and produces a separately signed
 * laboratory APK. It does not emulate store purchases, preserve the original signer, or modify the
 * original APK in place.
 */
object AutoModEngine {
    enum class Mode { RETURN_TRUE, RETURN_FALSE, RETURN_INT }

    data class Action(
        val id: String,
        val category: String,
        val dexEntry: String,
        val classDescriptor: String,
        val methodName: String,
        val prototype: String,
        val mode: Mode,
        val intValue: Int? = null,
        val confidence: Int,
        val reason: String,
    ) {
        val target: String get() = "$classDescriptor->$methodName$prototype"
        val methodKey: String get() = "$dexEntry|$classDescriptor|$methodName|$prototype"
    }

    data class Plan(
        val artifactSha256: String,
        val assessmentScore: Int,
        val assessmentBand: String,
        val actions: List<Action>,
        val eligibleBeforeCap: Int,
    )

    data class ApplyResult(val applied: List<Action>)

    internal data class Suggestion(
        val mode: Mode,
        val intValue: Int?,
        val confidence: Int,
        val reason: String,
    )

    fun plan(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace): Plan {
        if (report.artifact.sha256.isNotBlank()) {
            require(workspace.artifactSha256.equals(report.artifact.sha256, ignoreCase = true)) {
                "AutoMod заблокирован: workspace не совпадает с SHA-256 проанализированного APK"
            }
        }
        val packagePrefix = report.manifest?.packageName
            ?.takeIf { it.isNotBlank() }
            ?.replace('.', '/')
            ?.let { "L$it/" }
            ?: return Plan(workspace.artifactSha256, 0, "MINIMAL", emptyList(), 0)

        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val candidates = assessment.hits.asSequence()
            .filter {
                it.dexEntry != null && it.classDescriptor != null && it.methodName != null && it.prototype != null
            }
            .filter { requireNotNull(it.classDescriptor).startsWith(packagePrefix) }
            .mapNotNull { hit ->
                val suggestion = suggest(
                    category = hit.category,
                    methodName = requireNotNull(hit.methodName),
                    prototype = requireNotNull(hit.prototype),
                    baseScore = hit.score,
                ) ?: return@mapNotNull null
                Action(
                    id = "automod-${hit.category.lowercase(Locale.ROOT)}-${requireNotNull(hit.methodName)}",
                    category = hit.category,
                    dexEntry = requireNotNull(hit.dexEntry),
                    classDescriptor = requireNotNull(hit.classDescriptor),
                    methodName = requireNotNull(hit.methodName),
                    prototype = requireNotNull(hit.prototype),
                    mode = suggestion.mode,
                    intValue = suggestion.intValue,
                    confidence = suggestion.confidence,
                    reason = suggestion.reason,
                )
            }
            .distinctBy { it.methodKey }
            .sortedWith(compareByDescending<Action> { it.confidence }.thenBy { it.target })
            .toList()

        val selected = selectDiverse(candidates)
        return Plan(
            artifactSha256 = workspace.artifactSha256,
            assessmentScore = assessment.score,
            assessmentBand = assessment.band,
            actions = selected,
            eligibleBeforeCap = candidates.size,
        )
    }

    fun apply(workspace: PatchLabEngine.Workspace, plan: Plan, authorizationConfirmed: Boolean): ApplyResult {
        require(authorizationConfirmed) {
            "AutoMod требует отдельного подтверждения права на модификацию этого APK"
        }
        require(plan.artifactSha256.equals(workspace.artifactSha256, ignoreCase = true)) {
            "План AutoMod относится к другому APK"
        }
        require(plan.actions.isNotEmpty()) { "В плане AutoMod нет безопасно выбранных демонстрационных действий" }
        require(workspace.modifiedDexEntries.isEmpty() && workspace.replacements.isEmpty()) {
            "Для AutoMod нужен чистый workspace без ручных патчей/замен. Подготовьте workspace заново."
        }

        val edited = linkedMapOf<String, String>()
        plan.actions.forEach { action ->
            PatchLabEngine.disassembleDex(workspace, action.dexEntry)
            val key = "${action.dexEntry}|${action.classDescriptor}"
            val before = edited[key] ?: PatchLabEngine.loadClass(workspace, action.dexEntry, action.classDescriptor)
            val after = when (action.mode) {
                Mode.RETURN_TRUE -> PatchLabEngine.forceBooleanReturn(before, action.methodName, action.prototype, true)
                Mode.RETURN_FALSE -> PatchLabEngine.forceBooleanReturn(before, action.methodName, action.prototype, false)
                Mode.RETURN_INT -> forceIntReturn(
                    before,
                    action.methodName,
                    action.prototype,
                    requireNotNull(action.intValue),
                )
            }
            edited[key] = after
        }

        // Save only after every transformation succeeds, so a failed plan does not leave a half-patched workspace.
        edited.forEach { (key, text) ->
            val parts = key.split('|', limit = 2)
            PatchLabEngine.saveClass(workspace, parts[0], parts[1], text)
        }
        return ApplyResult(plan.actions)
    }

    internal fun suggestForTesting(
        category: String,
        methodName: String,
        prototype: String,
        baseScore: Int = 70,
    ): Suggestion? = suggest(category, methodName, prototype, baseScore)

    internal fun forceIntReturnForTesting(
        classText: String,
        methodName: String,
        prototype: String,
        value: Int,
    ): String = forceIntReturn(classText, methodName, prototype, value)

    private fun selectDiverse(candidates: List<Action>): List<Action> {
        if (candidates.size <= MAX_ACTIONS) return candidates
        val selected = mutableListOf<Action>()
        CATEGORY_PRIORITY.forEach { category ->
            candidates.firstOrNull { it.category == category && it !in selected }?.let(selected::add)
            if (selected.size >= MAX_ACTIONS) return selected
        }
        candidates.forEach { action ->
            if (selected.size >= MAX_ACTIONS) return@forEach
            if (action !in selected) selected += action
        }
        return selected
    }

    private fun suggest(category: String, methodName: String, prototype: String, baseScore: Int): Suggestion? {
        val tokens = identifierTokens(methodName)
        val compact = tokens.joinToString("")
        if (prototype.endsWith(")Z")) {
            val negative = NEGATIVE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
            val decisionPrefix = tokens.firstOrNull() in DECISION_PREFIXES
            return when (category) {
                "ENTITLEMENT_TRUST" -> {
                    if (PENDING_MARKERS.any { it in tokens }) return null
                    val signal = ENTITLEMENT_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || !decisionPrefix) null
                    else if (negative) {
                        Suggestion(
                            Mode.RETURN_FALSE,
                            null,
                            (baseScore + 8).coerceIn(0, 100),
                            "Демонстрация: отрицательное client-side entitlement-состояние принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE,
                            null,
                            (baseScore + 10).coerceIn(0, 100),
                            "Демонстрация: локальное решение о premium/access/entitlement принудительно возвращает true.",
                        )
                    }
                }

                "FEATURE_CONFIG" -> {
                    val signal = FEATURE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || !decisionPrefix) null
                    else if (negative) {
                        Suggestion(
                            Mode.RETURN_FALSE,
                            null,
                            (baseScore + 4).coerceIn(0, 100),
                            "Демонстрация: локальный disabled/blocked feature-флаг принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE,
                            null,
                            (baseScore + 6).coerceIn(0, 100),
                            "Демонстрация: локальный feature/config gate принудительно возвращает true.",
                        )
                    }
                }

                "INTEGRITY" -> {
                    val signal = INTEGRITY_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || !decisionPrefix) null
                    else if (negative) {
                        Suggestion(
                            Mode.RETURN_FALSE,
                            null,
                            (baseScore + 8).coerceIn(0, 100),
                            "Демонстрация: client-side tamper/root/emulator/debugger сигнал принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE,
                            null,
                            (baseScore + 6).coerceIn(0, 100),
                            "Демонстрация: локальная integrity/signature/attestation проверка принудительно возвращает true.",
                        )
                    }
                }

                "LOCAL_STATE" -> {
                    val signal = LOCAL_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || !decisionPrefix) null
                    else if ("dead" in tokens || "empty" in tokens || "depleted" in tokens) {
                        Suggestion(
                            Mode.RETURN_FALSE,
                            null,
                            baseScore.coerceIn(0, 100),
                            "Демонстрация: локальное отрицательное state-решение принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE,
                            null,
                            baseScore.coerceIn(0, 100),
                            "Демонстрация: локальное state-решение принудительно возвращает true.",
                        )
                    }
                }

                else -> null
            }
        }

        if (category == "LOCAL_STATE" && prototype.lastReturnType() in setOf('I', 'S', 'B', 'C')) {
            val selected = LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in tokens } ?: return null
            return Suggestion(
                Mode.RETURN_INT,
                selected.value,
                (baseScore + 4).coerceIn(0, 100),
                "Демонстрация: application-owned ${selected.key} getter получает фиксированное тестовое значение ${selected.value}.",
            )
        }
        return null
    }

    private fun String.lastReturnType(): Char? {
        val index = lastIndexOf(')')
        return if (index >= 0 && index + 1 < length) this[index + 1] else null
    }

    private fun identifierTokens(value: String): Set<String> {
        val expanded = value.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        return expanded.lowercase(Locale.ROOT)
            .split(Regex("[^a-z0-9]+"))
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun forceIntReturn(classText: String, methodName: String, prototype: String, value: Int): String {
        require(prototype.lastReturnType() in setOf('I', 'S', 'B', 'C')) {
            "AutoMod integer template поддерживает только int/short/byte/char return"
        }
        require(value in Short.MIN_VALUE..Short.MAX_VALUE) { "Тестовое значение не помещается в const/16" }
        val range = methodRange(classText, methodName, prototype)
        val block = classText.substring(range)
        val locals = LOCALS.find(block) ?: error("Метод не содержит .locals")
        val oldLocals = locals.groupValues[2].toInt()
        require(oldLocals <= 254) { "В методе слишком много локальных регистров" }
        val reg = oldLocals
        val indent = locals.groupValues[1]
        val marker = "# UniRevLab AutoMod Demo"
        require(marker !in block) { "AutoMod уже применён к этому методу" }
        val newLocalsLine = "${indent}.locals ${oldLocals + 1}"
        val literal = if (value < 0) "-0x${(-value).toString(16)}" else "0x${value.toString(16)}"
        val patch = buildString {
            append('\n')
            append(indent).append(marker).append('\n')
            append(indent).append("const/16 v").append(reg).append(", ").append(literal).append('\n')
            append(indent).append("return v").append(reg).append('\n')
        }
        val updatedBlock = block.replaceRange(locals.range, newLocalsLine + patch)
        return classText.replaceRange(range, updatedBlock)
    }

    private fun methodRange(text: String, methodName: String, prototype: String): IntRange {
        val header = Regex("(?m)^\\.method[^\\n]*\\s${Regex.escape(methodName)}${Regex.escape(prototype)}\\s*$")
            .find(text) ?: error("Метод $methodName$prototype не найден в Smali-классе")
        val end = Regex("(?m)^\\.end method\\s*$").find(text, header.range.last + 1)
            ?: error("У метода $methodName$prototype нет .end method")
        return header.range.first..end.range.last
    }

    private val LOCALS = Regex("(?m)^(\\s*)\\.locals\\s+(\\d+)\\s*$")
    private val DECISION_PREFIXES = setOf("is", "has", "can", "allow", "allows", "check", "verify", "validate", "enable", "should", "may")
    private val NEGATIVE_BOOLEAN_MARKERS = setOf(
        "expired", "locked", "blocked", "denied", "disabled", "tampered", "rooted", "emulator",
        "debug", "debugger", "hooked", "modified", "compromised", "fraud", "invalid",
    )
    private val PENDING_MARKERS = setOf("pending", "processing", "acknowledging", "acknowledged")
    private val ENTITLEMENT_BOOLEAN_MARKERS = setOf(
        "premium", "pro", "vip", "paid", "subscription", "subscribed", "entitlement", "entitled",
        "access", "owned", "unlocked", "licensed", "license", "trial",
    )
    private val FEATURE_BOOLEAN_MARKERS = setOf("feature", "flag", "enabled", "available", "variant", "experiment", "config")
    private val INTEGRITY_BOOLEAN_MARKERS = setOf(
        "integrity", "tamper", "signature", "checksum", "attestation", "attest", "root", "rooted",
        "emulator", "debug", "debugger", "hook", "hooked", "modified", "trusted", "valid", "verified", "secure",
    )
    private val LOCAL_BOOLEAN_MARKERS = setOf("alive", "dead", "lives", "energy", "stamina", "ammo", "currency", "coins", "gems")
    private val LOCAL_INT_VALUES = linkedMapOf(
        "cooldown" to 0,
        "rank" to 1,
        "speed" to 5,
        "health" to 999,
        "hp" to 999,
        "lives" to 999,
        "energy" to 999,
        "stamina" to 999,
        "armor" to 999,
        "damage" to 999,
        "score" to 9999,
        "balance" to 9999,
        "coins" to 9999,
        "coin" to 9999,
        "gems" to 9999,
        "gem" to 9999,
        "currency" to 9999,
        "wallet" to 9999,
        "credits" to 9999,
    )
    private val CATEGORY_PRIORITY = listOf("ENTITLEMENT_TRUST", "LOCAL_STATE", "FEATURE_CONFIG", "INTEGRITY")
    private const val MAX_ACTIONS = 4
}
