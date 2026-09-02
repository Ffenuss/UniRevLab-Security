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
    enum class Mode { RETURN_TRUE, RETURN_FALSE, RETURN_INT, TRACE_ONLY }

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
        val diagnostics: String = "",
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
                "AutoMod заблокирован: workspace не совпадает с проанализированным APK"
            }
        }
        val packagePrefix = report.manifest?.packageName
            ?.takeIf { it.isNotBlank() }
            ?.replace('.', '/')
            ?.let { "L$it/" }

        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        val methodsBySignature = dex?.methods.orEmpty().associateBy { method ->
            "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}"
        }
        val codeKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
        fun projectMethod(method: org.unirevlab.security.model.DexMethodReference): Boolean =
            method.dexEntry in workspace.dexEntries &&
                TamperAssessmentEngine.isProjectCodeForAutomation(method.declaringClass, packagePrefix)

        data class Evidence(
            val category: String,
            val method: org.unirevlab.security.model.DexMethodReference,
            val score: Int,
            val text: String,
        )
        val evidence = mutableListOf<Evidence>()
        fun collect(method: org.unirevlab.security.model.DexMethodReference, text: String, scorePenalty: Int = 0) {
            if (!projectMethod(method)) return
            TamperAssessmentEngine.categoriesForAutomation(text).forEach { (category, score) ->
                evidence += Evidence(category, method, (score - scorePenalty).coerceAtLeast(1), text)
            }
        }

        // Highest-signal source: exact surfaces already resolved by Tamper Assessment.
        assessment.hits.forEach { hit ->
            val dexEntry = hit.dexEntry ?: return@forEach
            val classDescriptor = hit.classDescriptor ?: return@forEach
            val methodName = hit.methodName ?: return@forEach
            val prototype = hit.prototype ?: return@forEach
            val method = methodsBySignature["$dexEntry|$classDescriptor|$methodName|$prototype"] ?: return@forEach
            if (!projectMethod(method)) return@forEach
            evidence += Evidence(
                category = hit.category,
                method = method,
                score = hit.score.coerceIn(1, 100),
                text = "${hit.preview} ${hit.location} ${method.declaringClass} ${method.name}",
            )
        }

        // Then scan the complete editable project method index. This keeps obfuscated app code eligible
        // even when package ownership cannot be inferred from a conventional Java/Kotlin namespace.
        dex?.methods.orEmpty().forEach { method ->
            collect(method, "${method.declaringClass}->${method.name}${method.prototype}")
        }
        dex?.stringXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            collect(method, "${xref.value} ${xref.callerClass} ${xref.callerName}", 2)
        }
        dex?.fieldXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            collect(method, "${xref.declaringClass} ${xref.fieldName} ${xref.fieldType} ${xref.callerClass} ${xref.callerName}", 1)
        }
        // External SDK/framework callees are not editable, but their app-owned callers are.
        dex?.callXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            collect(method, "${xref.calleeClass} ${xref.calleeName} ${xref.calleePrototype}", 3)
        }
        dex?.constants.orEmpty().forEach { constant ->
            val method = methodsByKey[constant.dexEntry to constant.methodIndex] ?: return@forEach
            collect(method, "${method.declaringClass} ${method.name} ${constant.kind} ${constant.value}", 5)
        }

        val semanticCandidates = evidence.asSequence()
            .mapNotNull { item ->
                val method = item.method
                val suggestion = suggest(item.category, method.name, method.prototype, item.score, item.text)
                    ?: return@mapNotNull null
                Action(
                    id = "automod-${item.category.lowercase(Locale.ROOT)}-${method.methodIndex}",
                    category = item.category,
                    dexEntry = method.dexEntry,
                    classDescriptor = method.declaringClass,
                    methodName = method.name,
                    prototype = method.prototype,
                    mode = suggestion.mode,
                    intValue = suggestion.intValue,
                    confidence = suggestion.confidence,
                    reason = suggestion.reason,
                )
            }
            .groupBy { it.methodKey }
            .mapNotNull { (_, values) -> values.maxByOrNull { it.confidence } }
            .sortedWith(compareByDescending<Action> { it.confidence }.thenBy { it.target })

        // If semantic mutation is not yet safe, still produce a useful evidence build by tracing
        // exact app-owned callers. This never guesses an entitlement value.
        val traceCandidates = if (semanticCandidates.isEmpty()) {
            evidence.asSequence()
                .sortedByDescending { it.score }
                .distinctBy { "${it.method.dexEntry}|${it.method.declaringClass}|${it.method.name}|${it.method.prototype}" }
                .map { item ->
                    val method = item.method
                    Action(
                        id = "automod-trace-${method.methodIndex}",
                        category = item.category,
                        dexEntry = method.dexEntry,
                        classDescriptor = method.declaringClass,
                        methodName = method.name,
                        prototype = method.prototype,
                        mode = Mode.TRACE_ONLY,
                        confidence = item.score.coerceIn(1, 100),
                        reason = "Диагностический fallback: точный app-owned caller будет трассироваться; значение не подменяется.",
                    )
                }
                .toList()
        } else emptyList()

        val smaliCache = mutableMapOf<String, String?>()
        var verificationFailures = 0
        fun verifiedBody(action: Action): Boolean {
            val classKey = "${action.dexEntry}|${action.classDescriptor}"
            val text = if (smaliCache.containsKey(classKey)) {
                smaliCache[classKey]
            } else {
                val loaded = runCatching {
                    PatchLabEngine.disassembleDex(workspace, action.dexEntry)
                    PatchLabEngine.loadClass(workspace, action.dexEntry, action.classDescriptor)
                }.getOrElse {
                    verificationFailures++
                    null
                }
                smaliCache[classKey] = loaded
                loaded
            } ?: return false
            return hasEditableMethodBody(text, action.methodName, action.prototype)
        }

        val candidates = (semanticCandidates + traceCandidates).filter(::verifiedBody)
        val selected = selectDiverse(candidates)
        val indexedEditableCount = dex?.methods.orEmpty().count { method ->
            projectMethod(method) && "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys
        }
        val verifiedEditableCount = candidates.map { it.methodKey }.distinct().size
        val exactTamperMethodHits = assessment.hits.count {
            it.dexEntry != null && it.classDescriptor != null && it.methodName != null && it.prototype != null
        }
        val diagnostics = when {
            candidates.isNotEmpty() -> "Smali-verified methods: $verifiedEditableCount; indexed bodies: $indexedEditableCount; exact tamper hits: $exactTamperMethodHits; eligible: ${candidates.size}; verification failures: $verificationFailures"
            evidence.isEmpty() -> "DEX callers не связаны с surface. Следующий маршрут: Runtime State, Native/managed или Backend Validation."
            else -> "Surface связаны с app-owned callers, но их Smali bodies недоступны. Следующий маршрут: Native/managed или Backend Validation; verification failures: $verificationFailures."
        }
        return Plan(
            artifactSha256 = workspace.artifactSha256,
            assessmentScore = assessment.score,
            assessmentBand = assessment.band,
            actions = selected,
            eligibleBeforeCap = candidates.size,
            diagnostics = diagnostics,
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
                Mode.TRACE_ONLY -> PatchLabEngine.addEntryLogHook(
                    before, action.methodName, action.prototype, "automod:${action.category}",
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
        evidence: String = "",
    ): Suggestion? = suggest(category, methodName, prototype, baseScore, evidence)

    internal fun forceIntReturnForTesting(
        classText: String,
        methodName: String,
        prototype: String,
        value: Int,
    ): String = forceIntReturn(classText, methodName, prototype, value)

    internal fun hasEditableMethodBodyForTesting(
        classText: String,
        methodName: String,
        prototype: String,
    ): Boolean = hasEditableMethodBody(classText, methodName, prototype)

    private fun hasEditableMethodBody(classText: String, methodName: String, prototype: String): Boolean {
        val header = Regex("(?m)^\\.method[^\\n]*\\s${Regex.escape(methodName)}${Regex.escape(prototype)}\\s*$")
            .find(classText) ?: return false
        if (Regex("\\b(?:abstract|native)\\b", RegexOption.IGNORE_CASE).containsMatchIn(header.value)) return false
        val end = Regex("(?m)^\\.end method\\s*$").find(classText, header.range.last + 1) ?: return false
        val block = classText.substring(header.range.first, end.range.last + 1)
        return Regex("(?m)^\\s*\\.locals\\s+\\d+\\s*$").containsMatchIn(block)
    }

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

    private fun suggest(
        category: String,
        methodName: String,
        prototype: String,
        baseScore: Int,
        evidence: String = "",
    ): Suggestion? {
        val methodTokens = identifierTokens(methodName)
        val evidenceTokens = identifierTokens(evidence)
        val tokens = methodTokens + evidenceTokens
        val compact = tokens.joinToString("")
        val methodCompact = methodTokens.joinToString("")
        val decisionPrefix = methodTokens.firstOrNull() in DECISION_PREFIXES
        val evidenceBacked = evidenceTokens.isNotEmpty() && baseScore >= 42

        if (prototype.endsWith(")Z")) {
            val negative = NEGATIVE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
            return when (category) {
                "ENTITLEMENT_TRUST" -> {
                    if (PENDING_MARKERS.any { it in tokens }) return null
                    val signal = ENTITLEMENT_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(
                            Mode.RETURN_FALSE, null, (baseScore + if (decisionPrefix) 8 else 2).coerceIn(0, 100),
                            "Демонстрация: client-side entitlement/access gate подтверждён кодом/ссылками и принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE, null, (baseScore + if (decisionPrefix) 10 else 3).coerceIn(0, 100),
                            "Демонстрация: client-side premium/access/entitlement gate подтверждён кодом/ссылками и принудительно возвращает true.",
                        )
                    }
                }
                "FEATURE_CONFIG" -> {
                    val signal = FEATURE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(Mode.RETURN_FALSE, null, (baseScore + 2).coerceIn(0, 100), "Демонстрация: локальный disabled/blocked feature-флаг принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, (baseScore + 4).coerceIn(0, 100), "Демонстрация: локальный feature/config gate принудительно возвращает true.")
                    }
                }
                "INTEGRITY" -> {
                    val signal = INTEGRITY_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(Mode.RETURN_FALSE, null, (baseScore + 6).coerceIn(0, 100), "Демонстрация: client-side tamper/root/emulator/debugger сигнал принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, (baseScore + 4).coerceIn(0, 100), "Демонстрация: локальная integrity/signature/attestation проверка принудительно возвращает true.")
                    }
                }
                "LOCAL_STATE" -> {
                    val signal = LOCAL_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if ("dead" in tokens || "empty" in tokens || "depleted" in tokens) {
                        Suggestion(Mode.RETURN_FALSE, null, baseScore.coerceIn(0, 100), "Демонстрация: локальное отрицательное state-решение принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, baseScore.coerceIn(0, 100), "Демонстрация: локальное state-решение принудительно возвращает true.")
                    }
                }
                else -> null
            }
        }

        if (category == "LOCAL_STATE" && prototype.lastReturnType() in setOf('I', 'S', 'B', 'C')) {
            val selected = LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in methodTokens }
                ?: LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in evidenceTokens }
                ?: return null
            val confidence = (baseScore + if (termInMethod(selected.key, methodTokens, methodCompact)) 4 else 0).coerceIn(0, 100)
            return Suggestion(
                Mode.RETURN_INT, selected.value, confidence,
                "Демонстрация: project-owned ${selected.key} state getter/consumer подтверждён индексом и получает фиксированное тестовое значение ${selected.value}.",
            )
        }
        return null
    }

    private fun termInMethod(term: String, methodTokens: Set<String>, methodCompact: String): Boolean =
        term in methodTokens || methodCompact.contains(term)

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
    private val LOCAL_BOOLEAN_MARKERS = setOf("alive", "dead", "lives", "energy", "stamina", "ammo", "currency", "coins", "gems", "money", "cash", "gold", "mana")
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
        "money" to 9999,
        "cash" to 9999,
        "gold" to 9999,
        "diamond" to 9999,
        "diamonds" to 9999,
        "xp" to 9999,
        "experience" to 9999,
        "level" to 99,
        "mana" to 999,
        "ammo" to 999,
        "attack" to 999,
        "defense" to 999,
        "defence" to 999,
        "power" to 999,
        "fuel" to 999,
        "ticket" to 999,
        "tickets" to 999,
        "points" to 9999,
        "stars" to 999,
    )
    private val CATEGORY_PRIORITY = listOf("ENTITLEMENT_TRUST", "LOCAL_STATE", "FEATURE_CONFIG", "INTEGRITY")
    private const val MAX_ACTIONS = 4
}
