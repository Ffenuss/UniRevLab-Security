package org.unirevlab.security.analysis

import java.util.Locale

/**
 * Produces a reproducible, SHA-bound native mod plan from IL2CPP evidence.
 *
 * This class deliberately does not guess addresses. A candidate is buildable only when the
 * evidence contains an aligned RVA and the native correlation is VERIFIED or SUPPORTED.
 * Monetization, entitlement and network-authentication surfaces are excluded from automatic
 * behavior-changing plans.
 */
object Il2CppModBuilderEngine {
    enum class ActionKind { CALL_VOID, CALL_BOOL, CALL_INT, CALL_FLOAT }
    enum class Availability { BUILDABLE, NEEDS_RVA, UNSAFE_CATEGORY, UNSUPPORTED_SIGNATURE }

    data class Action(
        val id: String,
        val title: String,
        val managedIdentity: String,
        val nativeLibrary: String,
        val rva: Long?,
        val kind: ActionKind?,
        val defaultValue: String? = null,
        val availability: Availability,
        val confidence: String,
        val diagnostic: String,
    )

    data class Plan(
        val artifactSha256: String,
        val targetAbi: String,
        val actions: List<Action>,
        val diagnostics: List<String>,
    ) {
        val buildable: List<Action> get() = actions.filter { it.availability == Availability.BUILDABLE }
    }

    fun plan(
        artifactSha256: String,
        explorer: Il2CppEvidenceExplorerModel.Result,
        targetAbi: String = "arm64-v8a",
    ): Plan {
        require(artifactSha256.matches(Regex("[0-9a-fA-F]{64}"))) { "Нужен полный SHA-256 исходного APK" }
        require(targetAbi == "arm64-v8a") { "Первая версия конструктора поддерживает только arm64-v8a" }

        val actions = explorer.rows.asSequence()
            .filter { it.kind == "METHOD" }
            .map(::toAction)
            .distinctBy { "${it.nativeLibrary}|${it.rva}|${it.managedIdentity}" }
            .sortedWith(compareBy<Action> { it.availability }.thenByDescending { confidenceRank(it.confidence) }.thenBy { it.title })
            .toList()

        val diagnostics = buildList {
            if (!explorer.il2cppDetected) add("IL2CPP не подтверждён")
            if (!explorer.nativeDataAvailable) add("Нет нативной корреляции: сначала выполните полный IL2CPP dump")
            if (!explorer.nativeCoverageComplete) add("Нативное покрытие неполное; методы без RVA оставлены диагностическими")
            add("К сборке: ${actions.count { it.availability == Availability.BUILDABLE }}")
            add("Без RVA: ${actions.count { it.availability == Availability.NEEDS_RVA }}")
            add("Исключено политикой безопасности: ${actions.count { it.availability == Availability.UNSAFE_CATEGORY }}")
        }
        return Plan(artifactSha256.lowercase(Locale.ROOT), targetAbi, actions, diagnostics)
    }

    /** Whole-token search: `hp` matches HP/get_HP, but never SmoothPath. */
    fun filter(actions: List<Action>, query: String): List<Action> {
        val wanted = tokens(query)
        if (wanted.isEmpty()) return actions
        return actions.filter { action ->
            val available = tokens("${action.title} ${action.managedIdentity}")
            wanted.all { it in available }
        }
    }

    fun exportManifest(plan: Plan, selectedIds: Set<String>): String {
        val selected = plan.buildable.filter { it.id in selectedIds }
        require(selected.isNotEmpty()) { "Не выбрано ни одного подтверждённого действия" }
        return buildString {
            append("{\n  \"schema\": \"unirevlab.native-mod-plan.v1\",\n")
            append("  \"artifactSha256\": \"").append(plan.artifactSha256).append("\",\n")
            append("  \"abi\": \"").append(plan.targetAbi).append("\",\n  \"actions\": [\n")
            selected.forEachIndexed { index, action ->
                append("    {\"id\":\"").append(json(action.id)).append("\",\"title\":\"")
                    .append(json(action.title)).append("\",\"library\":\"")
                    .append(json(action.nativeLibrary)).append("\",\"rva\":\"0x")
                    .append(requireNotNull(action.rva).toString(16)).append("\",\"kind\":\"")
                    .append(action.kind!!.name).append("\"")
                action.defaultValue?.let { append(",\"defaultValue\":\"").append(json(it)).append("\"") }
                append('}')
                if (index != selected.lastIndex) append(',')
                append('\n')
            }
            append("  ]\n}\n")
        }
    }

    private fun toAction(row: Il2CppEvidenceExplorerModel.Row): Action {
        val identity = row.managedIdentity
        val category = row.semanticCategory.uppercase(Locale.ROOT)
        val unsafe = UNSAFE_CATEGORIES.any { category.contains(it) }
        val rva = extractRva(row)
        val kind = inferKind(identity)
        val availability = when {
            unsafe -> Availability.UNSAFE_CATEGORY
            row.linkStatus !in setOf(Il2CppEvidenceExplorerModel.LinkStatus.VERIFIED, Il2CppEvidenceExplorerModel.LinkStatus.SUPPORTED) || rva == null -> Availability.NEEDS_RVA
            kind == null -> Availability.UNSUPPORTED_SIGNATURE
            else -> Availability.BUILDABLE
        }
        val title = row.analystAlias.ifBlank { identity.substringAfterLast("::", identity) }
        val diagnostic = when (availability) {
            Availability.BUILDABLE -> "Подтверждено: ${row.linkStatus}; RVA 0x${rva!!.toString(16)}"
            Availability.NEEDS_RVA -> "Нужен подтверждённый RVA из дампа/корреляции"
            Availability.UNSAFE_CATEGORY -> "Автосборка отключена для покупок, лицензий и сетевой авторизации"
            Availability.UNSUPPORTED_SIGNATURE -> "Сигнатура пока не поддерживается генератором"
        }
        return Action(
            id = "il2cpp-${row.symbolIndex}-${rva?.toString(16) ?: "no-rva"}",
            title = title,
            managedIdentity = identity,
            nativeLibrary = row.nativeLibrary ?: "libil2cpp.so",
            rva = rva,
            kind = kind,
            defaultValue = defaultFor(identity, kind),
            availability = availability,
            confidence = row.linkStatus.name,
            diagnostic = diagnostic,
        )
    }

    private fun extractRva(row: Il2CppEvidenceExplorerModel.Row): Long? {
        val text = (row.evidence + listOfNotNull(row.nativeProvenance, row.nativeFunctionName)).joinToString(" ")
        val match = Regex("(?i)\\bRVA\\s*[:=]?\\s*0x([0-9a-f]{1,16})\\b").find(text) ?: return null
        val value = match.groupValues[1].toLongOrNull(16) ?: return null
        return value.takeIf { it > 0 && it % 4L == 0L }
    }

    private fun inferKind(identity: String): ActionKind? {
        val compact = identity.replace(" ", "")
        val params = compact.substringAfter('(', "").substringBefore(')', "")
        if (params.isEmpty()) return ActionKind.CALL_VOID
        val first = params.substringBefore(',').lowercase(Locale.ROOT)
        return when {
            first in setOf("bool", "boolean", "system.boolean") -> ActionKind.CALL_BOOL
            first in setOf("int", "int32", "system.int32") -> ActionKind.CALL_INT
            first in setOf("float", "single", "system.single") -> ActionKind.CALL_FLOAT
            else -> null
        }
    }

    private fun defaultFor(identity: String, kind: ActionKind?): String? = when (kind) {
        ActionKind.CALL_BOOL -> "true"
        ActionKind.CALL_INT -> if (tokens(identity).any { it in setOf("health", "hp") }) "100" else "1"
        ActionKind.CALL_FLOAT -> "1.0"
        else -> null
    }

    private fun tokens(value: String): Set<String> = value
        .replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        .lowercase(Locale.ROOT)
        .split(Regex("[^\\p{L}\\p{N}]+"))
        .filter { it.isNotBlank() }
        .toSet()

    private fun confidenceRank(value: String) = when (value) { "VERIFIED" -> 2; "SUPPORTED" -> 1; else -> 0 }
    private fun json(value: String) = value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

    private val UNSAFE_CATEGORIES = setOf("ENTITLEMENT", "PURCHASE", "PAYMENT", "LICENSE", "AUTH", "NETWORK")
}
