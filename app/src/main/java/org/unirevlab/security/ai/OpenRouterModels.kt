package org.unirevlab.security.ai

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigDecimal

data class OpenRouterModel(
    val id: String,
    val name: String,
    val description: String,
    val contextLength: Int,
    val supportsTools: Boolean,
) {
    val contextLabel: String
        get() = when {
            contextLength >= 1_000_000 -> "${contextLength / 1_000_000.0}M context"
            contextLength >= 1_000 -> "${contextLength / 1_000}K context"
            else -> "контекст определяется маршрутизатором"
        }
}

data class OpenRouterChatMessage(
    val role: String,
    val text: String,
    val modelId: String? = null,
)

data class OpenRouterChatResult(
    val text: String,
    val modelId: String,
)

object OpenRouterModelCatalog {
    private val freeRouter = OpenRouterModel(
        id = "openrouter/free",
        name = "Автовыбор бесплатной модели",
        description = "OpenRouter подберёт доступную бесплатную модель для запроса.",
        contextLength = 0,
        supportsTools = true,
    )

    fun defaultModel(): OpenRouterModel = freeRouter

    fun parseFreeModels(raw: String): List<OpenRouterModel> {
        val root = JSONObject(raw)
        val data = root.optJSONArray("data") ?: JSONArray()
        val parsed = buildList {
            for (index in 0 until data.length()) {
                val item = data.optJSONObject(index) ?: continue
                val id = item.optString("id").trim()
                if (!MODEL_ID.matches(id)) continue
                val pricing = item.optJSONObject("pricing") ?: continue
                if (!pricing.isZero("prompt") || !pricing.isZero("completion")) continue
                val architecture = item.optJSONObject("architecture")
                if (!architecture.supportsTextInputAndOutput()) continue
                val parameters = item.optJSONArray("supported_parameters").strings()
                add(
                    OpenRouterModel(
                        id = id,
                        name = item.optString("name", id).trim().ifBlank { id },
                        description = item.optString("description").trim().take(MAX_DESCRIPTION_CHARS),
                        contextLength = item.optInt("context_length", 0).coerceAtLeast(0),
                        supportsTools = "tools" in parameters,
                    )
                )
            }
        }
        return (listOf(freeRouter) + parsed)
            .distinctBy { it.id }
            .sortedWith(compareBy<OpenRouterModel> { it.id != freeRouter.id }.thenByDescending { it.contextLength }.thenBy { it.name })
    }

    fun parseChatResult(raw: String, requestedModel: String): OpenRouterChatResult {
        val root = JSONObject(raw)
        val choice = root.optJSONArray("choices")?.optJSONObject(0)
            ?: error("OpenRouter вернул ответ без choices")
        val message = choice.optJSONObject("message") ?: error("OpenRouter вернул ответ без message")
        val content = when (val value = message.opt("content")) {
            is String -> value
            is JSONArray -> buildString {
                for (index in 0 until value.length()) {
                    val part = value.optJSONObject(index)?.optString("text").orEmpty()
                    if (part.isNotBlank()) append(part)
                }
            }
            else -> ""
        }.trim()
        require(content.isNotBlank()) { "Модель вернула пустой ответ" }
        return OpenRouterChatResult(
            text = content.take(MAX_RESPONSE_CHARS),
            modelId = root.optString("model", requestedModel).ifBlank { requestedModel },
        )
    }

    fun parseError(raw: String): String? = runCatching {
        val root = JSONObject(raw)
        val error = root.optJSONObject("error")
        error?.optString("message")?.trim()?.takeIf { it.isNotBlank() }
    }.getOrNull()

    private fun JSONObject.isZero(key: String): Boolean = runCatching {
        BigDecimal(optString(key, "1")).compareTo(BigDecimal.ZERO) == 0
    }.getOrDefault(false)

    private fun JSONObject?.supportsTextInputAndOutput(): Boolean {
        if (this == null) return true
        val inputs = optJSONArray("input_modalities").strings()
        val outputs = optJSONArray("output_modalities").strings()
        return (inputs.isEmpty() || "text" in inputs) && (outputs.isEmpty() || "text" in outputs)
    }

    private fun JSONArray?.strings(): Set<String> {
        if (this == null) return emptySet()
        return buildSet {
            for (index in 0 until length()) optString(index).takeIf { it.isNotBlank() }?.let(::add)
        }
    }

    private val MODEL_ID = Regex("[A-Za-z0-9._~:-]+/[A-Za-z0-9._~:-]+")
    private const val MAX_DESCRIPTION_CHARS = 600
    private const val MAX_RESPONSE_CHARS = 120_000
}
