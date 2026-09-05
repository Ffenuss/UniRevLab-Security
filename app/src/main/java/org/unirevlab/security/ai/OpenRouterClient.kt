package org.unirevlab.security.ai

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class OpenRouterClient(
    private val baseUrl: String = "https://openrouter.ai/api/v1",
) {
    fun fetchFreeModels(): List<OpenRouterModel> {
        val connection = open("$baseUrl/models", "GET")
        return connection.useResponse { status, body ->
            if (status !in 200..299) throw apiFailure(status, body)
            OpenRouterModelCatalog.parseFreeModels(body)
        }
    }

    fun complete(
        apiKey: String,
        model: OpenRouterModel,
        reportContext: ReportContext,
        history: List<OpenRouterChatMessage>,
        question: String,
    ): OpenRouterChatResult {
        require(apiKey.isNotBlank()) { "API-ключ OpenRouter не сохранён" }
        require(question.isNotBlank()) { "Введите вопрос" }
        val messages = JSONArray().put(
            JSONObject()
                .put("role", "system")
                .put("content", SYSTEM_PROMPT)
        )
        history.takeLast(MAX_HISTORY_MESSAGES).forEach { message ->
            if (message.role == "user" || message.role == "assistant") {
                messages.put(
                    JSONObject()
                        .put("role", message.role)
                        .put("content", message.text.take(MAX_HISTORY_MESSAGE_CHARS))
                )
            }
        }
        messages.put(
            JSONObject()
                .put("role", "user")
                .put(
                    "content",
                    buildString(reportContext.text.length + question.length + 512) {
                        appendLine("Ниже контекст из выбранного пользователем полного отчёта UniRevLab.")
                        appendLine(reportContext.text)
                        appendLine("\nВопрос пользователя:")
                        append(question.take(MAX_QUESTION_CHARS))
                    }
                )
        )

        val payload = JSONObject()
            .put("model", model.id)
            .put("messages", messages)
            .put("temperature", 0.15)
            .put("max_tokens", MAX_COMPLETION_TOKENS)
            .put(
                "provider",
                JSONObject()
                    .put("data_collection", "deny")
                    .put("allow_fallbacks", true)
            )

        val connection = open("$baseUrl/chat/completions", "POST").apply {
            setRequestProperty("Authorization", "Bearer $apiKey")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("HTTP-Referer", APP_URL)
            setRequestProperty("X-OpenRouter-Title", APP_TITLE)
            doOutput = true
            outputStream.buffered().use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
        }
        return connection.useResponse { status, body ->
            if (status !in 200..299) throw apiFailure(status, body)
            OpenRouterModelCatalog.parseChatResult(body, model.id)
        }
    }

    private fun open(url: String, method: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            useCaches = false
            setRequestProperty("Accept", "application/json")
        }

    private fun apiFailure(status: Int, body: String): IllegalStateException {
        val detail = OpenRouterModelCatalog.parseError(body)
        val friendly = when (status) {
            401, 403 -> "OpenRouter отклонил API-ключ"
            402 -> "Для этого запроса недостаточно бесплатного лимита или кредитов"
            408 -> "OpenRouter не успел обработать запрос"
            413 -> "Контекст отчёта оказался слишком большим для выбранной модели"
            429 -> "Достигнут бесплатный лимит запросов OpenRouter. Повторите позже"
            in 500..599 -> "OpenRouter или провайдер модели временно недоступен"
            else -> "Ошибка OpenRouter HTTP $status"
        }
        return IllegalStateException(listOfNotNull(friendly, detail?.take(300)).distinct().joinToString(": "))
    }

    private inline fun <T> HttpURLConnection.useResponse(block: (Int, String) -> T): T = try {
        val status = responseCode
        val stream = if (status in 200..299) inputStream else errorStream
        block(status, stream.readBoundedText())
    } finally {
        disconnect()
    }

    private fun InputStream?.readBoundedText(): String {
        if (this == null) return ""
        return BufferedReader(InputStreamReader(this, Charsets.UTF_8)).use { reader ->
            val output = StringBuilder()
            val buffer = CharArray(8_192)
            while (output.length < MAX_RESPONSE_BODY_CHARS) {
                val read = reader.read(buffer, 0, minOf(buffer.size, MAX_RESPONSE_BODY_CHARS - output.length))
                if (read < 0) break
                output.append(buffer, 0, read)
            }
            output.toString()
        }
    }

    companion object {
        private const val APP_TITLE = "UniRevLab Security"
        private const val APP_URL = "https://github.com/Ffenuss/UniRevLab-Security"
        private const val CONNECT_TIMEOUT_MS = 20_000
        private const val READ_TIMEOUT_MS = 120_000
        private const val MAX_HISTORY_MESSAGES = 10
        private const val MAX_HISTORY_MESSAGE_CHARS = 12_000
        private const val MAX_QUESTION_CHARS = 8_000
        private const val MAX_COMPLETION_TOKENS = 4_000
        private const val MAX_RESPONSE_BODY_CHARS = 1_000_000
        private val SYSTEM_PROMPT = """
            Ты — помощник по авторизованному аудиту безопасности Android-приложений.
            Отвечай на русском языке и опирайся только на переданный отчёт. Чётко разделяй подтверждённые факты,
            эвристические кандидаты и то, чего в evidence недостаточно. Для каждой проблемы объясняй риск,
            доказательство и конкретное защитное исправление. Не выдавай metadata token за native RVA.
            Не придумывай отсутствующие адреса, классы или методы. Не создавай инструкции для пиратства,
            обхода оплаты, вмешательства в чужие сервисы или несанкционированной эксплуатации.
        """.trimIndent()
    }
}
