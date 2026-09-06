package org.unirevlab.security.ai

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class OpenRouterClient(
    private val baseUrl: String = "https://openrouter.ai/api/v1",
) {
    fun fetchFreeModels(responseLanguage: String = "ru"): List<OpenRouterModel> {
        val connection = open("$baseUrl/models", "GET")
        return connection.useResponse { status, body ->
            if (status !in 200..299) throw apiFailure(status, body, responseLanguage)
            OpenRouterModelCatalog.parseFreeModels(body)
        }
    }

    fun complete(
        apiKey: String,
        model: OpenRouterModel,
        reportContext: ReportContext,
        history: List<OpenRouterChatMessage>,
        question: String,
        dataPolicy: OpenRouterDataPolicy = OpenRouterDataPolicy.STRICT,
        responseLanguage: String = "ru",
    ): OpenRouterChatResult {
        require(apiKey.isNotBlank()) {
            if (responseLanguage == "en") "OpenRouter API key is not saved" else "API-ключ OpenRouter не сохранён"
        }
        require(question.isNotBlank()) {
            if (responseLanguage == "en") "Enter a question" else "Введите вопрос"
        }
        val payload = buildPayload(model, reportContext, history, question, dataPolicy, responseLanguage)

        val connection = open("$baseUrl/chat/completions", "POST").apply {
            setRequestProperty("Authorization", "Bearer $apiKey")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("HTTP-Referer", APP_URL)
            setRequestProperty("X-OpenRouter-Title", APP_TITLE)
        }
        val timedOut = AtomicBoolean(false)
        val watchdog = WATCHDOG.schedule({
            timedOut.set(true)
            connection.disconnect()
        }, TOTAL_REQUEST_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        return try {
            val bytes = payload.toString().toByteArray(Charsets.UTF_8)
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(bytes.size)
            connection.outputStream.buffered().use { it.write(bytes) }
            connection.useResponse { status, body ->
                if (status !in 200..299) throw apiFailure(status, body, responseLanguage)
                OpenRouterModelCatalog.parseChatResult(body, model.id)
            }
        } catch (error: IOException) {
            if (timedOut.get()) {
                val message = if (responseLanguage == "en") {
                    "OpenRouter did not complete the request within ${TOTAL_REQUEST_TIMEOUT_MS / 1_000} seconds. Select another free model or try again later."
                } else {
                    "OpenRouter не завершил запрос за ${TOTAL_REQUEST_TIMEOUT_MS / 1_000} секунд. Выберите другую бесплатную модель или повторите позже."
                }
                throw IOException(message, error)
            }
            throw error
        } finally {
            watchdog.cancel(false)
            connection.disconnect()
        }
    }

    internal fun buildPayload(
        model: OpenRouterModel,
        reportContext: ReportContext,
        history: List<OpenRouterChatMessage>,
        question: String,
        dataPolicy: OpenRouterDataPolicy,
        responseLanguage: String = "ru",
    ): JSONObject {
        val messages = JSONArray().put(
            JSONObject()
                .put("role", "system")
                .put("content", systemPrompt(responseLanguage))
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
                        appendLine(
                            if (responseLanguage == "en") "Below is context from the complete UniRevLab report selected by the user."
                            else "Ниже контекст из выбранного пользователем полного отчёта UniRevLab."
                        )
                        appendLine(reportContext.text)
                        appendLine(if (responseLanguage == "en") "\nUser question:" else "\nВопрос пользователя:")
                        append(question.take(MAX_QUESTION_CHARS))
                    }
                )
        )

        return JSONObject()
            .put("model", model.id)
            .put("messages", messages)
            .put("temperature", 0.15)
            .put("max_tokens", MAX_COMPLETION_TOKENS)
            .put(
                "provider",
                JSONObject()
                    .put("data_collection", dataPolicy.apiValue)
                    .put("allow_fallbacks", true)
            )
    }

    private fun open(url: String, method: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            useCaches = false
            setRequestProperty("Accept", "application/json")
        }

    private fun apiFailure(status: Int, body: String, language: String): OpenRouterApiException {
        val detail = OpenRouterModelCatalog.parseError(body)
        val reason = classifyOpenRouterFailure(status, detail)
        val english = language == "en"
        val message = if (reason == OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT) {
            if (english) "No endpoint for this model matches the current data policy" else "Для модели нет endpoint, совместимого с текущей политикой данных"
        } else {
            val friendly = if (english) when (status) {
                401, 403 -> "OpenRouter rejected the API key"
                402 -> "Insufficient free quota or credits for this request"
                408 -> "OpenRouter did not process the request in time"
                413 -> "The report context is too large for the selected model"
                429 -> "OpenRouter free request limit reached; try again later"
                in 500..599 -> "OpenRouter or the model provider is temporarily unavailable"
                else -> "OpenRouter HTTP $status"
            } else when (status) {
                401, 403 -> "OpenRouter отклонил API-ключ"
                402 -> "Для этого запроса недостаточно бесплатного лимита или кредитов"
                408 -> "OpenRouter не успел обработать запрос"
                413 -> "Контекст отчёта оказался слишком большим для выбранной модели"
                429 -> "Достигнут бесплатный лимит запросов OpenRouter. Повторите позже"
                in 500..599 -> "OpenRouter или провайдер модели временно недоступен"
                else -> "Ошибка OpenRouter HTTP $status"
            }
            listOfNotNull(friendly, detail?.take(300)).distinct().joinToString(": ")
        }
        return OpenRouterApiException(status, reason, message)
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
        private const val TOTAL_REQUEST_TIMEOUT_MS = 150_000
        private const val MAX_HISTORY_MESSAGES = 10
        private const val MAX_HISTORY_MESSAGE_CHARS = 12_000
        private const val MAX_QUESTION_CHARS = 8_000
        private const val MAX_COMPLETION_TOKENS = 4_000
        private const val MAX_RESPONSE_BODY_CHARS = 1_000_000
        private val WATCHDOG = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "openrouter-timeout").apply { isDaemon = true }
        }
        private fun systemPrompt(language: String): String = if (language == "en") {
            """
                You assist with authorized Android application security assessments.
                Answer in English and rely only on the supplied report. Clearly separate confirmed facts,
                heuristic candidates, and missing evidence. For each issue, explain risk, evidence, and a concrete
                defensive fix. Never present a metadata token as a native RVA. Do not invent absent addresses,
                classes, or methods, and do not provide instructions for piracy, payment bypass, unauthorized
                service interference, or exploitation.
            """.trimIndent()
        } else {
            """
                Ты — помощник по авторизованному аудиту безопасности Android-приложений.
                Отвечай на русском языке и опирайся только на переданный отчёт. Чётко разделяй подтверждённые факты,
                эвристические кандидаты и то, чего в evidence недостаточно. Для каждой проблемы объясняй риск,
                доказательство и конкретное защитное исправление. Не выдавай metadata token за native RVA.
                Не придумывай отсутствующие адреса, классы или методы. Не создавай инструкции для пиратства,
                обхода оплаты, вмешательства в чужие сервисы или несанкционированной эксплуатации.
            """.trimIndent()
        }
    }
}
