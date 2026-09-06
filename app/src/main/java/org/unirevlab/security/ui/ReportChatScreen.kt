package org.unirevlab.security.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.ai.ImportedReport
import org.unirevlab.security.ai.OpenRouterChatMessage
import org.unirevlab.security.ai.OpenRouterClient
import org.unirevlab.security.ai.OpenRouterApiException
import org.unirevlab.security.ai.OpenRouterDataPolicy
import org.unirevlab.security.ai.OpenRouterFailureReason
import org.unirevlab.security.ai.OpenRouterModel
import org.unirevlab.security.ai.OpenRouterModelCatalog
import org.unirevlab.security.ai.OpenRouterSecretStore
import org.unirevlab.security.ai.ReportContextEngine
import org.unirevlab.security.ai.ReportImportStore
import java.io.File
import java.util.Locale

@Composable
fun ReportChatScreen(
    language: AppLanguage,
    currentReport: File?,
    currentDumpEvidence: File? = null,
    currentReportLabel: String?,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val scope = rememberCoroutineScope()
    val secretStore = remember { OpenRouterSecretStore(appContext) }
    val importStore = remember { ReportImportStore(appContext) }
    val client = remember { OpenRouterClient() }

    val initialCurrent = remember(currentReport) {
        currentReport?.takeIf { it.isFile }?.let {
            ImportedReport(
                it,
                currentReportLabel?.takeIf(String::isNotBlank) ?: it.name,
                it.length(),
                currentDumpEvidence?.takeIf { evidence -> evidence.isFile && evidence.length() > 0 },
            )
        }
    }
    var report by remember(currentReport) { mutableStateOf(initialCurrent ?: importStore.current()) }
    var models by remember { mutableStateOf(listOf(OpenRouterModelCatalog.defaultModel())) }
    var selectedModel by remember { mutableStateOf(OpenRouterModelCatalog.defaultModel()) }
    var keyDraft by remember { mutableStateOf("") }
    var keySaved by remember { mutableStateOf(secretStore.hasKey()) }
    var allowTrainingProviders by remember { mutableStateOf(false) }
    var privacyConflict by remember { mutableStateOf(false) }
    var messages by remember { mutableStateOf<List<OpenRouterChatMessage>>(emptyList()) }
    var question by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var busyMessage by remember { mutableStateOf(language.text("Подготавливаю запрос…", "Preparing request…")) }
    var refreshingModels by remember { mutableStateOf(false) }
    var showModels by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun refreshModels() {
        if (refreshingModels) return
        scope.launch {
            refreshingModels = true
            error = null
            val result = runCatching { withContext(Dispatchers.IO) { client.fetchFreeModels(language.code) } }
            result.onSuccess { loaded ->
                models = loaded
                val savedId = secretStore.selectedModelId()
                selectedModel = loaded.firstOrNull { it.id == savedId }
                    ?: loaded.firstOrNull { it.id == selectedModel.id }
                    ?: OpenRouterModelCatalog.defaultModel()
                status = language.text("Загружено бесплатных моделей: ${loaded.size}", "Free models loaded: ${loaded.size}")
            }.onFailure { failure ->
                error = failure.userMessage(language.text("Не удалось загрузить список моделей", "Unable to load the model list"))
            }
            refreshingModels = false
        }
    }

    val reportPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            scope.launch {
                busy = true
                error = null
                val result = runCatching { withContext(Dispatchers.IO) { importStore.import(uri) } }
                result.onSuccess { imported ->
                    report = imported
                    messages = emptyList()
                    allowTrainingProviders = false
                    privacyConflict = false
                    status = language.text("Полный отчёт загружен: ${formatBytes(imported.sizeBytes)}", "Full report loaded: ${formatBytes(imported.sizeBytes)}")
                }.onFailure { failure -> error = failure.userMessage(language.text("Не удалось импортировать отчёт", "Unable to import report")) }
                busy = false
            }
        }
    }

    fun send() {
        val selectedReport = report ?: return
        val prompt = question.trim()
        if (prompt.isBlank() || busy) return
        scope.launch {
            busy = true
            error = null
            privacyConflict = false
            question = ""
            val userMessage = OpenRouterChatMessage("user", prompt)
            val historyBefore = messages
            messages = messages + userMessage
            val result = runCatching {
                val key = withContext(Dispatchers.IO) {
                    requireNotNull(secretStore.loadKey()) { language.text("Сначала сохраните API-ключ OpenRouter", "Save an OpenRouter API key first") }
                }
                val policy = if (allowTrainingProviders) {
                    OpenRouterDataPolicy.FREE_MODEL_COMPATIBLE
                } else {
                    OpenRouterDataPolicy.STRICT
                }
                busyMessage = language.text("Быстро индексирую полный отчёт ${formatBytes(selectedReport.sizeBytes)}…", "Indexing the full ${formatBytes(selectedReport.sizeBytes)} report…")
                val primaryContext = withContext(Dispatchers.IO) {
                    buildReportAndDumpContext(selectedReport, prompt, selectedModel.contextLength)
                }
                busyMessage = language.text("Контекст готов. Жду OpenRouter (не более 150 секунд)…", "Context ready. Waiting for OpenRouter (up to 150 seconds)…")
                try {
                    withContext(Dispatchers.IO) {
                        try {
                            ChatAttempt(
                            answer = client.complete(key, selectedModel, primaryContext, historyBefore, prompt, policy, language.code),
                            reportContext = primaryContext,
                            strictFallbackUsed = false,
                            )
                        } catch (failure: OpenRouterApiException) {
                            throw failure
                        }
                    }
                } catch (failure: OpenRouterApiException) {
                    val canUseStrictFallback = policy == OpenRouterDataPolicy.STRICT &&
                        failure.reason == OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT &&
                        selectedModel.id != OpenRouterModelCatalog.defaultModel().id
                    if (!canUseStrictFallback) throw failure
                    val fallback = OpenRouterModelCatalog.defaultModel()
                    busyMessage = language.text("Выбранная модель отклонена политикой. Готовлю безопасный резервный маршрут…", "The selected model was rejected by policy. Preparing a safe fallback…")
                    val fallbackContext = withContext(Dispatchers.IO) {
                        buildReportAndDumpContext(selectedReport, prompt, fallback.contextLength)
                    }
                    busyMessage = language.text("Жду безопасный резервный маршрут OpenRouter (не более 150 секунд)…", "Waiting for the safe OpenRouter fallback (up to 150 seconds)…")
                    withContext(Dispatchers.IO) {
                        ChatAttempt(
                            answer = client.complete(key, fallback, fallbackContext, historyBefore, prompt, policy, language.code),
                            reportContext = fallbackContext,
                            strictFallbackUsed = true,
                        )
                    }
                }
            }
            result.onSuccess { attempt ->
                messages = messages + OpenRouterChatMessage("assistant", attempt.answer.text, attempt.answer.modelId)
                val privacyStatus = if (allowTrainingProviders) {
                    language.text("Режим совместимости", "Compatibility mode")
                } else if (attempt.strictFallbackUsed) {
                    language.text("Строгий режим · выбранная модель недоступна, безопасно использована ${attempt.answer.modelId}", "Strict mode · selected model unavailable; safely used ${attempt.answer.modelId}")
                } else {
                    language.text("Строгий режим", "Strict mode")
                }
                status = if (attempt.reportContext.completeFileIncluded) {
                    language.text("$privacyStatus · модель получила весь файл целиком · ${formatBytes(attempt.reportContext.reportBytes)}", "$privacyStatus · the complete file was supplied · ${formatBytes(attempt.reportContext.reportBytes)}")
                } else {
                    language.text("$privacyStatus · весь файл проверен потоково · ${formatBytes(attempt.reportContext.reportBytes)} · передано релевантных частей: ${attempt.reportContext.includedChunks}/${attempt.reportContext.scannedChunks}", "$privacyStatus · the whole file was scanned locally · ${formatBytes(attempt.reportContext.reportBytes)} · relevant chunks supplied: ${attempt.reportContext.includedChunks}/${attempt.reportContext.scannedChunks}")
                }
            }.onFailure { failure ->
                messages = historyBefore
                question = prompt
                privacyConflict = failure is OpenRouterApiException &&
                    failure.reason == OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT
                error = failure.userMessage(language.text("Не удалось получить ответ", "Unable to get a response"))
            }
            busy = false
        }
    }

    LaunchedEffect(Unit) { refreshModels() }

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(horizontal = 16.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(onClick = onBack, enabled = !busy) { Text(language.text("Назад", "Back")) }
                Column(Modifier.weight(1f).padding(start = 12.dp)) {
                    Text(language.text("AI-чат по полному отчёту", "Full-report AI chat"), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                    Text(language.text("OpenRouter · бесплатные модели", "OpenRouter · free models"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
            }

            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item {
                    ReportSourceCard(
                        language = language,
                        report = report,
                        currentAvailable = initialCurrent != null,
                        busy = busy,
                        onUseCurrent = {
                            report = initialCurrent
                            messages = emptyList()
                            allowTrainingProviders = false
                            privacyConflict = false
                        },
                        onPick = { reportPicker.launch(arrayOf("application/json", "application/zip", "application/octet-stream")) },
                    )
                }
                item {
                    OpenRouterConfigurationCard(
                        language = language,
                        keyDraft = keyDraft,
                        keySaved = keySaved,
                        onKeyChanged = { keyDraft = it.take(512) },
                        onSaveKey = {
                            val result = runCatching { secretStore.saveKey(keyDraft) }
                            result.onSuccess {
                                keyDraft = ""
                                keySaved = true
                                error = null
                                status = language.text("API-ключ сохранён в защищённом хранилище Android", "API key saved in Android secure storage")
                            }.onFailure { error = it.userMessage(language.text("Не удалось сохранить ключ", "Unable to save key")) }
                        },
                        onClearKey = {
                            secretStore.clearKey()
                            keySaved = false
                            status = language.text("API-ключ удалён", "API key removed")
                        },
                        selectedModel = selectedModel,
                        refreshing = refreshingModels,
                        onSelectModel = { showModels = true },
                        onRefreshModels = ::refreshModels,
                    )
                }
                item {
                    OpenRouterPrivacyCard(
                        language = language,
                        allowTrainingProviders = allowTrainingProviders,
                        privacyConflict = privacyConflict,
                        busy = busy,
                        onAllowChanged = { allow ->
                            allowTrainingProviders = allow
                            privacyConflict = false
                            error = null
                        },
                        onSelectModel = { showModels = true },
                        onOpenPrivacySettings = {
                            runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(OPENROUTER_PRIVACY_URL)))
                            }.onFailure { error = it.userMessage(language.text("Не удалось открыть настройки OpenRouter", "Unable to open OpenRouter settings")) }
                        },
                    )
                }
                item {
                    Text(
                        language.text(
                            "При нажатии «Отправить» в OpenRouter передаются вопрос и выбранные фрагменты отчёта. APK и архив артефактов не отправляются.",
                            "Pressing Send transmits the question and selected report excerpts to OpenRouter. The APK and artifact archive are not uploaded.",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (error != null) {
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                            Text(error.orEmpty(), Modifier.fillMaxWidth().padding(12.dp), color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
                status?.let { message ->
                    item { Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary) }
                }
                if (messages.isEmpty()) {
                    item {
                        Text(
                            language.text(
                                "Загрузите полный отчёт или подписанный пакет и спросите, например: «Какие три риска важнее всего и как их закрыть?»",
                                "Load a full report or signed package and ask, for example: “Which three risks matter most and how should they be fixed?”",
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                items(messages) { message -> ChatMessageCard(language, message) }
                if (busy) {
                    item {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            CircularProgressIndicator()
                            Text(busyMessage)
                        }
                    }
                }
            }

            OutlinedTextField(
                value = question,
                onValueChange = { question = it.take(8_000) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(language.text("Вопрос по отчёту", "Question about the report")) },
                minLines = 2,
                maxLines = 5,
                enabled = !busy,
            )
            Button(
                onClick = ::send,
                enabled = !busy && report != null && keySaved && question.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text(language.text("Отправить модели", "Send to model")) }
        }
    }

    if (showModels) {
        ModelSelectionDialog(
            language = language,
            models = models,
            selected = selectedModel,
            onSelect = { model ->
                selectedModel = model
                secretStore.saveSelectedModelId(model.id)
                showModels = false
                messages = emptyList()
                allowTrainingProviders = false
                privacyConflict = false
                status = language.text("Выбрана модель: ${model.name}", "Selected model: ${model.name}")
            },
            onDismiss = { showModels = false },
        )
    }
}

@Composable
private fun OpenRouterPrivacyCard(
    language: AppLanguage,
    allowTrainingProviders: Boolean,
    privacyConflict: Boolean,
    busy: Boolean,
    onAllowChanged: (Boolean) -> Unit,
    onSelectModel: () -> Unit,
    onOpenPrivacySettings: () -> Unit,
) {
    val warning = allowTrainingProviders || privacyConflict
    OutlinedCard(
        Modifier.fillMaxWidth(),
        border = BorderStroke(
            1.dp,
            if (warning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline.copy(alpha = .5f),
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(language.text("Совместимость с бесплатными моделями", "Free-model compatibility"), fontWeight = FontWeight.SemiBold)
                    Text(
                        if (allowTrainingProviders) language.text("Разрешены провайдеры со сбором данных", "Providers with data collection are allowed")
                        else language.text("Строгий режим: сбор данных провайдером запрещён", "Strict mode: provider data collection is denied"),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (allowTrainingProviders) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
                    )
                }
                Switch(checked = allowTrainingProviders, onCheckedChange = onAllowChanged, enabled = !busy)
            }
            if (allowTrainingProviders) {
                Text(
                    language.text(
                        "Провайдер выбранной модели может хранить отправленные фрагменты отчёта и использовать их для обучения.",
                        "The selected model provider may retain submitted report excerpts and use them for training.",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (privacyConflict) {
                Text(
                    if (allowTrainingProviders) {
                        language.text("Совместимость включена, но политика аккаунта OpenRouter всё ещё блокирует эту модель.", "Compatibility is enabled, but the OpenRouter account policy still blocks this model.")
                    } else {
                        language.text("Выбранная модель и безопасный бесплатный автовыбор недоступны без сбора данных. Выберите другую модель или включите совместимость.", "The selected model and safe free auto-routing are unavailable without data collection. Select another model or enable compatibility.")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onSelectModel, enabled = !busy) { Text(language.text("Другая модель", "Another model")) }
                    TextButton(onClick = onOpenPrivacySettings, enabled = !busy) { Text(language.text("Настройки OpenRouter", "OpenRouter settings")) }
                }
            }
        }
    }
}

@Composable
private fun ReportSourceCard(
    language: AppLanguage,
    report: ImportedReport?,
    currentAvailable: Boolean,
    busy: Boolean,
    onUseCurrent: () -> Unit,
    onPick: () -> Unit,
) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(language.text("Полный отчёт", "Full report"), fontWeight = FontWeight.SemiBold)
            if (report == null) Text(language.text("Отчёт ещё не выбран", "No report selected"), color = MaterialTheme.colorScheme.onSurfaceVariant)
            else {
                Text(report.displayName, style = MaterialTheme.typography.bodyMedium)
                Text(formatBytes(report.sizeBytes), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (currentAvailable) TextButton(onClick = onUseCurrent, enabled = !busy) { Text(language.text("Текущий анализ", "Current analysis")) }
                TextButton(onClick = onPick, enabled = !busy) { Text(language.text("Выбрать JSON / ZIP", "Select JSON / ZIP")) }
            }
        }
    }
}

@Composable
private fun OpenRouterConfigurationCard(
    language: AppLanguage,
    keyDraft: String,
    keySaved: Boolean,
    onKeyChanged: (String) -> Unit,
    onSaveKey: () -> Unit,
    onClearKey: () -> Unit,
    selectedModel: OpenRouterModel,
    refreshing: Boolean,
    onSelectModel: () -> Unit,
    onRefreshModels: () -> Unit,
) {
    OutlinedCard(Modifier.fillMaxWidth(), border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .5f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("OpenRouter", fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                value = keyDraft,
                onValueChange = onKeyChanged,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(if (keySaved) language.text("Ключ сохранён · введите для замены", "Key saved · enter to replace") else language.text("API-ключ", "API key")) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onSaveKey, enabled = keyDraft.isNotBlank()) { Text(language.text("Сохранить ключ", "Save key")) }
                if (keySaved) TextButton(onClick = onClearKey) { Text(language.text("Удалить", "Delete")) }
            }
            HorizontalDivider()
            Text(language.text("Модель", "Model"), style = MaterialTheme.typography.labelMedium)
            OutlinedCard(Modifier.fillMaxWidth().clickable(onClick = onSelectModel)) {
                Column(Modifier.padding(12.dp)) {
                    Text(selectedModel.name, fontWeight = FontWeight.SemiBold)
                    Text(selectedModel.contextLabel, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            TextButton(onClick = onRefreshModels, enabled = !refreshing) {
                Text(if (refreshing) language.text("Загрузка моделей…", "Loading models…") else language.text("Обновить бесплатные модели", "Refresh free models"))
            }
        }
    }
}

@Composable
private fun ModelSelectionDialog(
    language: AppLanguage,
    models: List<OpenRouterModel>,
    selected: OpenRouterModel,
    onSelect: (OpenRouterModel) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(language.text("Бесплатная модель", "Free model")) },
        text = {
            LazyColumn(Modifier.fillMaxWidth().heightIn(max = 460.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(models) { model ->
                    OutlinedCard(
                        Modifier.fillMaxWidth().clickable { onSelect(model) },
                        border = BorderStroke(
                            if (model.id == selected.id) 2.dp else 1.dp,
                            if (model.id == selected.id) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                        ),
                    ) {
                        Column(Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(model.name, fontWeight = FontWeight.SemiBold)
                            Text(model.id, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
                            Text(model.contextLabel, style = MaterialTheme.typography.bodySmall)
                            if (model.description.isNotBlank()) {
                                Text(model.description.take(180), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(language.text("Закрыть", "Close")) } },
    )
}

@Composable
private fun ChatMessageCard(language: AppLanguage, message: OpenRouterChatMessage) {
    val assistant = message.role == "assistant"
    Card(
        modifier = Modifier.fillMaxWidth().padding(start = if (assistant) 0.dp else 28.dp, end = if (assistant) 28.dp else 0.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (assistant) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.primaryContainer,
        ),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(if (assistant) "AI · ${message.modelId.orEmpty()}" else language.text("Вы", "You"), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
            Text(message.text)
        }
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1024L * 1024L * 1024L -> String.format(Locale.ROOT, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    bytes >= 1024L * 1024L -> String.format(Locale.ROOT, "%.2f MB", bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
}

private fun Throwable.userMessage(prefix: String): String =
    "$prefix: ${message?.takeIf { it.isNotBlank() } ?: javaClass.simpleName}"

private data class ChatAttempt(
    val answer: org.unirevlab.security.ai.OpenRouterChatResult,
    val reportContext: org.unirevlab.security.ai.ReportContext,
    val strictFallbackUsed: Boolean,
)

private fun buildReportAndDumpContext(report: ImportedReport, query: String, modelContextLength: Int): org.unirevlab.security.ai.ReportContext {
    val dumpEvidence = report.dumpEvidenceFile?.takeIf { it.isFile && it.length() > 0 }
        ?: return ReportContextEngine.build(report.file, query, modelContextLength)
    val reportBudget = (modelContextLength * 3 / 4).coerceAtLeast(32_000)
    val dumpBudget = (modelContextLength / 4).coerceAtLeast(16_000)
    val primary = ReportContextEngine.build(report.file, query, reportBudget)
    val dump = ReportContextEngine.build(dumpEvidence, query, dumpBudget)
    return org.unirevlab.security.ai.ReportContext(
        text = buildString(primary.text.length + dump.text.length + 160) {
            appendLine(primary.text)
            appendLine("\n<confirmed-real-il2cpp-dump-evidence>")
            appendLine(dump.text)
            appendLine("</confirmed-real-il2cpp-dump-evidence>")
        },
        reportBytes = primary.reportBytes + dump.reportBytes,
        scannedChunks = primary.scannedChunks + dump.scannedChunks,
        includedChunks = primary.includedChunks + dump.includedChunks,
        completeFileIncluded = primary.completeFileIncluded && dump.completeFileIncluded,
    )
}

private const val OPENROUTER_PRIVACY_URL = "https://openrouter.ai/settings/privacy"
