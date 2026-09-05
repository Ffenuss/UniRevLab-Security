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
import androidx.compose.material3.Checkbox
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
    currentReport: File?,
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
            ImportedReport(it, currentReportLabel?.takeIf(String::isNotBlank) ?: it.name, it.length())
        }
    }
    var report by remember(currentReport) { mutableStateOf(initialCurrent ?: importStore.current()) }
    var models by remember { mutableStateOf(listOf(OpenRouterModelCatalog.defaultModel())) }
    var selectedModel by remember { mutableStateOf(OpenRouterModelCatalog.defaultModel()) }
    var keyDraft by remember { mutableStateOf("") }
    var keySaved by remember { mutableStateOf(secretStore.hasKey()) }
    var consent by remember { mutableStateOf(false) }
    var allowTrainingProviders by remember { mutableStateOf(false) }
    var trainingConsent by remember { mutableStateOf(false) }
    var privacyConflict by remember { mutableStateOf(false) }
    var messages by remember { mutableStateOf<List<OpenRouterChatMessage>>(emptyList()) }
    var question by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var refreshingModels by remember { mutableStateOf(false) }
    var showModels by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun refreshModels() {
        if (refreshingModels) return
        scope.launch {
            refreshingModels = true
            error = null
            val result = runCatching { withContext(Dispatchers.IO) { client.fetchFreeModels() } }
            result.onSuccess { loaded ->
                models = loaded
                val savedId = secretStore.selectedModelId()
                selectedModel = loaded.firstOrNull { it.id == savedId }
                    ?: loaded.firstOrNull { it.id == selectedModel.id }
                    ?: OpenRouterModelCatalog.defaultModel()
                status = "Загружено бесплатных моделей: ${loaded.size}"
            }.onFailure { failure ->
                error = failure.userMessage("Не удалось загрузить список моделей")
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
                    consent = false
                    allowTrainingProviders = false
                    trainingConsent = false
                    privacyConflict = false
                    status = "Полный отчёт загружен: ${formatBytes(imported.sizeBytes)}"
                }.onFailure { failure -> error = failure.userMessage("Не удалось импортировать отчёт") }
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
                withContext(Dispatchers.IO) {
                    val key = requireNotNull(secretStore.loadKey()) { "Сначала сохраните API-ключ OpenRouter" }
                    val policy = if (allowTrainingProviders) {
                        OpenRouterDataPolicy.FREE_MODEL_COMPATIBLE
                    } else {
                        OpenRouterDataPolicy.STRICT
                    }
                    val primaryContext = ReportContextEngine.build(selectedReport.file, prompt, selectedModel.contextLength)
                    try {
                        ChatAttempt(
                            answer = client.complete(key, selectedModel, primaryContext, historyBefore, prompt, policy),
                            reportContext = primaryContext,
                            strictFallbackUsed = false,
                        )
                    } catch (failure: OpenRouterApiException) {
                        val canUseStrictFallback = policy == OpenRouterDataPolicy.STRICT &&
                            failure.reason == OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT &&
                            selectedModel.id != OpenRouterModelCatalog.defaultModel().id
                        if (!canUseStrictFallback) throw failure
                        val fallback = OpenRouterModelCatalog.defaultModel()
                        val fallbackContext = ReportContextEngine.build(selectedReport.file, prompt, fallback.contextLength)
                        ChatAttempt(
                            answer = client.complete(key, fallback, fallbackContext, historyBefore, prompt, policy),
                            reportContext = fallbackContext,
                            strictFallbackUsed = true,
                        )
                    }
                }
            }
            result.onSuccess { attempt ->
                messages = messages + OpenRouterChatMessage("assistant", attempt.answer.text, attempt.answer.modelId)
                val privacyStatus = if (allowTrainingProviders) {
                    "Режим совместимости"
                } else if (attempt.strictFallbackUsed) {
                    "Строгий режим · выбранная модель недоступна, безопасно использована ${attempt.answer.modelId}"
                } else {
                    "Строгий режим"
                }
                status = if (attempt.reportContext.completeFileIncluded) {
                    "$privacyStatus · модель получила весь файл целиком · ${formatBytes(attempt.reportContext.reportBytes)}"
                } else {
                    "$privacyStatus · весь файл проверен потоково · ${formatBytes(attempt.reportContext.reportBytes)} · передано релевантных частей: ${attempt.reportContext.includedChunks}/${attempt.reportContext.scannedChunks}"
                }
            }.onFailure { failure ->
                messages = historyBefore
                question = prompt
                privacyConflict = failure is OpenRouterApiException &&
                    failure.reason == OpenRouterFailureReason.DATA_POLICY_NO_ENDPOINT
                error = failure.userMessage("Не удалось получить ответ")
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
                OutlinedButton(onClick = onBack, enabled = !busy) { Text("Назад") }
                Column(Modifier.weight(1f).padding(start = 12.dp)) {
                    Text("AI-чат по полному отчёту", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                    Text("OpenRouter · бесплатные модели", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
            }

            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item {
                    ReportSourceCard(
                        report = report,
                        currentAvailable = initialCurrent != null,
                        busy = busy,
                        onUseCurrent = {
                            report = initialCurrent
                            messages = emptyList()
                            consent = false
                            allowTrainingProviders = false
                            trainingConsent = false
                            privacyConflict = false
                        },
                        onPick = { reportPicker.launch(arrayOf("application/json", "application/zip", "application/octet-stream")) },
                    )
                }
                item {
                    OpenRouterConfigurationCard(
                        keyDraft = keyDraft,
                        keySaved = keySaved,
                        onKeyChanged = { keyDraft = it.take(512) },
                        onSaveKey = {
                            val result = runCatching { secretStore.saveKey(keyDraft) }
                            result.onSuccess {
                                keyDraft = ""
                                keySaved = true
                                error = null
                                status = "API-ключ сохранён в защищённом хранилище Android"
                            }.onFailure { error = it.userMessage("Не удалось сохранить ключ") }
                        },
                        onClearKey = {
                            secretStore.clearKey()
                            keySaved = false
                            status = "API-ключ удалён"
                        },
                        selectedModel = selectedModel,
                        refreshing = refreshingModels,
                        onSelectModel = { showModels = true },
                        onRefreshModels = ::refreshModels,
                    )
                }
                item {
                    OpenRouterPrivacyCard(
                        allowTrainingProviders = allowTrainingProviders,
                        trainingConsent = trainingConsent,
                        privacyConflict = privacyConflict,
                        busy = busy,
                        onAllowChanged = { allow ->
                            allowTrainingProviders = allow
                            trainingConsent = false
                            privacyConflict = false
                            error = null
                        },
                        onTrainingConsentChanged = { trainingConsent = it },
                        onSelectModel = { showModels = true },
                        onOpenPrivacySettings = {
                            runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(OPENROUTER_PRIVACY_URL)))
                            }.onFailure { error = it.userMessage("Не удалось открыть настройки OpenRouter") }
                        },
                    )
                }
                item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                        Checkbox(checked = consent, onCheckedChange = { consent = it }, enabled = !busy)
                        Text(
                            "Разрешаю передавать OpenRouter вопрос и выбранные исходные фрагменты полного отчёта. Сам APK и analysis-artifacts.zip не отправляются.",
                            modifier = Modifier.padding(top = 10.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
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
                            "Загрузите full-report.json или подписанный evidence-пакет и спросите, например: «Какие три риска важнее всего и как их закрыть?»",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                items(messages) { message -> ChatMessageCard(message) }
                if (busy) {
                    item {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            CircularProgressIndicator()
                            Text("Просматриваю полный отчёт и жду ответ модели…")
                        }
                    }
                }
            }

            OutlinedTextField(
                value = question,
                onValueChange = { question = it.take(8_000) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Вопрос по отчёту") },
                minLines = 2,
                maxLines = 5,
                enabled = !busy,
            )
            Button(
                onClick = ::send,
                enabled = !busy && report != null && keySaved && consent && question.isNotBlank() &&
                    (!allowTrainingProviders || trainingConsent),
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Отправить модели") }
        }
    }

    if (showModels) {
        ModelSelectionDialog(
            models = models,
            selected = selectedModel,
            onSelect = { model ->
                selectedModel = model
                secretStore.saveSelectedModelId(model.id)
                showModels = false
                messages = emptyList()
                allowTrainingProviders = false
                trainingConsent = false
                privacyConflict = false
                status = "Выбрана модель: ${model.name}"
            },
            onDismiss = { showModels = false },
        )
    }
}

@Composable
private fun OpenRouterPrivacyCard(
    allowTrainingProviders: Boolean,
    trainingConsent: Boolean,
    privacyConflict: Boolean,
    busy: Boolean,
    onAllowChanged: (Boolean) -> Unit,
    onTrainingConsentChanged: (Boolean) -> Unit,
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
                    Text("Совместимость с бесплатными моделями", fontWeight = FontWeight.SemiBold)
                    Text(
                        if (allowTrainingProviders) "Разрешены провайдеры со сбором данных"
                        else "Строгий режим: сбор данных провайдером запрещён",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (allowTrainingProviders) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
                    )
                }
                Switch(checked = allowTrainingProviders, onCheckedChange = onAllowChanged, enabled = !busy)
            }
            if (allowTrainingProviders) {
                Text(
                    "Провайдер выбранной модели может хранить отправленные фрагменты отчёта и использовать их для обучения. Включайте это только с разрешения заказчика.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                    Checkbox(
                        checked = trainingConsent,
                        onCheckedChange = onTrainingConsentChanged,
                        enabled = !busy,
                    )
                    Text(
                        "Подтверждаю разрешение заказчика на такую передачу данных.",
                        modifier = Modifier.padding(top = 10.dp),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            if (privacyConflict) {
                Text(
                    if (allowTrainingProviders) {
                        "Разрешение в приложении включено, но политика аккаунта OpenRouter всё ещё блокирует эту модель."
                    } else {
                        "Выбранная модель и безопасный бесплатный автовыбор недоступны без сбора данных. Выберите другую модель или явно включите совместимость."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onSelectModel, enabled = !busy) { Text("Другая модель") }
                    TextButton(onClick = onOpenPrivacySettings, enabled = !busy) { Text("Настройки OpenRouter") }
                }
            }
        }
    }
}

@Composable
private fun ReportSourceCard(
    report: ImportedReport?,
    currentAvailable: Boolean,
    busy: Boolean,
    onUseCurrent: () -> Unit,
    onPick: () -> Unit,
) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Полный отчёт", fontWeight = FontWeight.SemiBold)
            if (report == null) Text("Отчёт ещё не выбран", color = MaterialTheme.colorScheme.onSurfaceVariant)
            else {
                Text(report.displayName, style = MaterialTheme.typography.bodyMedium)
                Text(formatBytes(report.sizeBytes), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (currentAvailable) TextButton(onClick = onUseCurrent, enabled = !busy) { Text("Текущий анализ") }
                TextButton(onClick = onPick, enabled = !busy) { Text("Выбрать JSON / ZIP") }
            }
        }
    }
}

@Composable
private fun OpenRouterConfigurationCard(
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
                label = { Text(if (keySaved) "Ключ сохранён · введите для замены" else "API-ключ") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onSaveKey, enabled = keyDraft.isNotBlank()) { Text("Сохранить ключ") }
                if (keySaved) TextButton(onClick = onClearKey) { Text("Удалить") }
            }
            HorizontalDivider()
            Text("Модель", style = MaterialTheme.typography.labelMedium)
            OutlinedCard(Modifier.fillMaxWidth().clickable(onClick = onSelectModel)) {
                Column(Modifier.padding(12.dp)) {
                    Text(selectedModel.name, fontWeight = FontWeight.SemiBold)
                    Text(selectedModel.contextLabel, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            TextButton(onClick = onRefreshModels, enabled = !refreshing) {
                Text(if (refreshing) "Загрузка моделей…" else "Обновить бесплатные модели")
            }
        }
    }
}

@Composable
private fun ModelSelectionDialog(
    models: List<OpenRouterModel>,
    selected: OpenRouterModel,
    onSelect: (OpenRouterModel) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Бесплатная модель") },
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
        confirmButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
    )
}

@Composable
private fun ChatMessageCard(message: OpenRouterChatMessage) {
    val assistant = message.role == "assistant"
    Card(
        modifier = Modifier.fillMaxWidth().padding(start = if (assistant) 0.dp else 28.dp, end = if (assistant) 28.dp else 0.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (assistant) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.primaryContainer,
        ),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(if (assistant) "AI · ${message.modelId.orEmpty()}" else "Вы", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
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

private const val OPENROUTER_PRIVACY_URL = "https://openrouter.ai/settings/privacy"
