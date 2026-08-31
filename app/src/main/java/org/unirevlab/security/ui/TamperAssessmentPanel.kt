package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.PatchLabEngine
import org.unirevlab.security.analysis.TamperAssessmentEngine
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun TamperAssessmentPanel(
    report: StaticAnalysisReport,
    workspace: PatchLabEngine.Workspace,
    busy: Boolean,
    onOpenTarget: (TamperAssessmentEngine.SearchResult) -> Unit,
    onApplyHook: (TamperAssessmentEngine.HookProposal) -> Unit,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val assessment by produceState<TamperAssessmentEngine.Assessment?>(null, report.artifact.sha256, workspace.root.absolutePath) {
        value = withContext(Dispatchers.IO) { TamperAssessmentEngine.scan(report, workspace) }
    }
    var query by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<TamperAssessmentEngine.SearchResult>>(emptyList()) }
    var searching by remember { mutableStateOf(false) }
    var selectedTextEntry by remember { mutableStateOf<String?>(null) }
    var originalText by remember { mutableStateOf("") }
    var textValue by remember { mutableStateOf("") }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.38f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("Tamper Assessment — автоматический поиск поверхностей", fontWeight = FontWeight.Bold)
            Text(
                "Ищет client-side trust/state/config, значения и файлы. Предварительные secret candidates можно перепроверить через Secret Exposure Proof; авто-hooks только наблюдают выполнение.",
                style = MaterialTheme.typography.bodySmall,
            )
            EasyAuditPanel(
                report = report,
                workspace = workspace,
                busy = busy,
                onApplyHook = onApplyHook,
                onStatus = onStatus,
                onError = onError,
            )
            if (assessment == null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Индексируем DEX/native/assets для Patch Lab…", style = MaterialTheme.typography.bodySmall)
            } else {
                val a = requireNotNull(assessment)
                Text("Tamper surface score: ${a.score}/100 (${a.band})", fontWeight = FontWeight.SemiBold)
                Text("Поверхностей: ${a.hits.size}; secret/key candidates: ${a.secrets.size}; trace hooks: ${a.hookProposals.size}${if (a.truncated) "; индекс ограничен" else ""}", style = MaterialTheme.typography.bodySmall)
                a.categories.take(8).forEach { category ->
                    Text("• ${category.category}: ${category.count}, max=${category.maxScore}", style = MaterialTheme.typography.bodySmall)
                }
                Text("Наиболее значимые точки", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                a.hits.take(16).forEach { hit ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.72f))) {
                        Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("${hit.category} · ${hit.kind} · score ${hit.score}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                            Text(hit.location, style = MaterialTheme.typography.bodySmall)
                            Text(hit.preview, style = MaterialTheme.typography.bodySmall)
                            if (hit.dexEntry != null && hit.classDescriptor != null) {
                                OutlinedButton(
                                    onClick = {
                                        onOpenTarget(
                                            TamperAssessmentEngine.SearchResult(
                                                hit.kind, hit.location, hit.preview, hit.dexEntry, hit.classDescriptor, hit.methodName, hit.prototype, hit.archiveEntry,
                                            ),
                                        )
                                    },
                                    enabled = !busy,
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text("Открыть цель в редакторе") }
                            }
                        }
                    }
                }
                if (a.secrets.isNotEmpty()) {
                    Text("Предварительные ключи / секреты (redacted candidates)", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                    Text("Private signing key корректно собранного APK извлечь из сертификата нельзя; здесь ищутся ошибочно встроенные application secrets/key material.", style = MaterialTheme.typography.bodySmall)
                    a.secrets.take(16).forEach { secret ->
                        Text("• ${secret.kind} · ${secret.location} · ${secret.redactedPreview} · sha=${secret.sha256.take(12)}…", style = MaterialTheme.typography.bodySmall)
                    }
                }
                SecretExposurePanel(
                    workspace = workspace,
                    busy = busy,
                    onStatus = onStatus,
                    onError = onError,
                )
                if (a.hookProposals.isNotEmpty()) {
                    Text("Автоматический генератор trace hooks", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                    a.hookProposals.take(12).forEach { proposal ->
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("${proposal.classDescriptor}->${proposal.methodName}${proposal.prototype}", style = MaterialTheme.typography.bodySmall)
                            Text(proposal.reason, style = MaterialTheme.typography.bodySmall)
                            Button(onClick = { onApplyHook(proposal) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                                Text("Сгенерировать + применить trace hook")
                            }
                        }
                    }
                }
            }

            Text("Ручной поиск по всему артефакту", fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(220) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Значение, класс, метод, файл, symbol…") },
                supportingText = { Text("Фильтры: file:, text:, method:, class:, field:, string:, const:, native:, secret:, type:") },
            )
            Button(
                onClick = {
                    scope.launch {
                        searching = true
                        onError(null)
                        val result = runCatching { withContext(Dispatchers.IO) { TamperAssessmentEngine.search(report, workspace, query) } }
                        results = result.getOrDefault(emptyList())
                        result.exceptionOrNull()?.let { onError(it.message) }
                        if (result.isSuccess) onStatus("Поиск: найдено ${results.size}")
                        searching = false
                    }
                },
                enabled = query.trim().length >= 2 && !busy && !searching,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Искать значения и файлы") }
            if (searching) LinearProgressIndicator(Modifier.fillMaxWidth())
            results.take(40).forEach { item ->
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))) {
                    Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("${item.kind}: ${item.location}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                        Text(item.preview, style = MaterialTheme.typography.bodySmall)
                        if (item.dexEntry != null && item.classDescriptor != null) {
                            OutlinedButton(onClick = { onOpenTarget(item) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Открыть DEX/класс/метод") }
                        }
                        item.archiveEntry?.let { entry ->
                            OutlinedButton(
                                onClick = {
                                    scope.launch {
                                        onError(null)
                                        val loaded = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.loadArchiveText(workspace, entry) } }
                                        loaded.getOrNull()?.let {
                                            selectedTextEntry = entry
                                            originalText = it
                                            textValue = it
                                            onStatus("Открыт текстовый entry: $entry")
                                        }
                                        loaded.exceptionOrNull()?.let { onError(it.message) }
                                    }
                                },
                                enabled = !busy,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Открыть файл как текст") }
                        }
                    }
                }
            }

            selectedTextEntry?.let { entry ->
                Text("Текстовый редактор: $entry", fontWeight = FontWeight.SemiBold)
                OutlinedTextField(
                    value = textValue,
                    onValueChange = { textValue = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 260.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    label = { Text("Содержимое entry") },
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { textValue = originalText }, enabled = textValue != originalText && !busy, modifier = Modifier.weight(1f)) { Text("Откатить") }
                    Button(
                        onClick = {
                            scope.launch {
                                val saved = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.saveArchiveText(workspace, entry, textValue) } }
                                saved.onSuccess {
                                    originalText = textValue
                                    onStatus("Текстовый патч сохранён: $entry")
                                    onError(null)
                                }.onFailure { onError(it.message) }
                            }
                        },
                        enabled = textValue != originalText && !busy,
                        modifier = Modifier.weight(1f),
                    ) { Text("Сохранить") }
                }
            }
        }
    }
}

@Composable
fun PatchBuildAuditPanel(
    report: StaticAnalysisReport,
    workspace: PatchLabEngine.Workspace,
    result: PatchLabEngine.BuildResult,
) {
    val assessment by produceState<TamperAssessmentEngine.Assessment?>(null, report.artifact.sha256, result.sha256) {
        value = withContext(Dispatchers.IO) { TamperAssessmentEngine.scan(report, workspace) }
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.36f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Сверка оригинала и модифицированного APK", fontWeight = FontWeight.Bold)
            Text("Content changes: ${result.apkDiff.contentChanges}; signature metadata: ${result.apkDiff.signatureMetadataChanges}; unexpected: ${result.apkDiff.unexpectedContentChanges.size}", style = MaterialTheme.typography.bodySmall)
            result.apkDiff.entries.take(32).forEach { diff ->
                val label = when { diff.signatureMetadata -> "SIGNATURE"; diff.expectedLabChange -> "LAB"; else -> "UNEXPECTED" }
                Text("• [$label] ${diff.change} ${diff.entryName} (${diff.beforeSize ?: 0} → ${diff.afterSize ?: 0})", style = MaterialTheme.typography.bodySmall)
            }
            if (result.codeDiffs.isNotEmpty()) {
                Text("Точный diff изменённого кода/текста", fontWeight = FontWeight.SemiBold)
                result.codeDiffs.forEach { diff ->
                    Text("${diff.kind}: ${diff.target}  -${diff.removedLines}/+${diff.addedLines}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                    Text(diff.preview.ifBlank { "(без текстового diff)" }, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                }
            }
            assessment?.let { a ->
                val advice = remember(a, result.sha256) { TamperAssessmentEngine.hardeningAdvice(report, a, result.apkDiff, result.codeDiffs) }
                if (advice.isNotEmpty()) {
                    Text("Что исправить заказчику", fontWeight = FontWeight.Bold)
                    advice.forEach { item ->
                        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.68f))) {
                            Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text("${item.priority}: ${item.title}", fontWeight = FontWeight.SemiBold)
                                Text(item.evidence, style = MaterialTheme.typography.bodySmall)
                                item.actions.forEach { action -> Text("• $action", style = MaterialTheme.typography.bodySmall) }
                            }
                        }
                    }
                }
            }
        }
    }
}
