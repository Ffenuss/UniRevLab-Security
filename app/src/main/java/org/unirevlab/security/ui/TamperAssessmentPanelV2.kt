package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.PatchLabEngine
import org.unirevlab.security.analysis.TamperAssessmentEngine
import org.unirevlab.security.model.StaticAnalysisReport

private enum class AssessmentList { SURFACES, SECRETS, HOOKS }

@Composable
fun TamperAssessmentPanelV2(
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
    var showSearchResults by remember { mutableStateOf(false) }
    var assessmentList by remember { mutableStateOf<AssessmentList?>(null) }
    var selectedTextEntry by remember { mutableStateOf<String?>(null) }
    var originalText by remember { mutableStateOf("") }
    var textValue by remember { mutableStateOf("") }

    fun openTextEntry(entry: String) {
        scope.launch {
            onError(null)
            val loaded = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.loadArchiveText(workspace, entry) } }
            loaded.getOrNull()?.let {
                selectedTextEntry = entry
                originalText = it
                textValue = it
                showSearchResults = false
                onStatus("Открыт текстовый entry: $entry")
            }
            loaded.exceptionOrNull()?.let { onError(it.message) }
        }
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.30f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("Tamper Assessment", fontWeight = FontWeight.Bold)
            Text(
                "Главный экран показывает только сводку. Длинные списки открываются отдельно и виртуализируются.",
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

            val a = assessment
            if (a == null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Индексируем DEX/native/assets…", style = MaterialTheme.typography.bodySmall)
            } else {
                Text("Calibrated tamper score: ${a.score}/100 (${a.band})", fontWeight = FontWeight.SemiBold)
                Text(
                    "Поверхностей: ${a.hits.size} · secret/key candidates: ${a.secrets.size} · trace hooks: ${a.hookProposals.size}${if (a.truncated) " · assessment index ограничен" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                )
                a.categories.forEach { category ->
                    Text("• ${category.category}: ${category.count}, max=${category.maxScore}", style = MaterialTheme.typography.bodySmall)
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    OutlinedButton(onClick = { assessmentList = AssessmentList.SURFACES }, modifier = Modifier.weight(1f)) { Text("Поверхности (${a.hits.size})") }
                    OutlinedButton(onClick = { assessmentList = AssessmentList.SECRETS }, modifier = Modifier.weight(1f)) { Text("Секреты (${a.secrets.size})") }
                }
                OutlinedButton(
                    onClick = { assessmentList = AssessmentList.HOOKS },
                    enabled = a.hookProposals.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Trace hooks (${a.hookProposals.size})") }
            }

            SecretExposurePanel(
                workspace = workspace,
                busy = busy,
                onStatus = onStatus,
                onError = onError,
            )

            HorizontalDivider()
            Text("Ручной поиск по артефакту", fontWeight = FontWeight.SemiBold)
            Text(
                "По умолчанию поиск scoped: код приложения/project-owned и релевантные assets. raw: включает SDK/framework/native-шум. Результаты по количеству не обрезаются.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(220) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Значение, класс, метод, файл, symbol…") },
                supportingText = { Text("file:, text:, method:, class:, field:, string:, const:, native:, secret:, type:, raw:") },
            )
            Button(
                onClick = {
                    scope.launch {
                        searching = true
                        onError(null)
                        val result = runCatching { withContext(Dispatchers.IO) { TamperAssessmentEngine.search(report, workspace, query) } }
                        results = result.getOrDefault(emptyList())
                        result.exceptionOrNull()?.let { onError(it.message) }
                        if (result.isSuccess) {
                            onStatus("Поиск: найдено ${results.size}")
                            showSearchResults = true
                        }
                        searching = false
                    }
                },
                enabled = query.trim().length >= 2 && !busy && !searching,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Искать") }
            if (searching) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (results.isNotEmpty()) {
                OutlinedButton(onClick = { showSearchResults = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Открыть все результаты (${results.size})")
                }
            }

            selectedTextEntry?.let { entry ->
                HorizontalDivider()
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

    val a = assessment
    val list = assessmentList
    if (a != null && list != null) {
        Dialog(onDismissRequest = { assessmentList = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxSize().padding(10.dp), tonalElevation = 3.dp) {
                Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            when (list) {
                                AssessmentList.SURFACES -> "Все поверхности (${a.hits.size})"
                                AssessmentList.SECRETS -> "Все secret candidates (${a.secrets.size})"
                                AssessmentList.HOOKS -> "Все trace hooks (${a.hookProposals.size})"
                            },
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedButton(onClick = { assessmentList = null }) { Text("Закрыть") }
                    }
                    LazyColumn(Modifier.weight(1f).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        when (list) {
                            AssessmentList.SURFACES -> items(a.hits, key = { "${it.kind}|${it.location}|${it.category}" }) { hit ->
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f))) {
                                    Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Text("${hit.category} · ${hit.kind} · score ${hit.score}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                        Text(hit.location, style = MaterialTheme.typography.bodySmall)
                                        Text(hit.preview, style = MaterialTheme.typography.bodySmall)
                                        if (hit.dexEntry != null && hit.classDescriptor != null) {
                                            OutlinedButton(
                                                onClick = {
                                                    assessmentList = null
                                                    onOpenTarget(TamperAssessmentEngine.SearchResult(hit.kind, hit.location, hit.preview, hit.dexEntry, hit.classDescriptor, hit.methodName, hit.prototype, hit.archiveEntry))
                                                },
                                                enabled = !busy,
                                                modifier = Modifier.fillMaxWidth(),
                                            ) { Text("Открыть цель") }
                                        }
                                    }
                                }
                            }
                            AssessmentList.SECRETS -> items(a.secrets, key = { it.sha256 }) { secret ->
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f))) {
                                    Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Text(secret.kind, fontWeight = FontWeight.SemiBold)
                                        Text(secret.location, style = MaterialTheme.typography.bodySmall)
                                        Text(secret.redactedPreview, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                                        Text("sha=${secret.sha256}", style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                                    }
                                }
                            }
                            AssessmentList.HOOKS -> items(a.hookProposals, key = { it.id }) { proposal ->
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f))) {
                                    Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Text("${proposal.classDescriptor}->${proposal.methodName}${proposal.prototype}", style = MaterialTheme.typography.bodySmall)
                                        Text(proposal.reason, style = MaterialTheme.typography.bodySmall)
                                        Button(
                                            onClick = { assessmentList = null; onApplyHook(proposal) },
                                            enabled = !busy,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) { Text("Сгенерировать + применить trace hook") }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (showSearchResults) {
        Dialog(onDismissRequest = { showSearchResults = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxSize().padding(10.dp), tonalElevation = 3.dp) {
                Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Результаты поиска (${results.size})", fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        OutlinedButton(onClick = { showSearchResults = false }) { Text("Закрыть") }
                    }
                    Text("Показаны все найденные элементы; LazyColumn не создаёт карточки вне экрана.", style = MaterialTheme.typography.bodySmall)
                    LazyColumn(Modifier.weight(1f).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        items(results, key = { "${it.kind}|${it.location}|${it.preview}" }) { item ->
                            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.40f))) {
                                Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    Text("${item.kind}: ${item.location}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                    Text(item.preview, style = MaterialTheme.typography.bodySmall)
                                    if (item.dexEntry != null && item.classDescriptor != null) {
                                        OutlinedButton(
                                            onClick = { showSearchResults = false; onOpenTarget(item) },
                                            enabled = !busy,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) { Text("Открыть DEX/класс/метод") }
                                    }
                                    item.archiveEntry?.let { entry ->
                                        OutlinedButton(onClick = { openTextEntry(entry) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                                            Text("Открыть файл как текст")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
