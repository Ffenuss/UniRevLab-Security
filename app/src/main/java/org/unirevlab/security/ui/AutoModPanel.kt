package org.unirevlab.security.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.AutoModEngine
import org.unirevlab.security.analysis.PatchLabEngine
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun AutoModPanel(
    report: StaticAnalysisReport,
    workspace: PatchLabEngine.Workspace,
    busy: Boolean,
    onAnalyzeBuilt: (File) -> Unit,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val plan by produceState<AutoModEngine.Plan?>(null, report.artifact.sha256, workspace.root.absolutePath) {
        value = withContext(Dispatchers.IO) { AutoModEngine.plan(report, workspace) }
    }
    var rightsConfirmed by remember(workspace.artifactSha256) { mutableStateOf(false) }
    var autoBusy by remember(workspace.artifactSha256) { mutableStateOf(false) }
    var built by remember(workspace.artifactSha256) { mutableStateOf<PatchLabEngine.BuildResult?>(null) }

    val exportPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
    ) { uri ->
        val file = built?.signedApk
        if (uri != null && file != null) {
            scope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть файл назначения" }
                            file.inputStream().buffered(128 * 1024).use { input ->
                                input.copyTo(output, 128 * 1024)
                            }
                            output.flush()
                        }
                    }
                }
                result.onSuccess { onStatus("AutoMod APK экспортирован.") }
                    .onFailure { onError(it.message) }
            }
        }
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.22f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("AutoMod Demo — наглядное доказательство", fontWeight = FontWeight.Bold)
            Text(
                "После отдельного подтверждения прав AutoMod меняет только высокосигнальные методы кода самого приложения: " +
                    "локальные premium/access/feature/integrity boolean-gates и часть int-getter'ов локального state. " +
                    "Максимум 4 точечных изменения. Исходный APK не меняется, подпись оригинала не сохраняется, store/billing не эмулируется.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Привязка: SHA-256 ${workspace.artifactSha256}",
                style = MaterialTheme.typography.bodySmall,
            )

            if (plan == null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Формируем безопасный AutoMod-план…", style = MaterialTheme.typography.bodySmall)
            } else {
                val current = requireNotNull(plan)
                Text(
                    "Основа плана: calibrated score ${current.assessmentScore}/100 (${current.assessmentBand}); " +
                        "подходящих целей до лимита: ${current.eligibleBeforeCap}; выбрано: ${current.actions.size}.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (current.actions.isEmpty()) {
                    Text(
                        "Высокоуверенных app-owned целей для автоматической модификации не найдено. " +
                            "Это не означает отсутствия риска — используйте ручной Patch Lab/trace.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else {
                    current.actions.forEach { action ->
                        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.72f))) {
                            Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(
                                    "${action.category} · confidence ${action.confidence}",
                                    fontWeight = FontWeight.SemiBold,
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Text(action.target, style = MaterialTheme.typography.bodySmall)
                                Text(
                                    when (action.mode) {
                                        AutoModEngine.Mode.RETURN_TRUE -> "Патч: return true"
                                        AutoModEngine.Mode.RETURN_FALSE -> "Патч: return false"
                                        AutoModEngine.Mode.RETURN_INT -> "Патч: return ${action.intValue}"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Text(action.reason, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }

                val workspaceClean = workspace.modifiedDexEntries.isEmpty() && workspace.replacements.isEmpty()
                if (!workspaceClean && built == null) {
                    Text(
                        "AutoMod требует чистый workspace, чтобы доказательство и diff не смешивались с ручными изменениями. " +
                            "Нажмите «Подготовить Patch Lab workspace» заново.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Checkbox(
                        checked = rightsConfirmed,
                        onCheckedChange = { rightsConfirmed = it },
                        enabled = !busy && !autoBusy && built == null,
                    )
                    Text(
                        "Подтверждаю право/разрешение правообладателя на модификацию именно этого APK для демонстрационного теста.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                }

                Button(
                    onClick = {
                        scope.launch {
                            autoBusy = true
                            built = null
                            onError(null)
                            onStatus("AutoMod: применяем проверенный план → Smali → DEX → APK → тестовая подпись…")
                            val result = runCatching {
                                withContext(Dispatchers.IO) {
                                    AutoModEngine.apply(workspace, current, rightsConfirmed)
                                    PatchLabEngine.build(workspace)
                                }
                            }
                            result.getOrNull()?.let {
                                built = it
                                onStatus("AutoMod Demo готов: ${current.actions.size} точечных изменений, APK собран и подписан тестовым ключом.")
                            }
                            result.exceptionOrNull()?.let { onError(it.message) }
                            autoBusy = false
                        }
                    },
                    enabled = rightsConfirmed && current.actions.isNotEmpty() && workspaceClean && !busy && !autoBusy && built == null,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Применить AutoMod и собрать тестовый APK")
                }
            }

            if (autoBusy) LinearProgressIndicator(Modifier.fillMaxWidth())

            built?.let { result ->
                Text("AutoMod тестовая сборка готова", fontWeight = FontWeight.Bold)
                Text("SHA-256: ${result.sha256}", style = MaterialTheme.typography.bodySmall)
                Text("Изменено: ${result.changedEntries.joinToString()}", style = MaterialTheme.typography.bodySmall)
                PatchBuildAuditPanel(report = report, workspace = workspace, result = result)
                OutlinedButton(
                    onClick = {
                        val base = report.artifact.displayName.substringBeforeLast('.')
                            .replace(Regex("[^A-Za-z0-9._-]"), "_")
                            .take(64)
                        exportPicker.launch("${base}-unirevlab-automod.apk")
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Экспортировать AutoMod APK") }
                OutlinedButton(
                    onClick = {
                        runCatching {
                            val uri = FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                result.signedApk,
                            )
                            val intent = Intent(Intent.ACTION_VIEW)
                                .setDataAndType(uri, "application/vnd.android.package-archive")
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        }.onFailure { onError(it.message) }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Установить AutoMod тестовую сборку") }
                Button(
                    onClick = { onAnalyzeBuilt(result.signedApk) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Повторно проанализировать AutoMod APK") }
            }
        }
    }
}
