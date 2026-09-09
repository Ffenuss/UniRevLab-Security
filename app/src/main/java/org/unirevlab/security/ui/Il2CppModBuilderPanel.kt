package org.unirevlab.security.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.analysis.Il2CppEvidenceExplorerModel
import org.unirevlab.security.analysis.Il2CppModBuilderEngine
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun Il2CppModBuilderPanel(
    report: StaticAnalysisReport,
    busy: Boolean,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val context = LocalContext.current
    val result = remember(report) { Il2CppEvidenceExplorerModel.build(report, maxRows = 10_000) }
    val planResult = remember(report, result) {
        runCatching { Il2CppModBuilderEngine.plan(report.artifact.sha256, result) }
    }
    val plan = planResult.getOrNull()
    var query by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf(emptySet<String>()) }
    var pendingManifest by remember { mutableStateOf<String?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val data = pendingManifest
        if (uri != null && data != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri, "wt").use { output ->
                    requireNotNull(output) { "Не удалось открыть файл проекта" }
                    output.write(data.toByteArray(Charsets.UTF_8))
                }
            }.onSuccess {
                onError(null); onStatus("Проект мода сохранён. Он привязан к SHA-256 анализируемого APK.")
            }.onFailure { onError(it.message) }
        }
        pendingManifest = null
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("IL2CPP Mod Builder", fontWeight = FontWeight.SemiBold)
        Text(
            "В проект попадают только методы VERIFIED/SUPPORTED с выровненным RVA. Методы без адреса остаются диагностическими.",
            style = MaterialTheme.typography.bodySmall,
        )
        planResult.exceptionOrNull()?.let { Text("Недоступно: ${it.message}", color = MaterialTheme.colorScheme.error) }
        plan?.let { value ->
            Text(value.diagnostics.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(120) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Точный поиск: hp, health, damage…") },
                supportingText = { Text("Короткие запросы ищутся как целые слова, а не как часть SmoothPath.") },
            )
            val visible = remember(value.actions, query) { Il2CppModBuilderEngine.filter(value.actions, query).take(250) }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.fillMaxWidth().padding(6.dp)) {
                    visible.forEach { action ->
                        val enabled = action.availability == Il2CppModBuilderEngine.Availability.BUILDABLE
                        Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                            Checkbox(
                                checked = action.id in selected,
                                onCheckedChange = { checked ->
                                    if (enabled) selected = if (checked) selected + action.id else selected - action.id
                                },
                                enabled = enabled && !busy,
                            )
                            Column(Modifier.weight(1f)) {
                                Text(action.title)
                                Text(action.managedIdentity, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                                Text(action.diagnostic, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
            Button(
                onClick = {
                    runCatching { Il2CppModBuilderEngine.exportManifest(value, selected) }
                        .onSuccess { manifest ->
                            pendingManifest = manifest
                            saver.launch("unirevlab-il2cpp-mod-plan.json")
                        }
                        .onFailure { onError(it.message) }
                },
                enabled = selected.isNotEmpty() && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Сохранить проект мода (${selected.size})") }
        }
    }
}
