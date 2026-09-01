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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
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
import org.unirevlab.security.analysis.SecretExposureEngine

@Composable
fun SecretExposurePanel(
    workspace: PatchLabEngine.Workspace,
    busy: Boolean,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var running by remember(workspace.artifactSha256) { mutableStateOf(false) }
    var proof by remember(workspace.artifactSha256) { mutableStateOf<SecretExposureEngine.ExposureReport?>(null) }
    var authorizationChecked by remember(workspace.artifactSha256) { mutableStateOf(false) }
    var revealUnlocked by remember(workspace.artifactSha256) { mutableStateOf(false) }
    var revealed by remember(workspace.artifactSha256) { mutableStateOf<Map<String, SecretExposureEngine.RevealResult>>(emptyMap()) }
    var selectedTextEntry by remember(workspace.artifactSha256) { mutableStateOf<String?>(null) }
    var originalText by remember(workspace.artifactSha256) { mutableStateOf("") }
    var textValue by remember(workspace.artifactSha256) { mutableStateOf("") }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.18f))) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Secret Exposure Proof", fontWeight = FontWeight.Bold)
            Text(
                "Повторно проверяет исходный APK по байтам: DEX, .so, assets/config и остальные ZIP-entry. Отличает простой marker от подтверждённого material, проверяет обратимые Base64/hex/URL-кодировки и PEM/DER структуру.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Обычный отчёт остаётся redacted. Полные значения хранятся только во временном in-memory vault этого Patch Lab и не пишутся в status/log.",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = {
                    scope.launch {
                        running = true
                        revealUnlocked = false
                        revealed = emptyMap()
                        onError(null)
                        onStatus("Secret Exposure Proof: сканируем содержимое APK…")
                        val result = runCatching { withContext(Dispatchers.IO) { SecretExposureEngine.scan(workspace) } }
                        proof = result.getOrNull()
                        result.onSuccess {
                            onStatus("Secret Exposure Proof завершён: подтверждённых/проверяемых кандидатов ${it.hits.size}")
                        }.onFailure { onError(it.message) }
                        running = false
                    }
                },
                enabled = !busy && !running,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (proof == null) "Запустить Secret Exposure Proof" else "Повторить Secret Exposure Proof") }
            if (running) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Потоково сканируем APK без распаковки всего артефакта в RAM…", style = MaterialTheme.typography.bodySmall)
            }

            proof?.let { report ->
                Text(
                    "Entries: ${report.entriesScanned} · scanned ${formatSecretBytes(report.bytesScanned)} · findings ${report.hits.size}${if (report.truncated) " · bounded" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (report.hits.isEmpty()) {
                    Text("Подтверждённых secret exposure по поддерживаемым форматам не найдено.", style = MaterialTheme.typography.bodySmall)
                } else {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.72f))) {
                        Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("Локальное подтверждение полномочий", fontWeight = FontWeight.SemiBold)
                            Text(
                                "После подтверждения полный просмотр доступен для текущей открытой цели. До подтверждения отображаются proof metadata и fingerprints.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                Checkbox(
                                    checked = authorizationChecked,
                                    onCheckedChange = {
                                        authorizationChecked = it
                                        if (!it) {
                                            revealUnlocked = false
                                            revealed = emptyMap()
                                        }
                                    },
                                    enabled = !busy && !running,
                                )
                                Text(
                                    "Подтверждаю право на полный аудит именно этого APK и соответствие согласованной цели.",
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.weight(1f),
                                )
                            }
                            Button(
                                onClick = {
                                    revealUnlocked = true
                                    onStatus("Полный Secret Proof локально разблокирован для текущей цели")
                                },
                                enabled = authorizationChecked && !busy && !running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(if (revealUnlocked) "✓ Полный просмотр разблокирован" else "Разблокировать полный просмотр") }
                        }
                    }

                    report.hits.take(80).forEach { hit ->
                        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.46f))) {
                            Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("${hit.confidence} · ${hit.kind} · ${hit.exposure}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                Text("${hit.entryName} @ ${hit.offset}", style = MaterialTheme.typography.bodySmall)
                                Text("Storage: ${hit.storage} · ${hit.redactedPreview}", style = MaterialTheme.typography.bodySmall)
                                Text("SHA-256: ${hit.valueSha256}", style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                                hit.recoveredSha256?.let {
                                    Text("Recovered SHA-256: $it", style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                                }
                                if (hit.recoverySteps.isNotEmpty()) {
                                    hit.recoverySteps.forEach { step -> Text("✓ $step", style = MaterialTheme.typography.bodySmall) }
                                }
                                if (hit.roundTripVerified) Text("✓ Обратимость подтверждена round-trip проверкой", style = MaterialTheme.typography.bodySmall)
                                if (hit.structurallyValid) Text("✓ Структура материала подтверждена", style = MaterialTheme.typography.bodySmall)

                                if (revealUnlocked) {
                                    val currentReveal = revealed[hit.id]
                                    if (currentReveal == null) {
                                        OutlinedButton(
                                            onClick = {
                                                val value = runCatching {
                                                    SecretExposureEngine.reveal(hit.id, workspace.artifactSha256, authorizationConfirmed = true)
                                                }
                                                value.onSuccess { reveal -> revealed = revealed + (hit.id to reveal) }
                                                    .onFailure { onError(it.message) }
                                            },
                                            enabled = !busy && !running,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) { Text("Показать значение полностью") }
                                    } else {
                                        OutlinedTextField(
                                            value = currentReveal.rawValue,
                                            onValueChange = {},
                                            readOnly = true,
                                            modifier = Modifier.fillMaxWidth().heightIn(min = 110.dp, max = 360.dp),
                                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                            label = { Text("Полное значение из APK") },
                                        )
                                        currentReveal.recoveredValue?.takeIf { it != currentReveal.rawValue }?.let { recovered ->
                                            OutlinedTextField(
                                                value = recovered,
                                                onValueChange = {},
                                                readOnly = true,
                                                modifier = Modifier.fillMaxWidth().heightIn(min = 110.dp, max = 360.dp),
                                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                                label = { Text("Полностью восстановленное значение") },
                                            )
                                        }
                                        OutlinedButton(
                                            onClick = { revealed = revealed - hit.id },
                                            modifier = Modifier.fillMaxWidth(),
                                        ) { Text("Скрыть полное значение") }
                                    }
                                }

                                if (hit.editableTextEntry && revealUnlocked) {
                                    OutlinedButton(
                                        onClick = {
                                            scope.launch {
                                                onError(null)
                                                val loaded = runCatching {
                                                    withContext(Dispatchers.IO) { PatchLabEngine.loadArchiveText(workspace, hit.entryName) }
                                                }
                                                loaded.getOrNull()?.let {
                                                    selectedTextEntry = hit.entryName
                                                    originalText = it
                                                    textValue = it
                                                    onStatus("Secret source открыт в текстовом редакторе: ${hit.entryName}")
                                                }
                                                loaded.exceptionOrNull()?.let { onError(it.message) }
                                            }
                                        },
                                        enabled = !busy && !running,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) { Text("Открыть source entry в редакторе") }
                                }

                                Text("Как исправить:", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                hit.remediation.forEach { action -> Text("• $action", style = MaterialTheme.typography.bodySmall) }
                            }
                        }
                    }
                    if (report.hits.size > 80) {
                        Text("Показаны первые 80 из ${report.hits.size}; fingerprints всех найденных значений остаются в proof result.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            selectedTextEntry?.let { entry ->
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.35f))) {
                    Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Secret source editor: $entry", fontWeight = FontWeight.SemiBold)
                        Text("Изменение сохраняется только в Patch Lab workspace и затем попадёт в отдельную тестовую сборку.", style = MaterialTheme.typography.bodySmall)
                        OutlinedTextField(
                            value = textValue,
                            onValueChange = { textValue = it },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 260.dp),
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            label = { Text("Содержимое entry") },
                        )
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { textValue = originalText },
                                enabled = textValue != originalText && !busy,
                                modifier = Modifier.weight(1f),
                            ) { Text("Откатить") }
                            Button(
                                onClick = {
                                    scope.launch {
                                        val saved = runCatching {
                                            withContext(Dispatchers.IO) { PatchLabEngine.saveArchiveText(workspace, entry, textValue) }
                                        }
                                        saved.onSuccess {
                                            originalText = textValue
                                            onStatus("Secret source patch сохранён: $entry")
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
    }
}

private fun formatSecretBytes(value: Long): String = when {
    value >= 1024L * 1024L * 1024L -> "%.2f GiB".format(java.util.Locale.ROOT, value / (1024.0 * 1024.0 * 1024.0))
    value >= 1024L * 1024L -> "%.1f MiB".format(java.util.Locale.ROOT, value / (1024.0 * 1024.0))
    value >= 1024L -> "%.1f KiB".format(java.util.Locale.ROOT, value / 1024.0)
    else -> "$value B"
}
