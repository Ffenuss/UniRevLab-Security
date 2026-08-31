package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.EasyAuditEngine
import org.unirevlab.security.analysis.FlagSweepEngine
import org.unirevlab.security.analysis.PatchLabEngine
import org.unirevlab.security.analysis.TamperAssessmentEngine
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun EasyAuditPanel(
    report: StaticAnalysisReport,
    workspace: PatchLabEngine.Workspace,
    busy: Boolean,
    onApplyHook: (TamperAssessmentEngine.HookProposal) -> Unit,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var customFlags by remember { mutableStateOf("") }
    var result by remember(report.artifact.sha256, workspace.root.absolutePath) {
        mutableStateOf<EasyAuditEngine.EasyAuditReport?>(null)
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("Easy Audit — проверка в один запуск", fontWeight = FontWeight.Bold)
            Text(
                "Проверяет те поверхности, которые обычно становятся целью массового моддинга: ad-free, billing/entitlement, premium/VIP, API trust, HP/валюта/state, feature flags и integrity. Вместо автоматического обхода показывает доказательства и защитные меры.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = customFlags,
                onValueChange = { customFlags = it.take(800) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Дополнительные флаги, если нужны") },
                supportingText = { Text("Через запятую/пробел/новую строку. Например: privateTier, internalFeature, myFlag") },
            )
            Button(
                onClick = {
                    scope.launch {
                        running = true
                        onError(null)
                        onStatus("Easy Audit: индексируем tamper surfaces и все APK-entry…")
                        val flags = customFlags.split(Regex("[,;\\s]+"))
                            .map { it.trim() }
                            .filter { it.length >= 2 }
                        val run = runCatching {
                            withContext(Dispatchers.IO) { EasyAuditEngine.run(report, workspace, flags) }
                        }
                        result = run.getOrNull()
                        run.onSuccess {
                            onStatus("Easy Audit завершён: score ${it.score}/100, flag matches ${it.flagSweep.matches.size}")
                        }.onFailure { onError(it.message) }
                        running = false
                    }
                },
                enabled = !busy && !running,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (result == null) "Запустить Easy Audit + Flag Sweep" else "Повторить Easy Audit") }
            if (running) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Сканируем имена всех файлов и ограниченное содержимое каждого APK-entry…", style = MaterialTheme.typography.bodySmall)
            }

            result?.let { audit ->
                Text("Easy Audit score: ${audit.score}/100 (${audit.band})", fontWeight = FontWeight.SemiBold)
                Text(
                    "Flag Sweep: ${audit.flagSweep.matches.size} совпадений; entries ${audit.flagSweep.entriesVisited}; content scanned ${formatBytes(audit.flagSweep.contentBytesScanned)}" +
                        if (audit.flagSweep.budgetTruncated || audit.flagSweep.contentEntriesTruncated > 0) " · bounded scan" else "",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (audit.flagSweep.customTerms.isNotEmpty()) {
                    Text("Custom flags: ${audit.flagSweep.customTerms.joinToString()}", style = MaterialTheme.typography.bodySmall)
                }

                Text("Автоматические проверки", fontWeight = FontWeight.SemiBold)
                audit.checks.forEach { check ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.72f))) {
                        Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("${check.severity} · ${check.title}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                            Text("Статус: ${check.status}", style = MaterialTheme.typography.bodySmall)
                            Text(check.explanation, style = MaterialTheme.typography.bodySmall)
                            check.evidence.take(6).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                            if (check.status != "NO_SURFACE_FOUND") {
                                Text("Как закрыть:", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                check.actions.take(4).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                            }
                        }
                    }
                }

                if (audit.flagSweep.matches.isNotEmpty()) {
                    Text("Flag Sweep — найденные маркеры", fontWeight = FontWeight.SemiBold)
                    val categoryCounts = audit.flagSweep.categoryCounts.entries.sortedByDescending { it.value }
                    Text(categoryCounts.joinToString(" · ") { "${it.key}:${it.value}" }, style = MaterialTheme.typography.bodySmall)
                    audit.flagSweep.matches.take(60).forEach { match ->
                        FlagMatchRow(match)
                    }
                    if (audit.flagSweep.matches.size > 60) {
                        Text("Показаны первые 60 из ${audit.flagSweep.matches.size}; полный поиск можно сузить пользовательским флагом или ручным поиском ниже.", style = MaterialTheme.typography.bodySmall)
                    }
                }

                if (audit.traceHooks.isNotEmpty()) {
                    Text("Безопасные trace hooks для подтверждения поведения", fontWeight = FontWeight.SemiBold)
                    Text("Эти hooks только фиксируют вход в найденный метод; они не эмулируют покупку и не отключают проверку.", style = MaterialTheme.typography.bodySmall)
                    audit.traceHooks.take(10).forEach { proposal ->
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("${proposal.classDescriptor}->${proposal.methodName}${proposal.prototype}", style = MaterialTheme.typography.bodySmall)
                            Text(proposal.reason, style = MaterialTheme.typography.bodySmall)
                            OutlinedButton(
                                onClick = { onApplyHook(proposal) },
                                enabled = !busy && !running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Применить trace hook") }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FlagMatchRow(match: FlagSweepEngine.FlagMatch) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))) {
        Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(match.category, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                Text("flag=${match.term}", style = MaterialTheme.typography.bodySmall)
            }
            Text(match.entryName, style = MaterialTheme.typography.bodySmall)
            Text("${match.source}${match.offset?.let { " @ $it" }.orEmpty()}: ${match.preview}", style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun formatBytes(value: Long): String = when {
    value >= 1024L * 1024L -> "%.1f MiB".format(LocaleHolder.ROOT, value / (1024.0 * 1024.0))
    value >= 1024L -> "%.1f KiB".format(LocaleHolder.ROOT, value / 1024.0)
    else -> "$value B"
}

private object LocaleHolder {
    val ROOT: java.util.Locale = java.util.Locale.ROOT
}
