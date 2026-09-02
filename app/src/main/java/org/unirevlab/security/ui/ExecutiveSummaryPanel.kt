package org.unirevlab.security.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.ExecutiveSummaryEngine
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun ExecutiveSummaryPanel(report: StaticAnalysisReport) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var exportStatus by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }

    val summary by produceState<ExecutiveSummaryEngine.Summary?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.findings.size,
    ) {
        value = withContext(Dispatchers.Default) { ExecutiveSummaryEngine.summarize(report) }
    }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/markdown")) { uri ->
        val current = summary
        if (uri != null && current != null) {
            scope.launch {
                runCatching {
                    val markdown = withContext(Dispatchers.Default) { ExecutiveSummaryEngine.toMarkdown(report, current) }
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt")?.bufferedWriter()?.use { writer ->
                            writer.write(markdown)
                        } ?: error("Не удалось открыть файл для записи")
                    }
                }.onSuccess {
                    exportStatus = "Executive Summary сохранён."
                }.onFailure {
                    exportStatus = "Ошибка экспорта: ${it.message ?: it.javaClass.simpleName}"
                }
            }
        }
    }

    when (val current = summary) {
        null -> SummaryCard("Готовим Executive Summary…", "Сводим findings, coverage, protection, attack surface и deobfuscation.")
        else -> {
            Card(
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            ) {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Executive Summary", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text(
                        "Риск: ${riskLabel(current.riskBand)}",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = riskColor(current.riskBand),
                    )
                    Text(
                        "Findings ${current.totalFindings} · Critical ${current.critical} · High ${current.high} · Medium ${current.medium} · Low ${current.low}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text("Полнота анализа: ${current.coverageLabel}", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Риск и полнота показываются отдельно: отсутствие findings при неполном анализе не трактуется как безопасность.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = { exportLauncher.launch("UniRevLab-Executive-Summary-${report.artifact.sha256.take(8)}.md") },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Сохранить Executive Summary") }
                }
            }

            Text("Attack surface", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SummaryMetric("Exported", current.exportedComponents.toString(), Modifier.weight(1f))
                SummaryMetric("Dangerous perms", current.dangerousPermissions.toString(), Modifier.weight(1f))
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SummaryMetric("Deep links", current.deepLinks.toString(), Modifier.weight(1f))
                SummaryMetric("Providers", current.providers.toString(), Modifier.weight(1f))
            }
            SummaryCard(
                "Cleartext traffic",
                when (current.cleartextTraffic) {
                    true -> "Разрешён manifest policy — проверить домены и trust boundary."
                    false -> "Запрещён на уровне manifest policy."
                    null -> "Не определено."
                },
            )

            Text("Protection & resilience", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            SummaryCard(
                "Матрица защит",
                "Обнаружено ${current.protectionPresent} · не обнаружено ${current.protectionNotDetected} · неизвестно ${current.protectionUnknown}",
            )
            SummaryCard(
                "Обфускация",
                current.obfuscationScore?.let {
                    "$it/100 · ${if (current.likelyObfuscated == true) "обфускация вероятна; analyst mapping доступен" else "сильная обфускация не подтверждена"}"
                } ?: "DEX-профиль недоступен.",
            )
            SummaryCard(
                "Serialization / deserialization",
                "Поверхностей ${current.deserializationSurfaces} · high-risk ${current.highRiskDeserialization} · достижимы из exported graph ${current.externallyReachableDeserialization}",
            )

            Text("Analysis coverage", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            current.coverageChecks.forEach { check ->
                Card(shape = RoundedCornerShape(16.dp)) {
                    Column(Modifier.fillMaxWidth().padding(13.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(check.title, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                            Text(check.state.name, fontWeight = FontWeight.Bold, color = coverageColor(check.state))
                        }
                        Text(check.detail, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            Text("Priority findings", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            if (current.topFindings.isEmpty()) {
                SummaryCard(
                    "Rule-based findings отсутствуют",
                    "Это не доказательство отсутствия уязвимостей. Оцените coverage, Protection Matrix и ручные trust-boundary проверки.",
                )
            } else {
                current.topFindings.forEach { finding ->
                    Card(shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("${finding.severity} · ${finding.title}", fontWeight = FontWeight.Bold, color = findingColor(finding.severity))
                            Text(finding.description, style = MaterialTheme.typography.bodySmall)
                            Text("Что исправить", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                            Text(finding.remediation, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (current.recommendations.isNotEmpty()) {
                Text("Next actions", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Card(shape = RoundedCornerShape(18.dp)) {
                    Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        current.recommendations.forEachIndexed { index, recommendation ->
                            Text("${index + 1}. $recommendation", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            exportStatus?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                "Scope: Executive Summary агрегирует результаты статического анализа. Он не является сертификатом безопасности и не утверждает runtime-эксплуатируемость без отдельной валидации.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SummaryMetric(title: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(13.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(title, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SummaryCard(title: String, detail: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun riskLabel(risk: ExecutiveSummaryEngine.RiskBand): String = when (risk) {
    ExecutiveSummaryEngine.RiskBand.CRITICAL -> "CRITICAL"
    ExecutiveSummaryEngine.RiskBand.HIGH -> "HIGH"
    ExecutiveSummaryEngine.RiskBand.MEDIUM -> "MEDIUM"
    ExecutiveSummaryEngine.RiskBand.LOW -> "LOW"
    ExecutiveSummaryEngine.RiskBand.INFORMATIONAL -> "INFORMATIONAL"
    ExecutiveSummaryEngine.RiskBand.NO_FINDINGS -> "NO RULE-BASED FINDINGS"
}

@Composable
private fun riskColor(risk: ExecutiveSummaryEngine.RiskBand) = when (risk) {
    ExecutiveSummaryEngine.RiskBand.CRITICAL, ExecutiveSummaryEngine.RiskBand.HIGH -> MaterialTheme.colorScheme.error
    ExecutiveSummaryEngine.RiskBand.MEDIUM -> MaterialTheme.colorScheme.tertiary
    ExecutiveSummaryEngine.RiskBand.LOW -> MaterialTheme.colorScheme.primary
    ExecutiveSummaryEngine.RiskBand.INFORMATIONAL, ExecutiveSummaryEngine.RiskBand.NO_FINDINGS -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
private fun coverageColor(state: ExecutiveSummaryEngine.CoverageState) = when (state) {
    ExecutiveSummaryEngine.CoverageState.COMPLETE -> MaterialTheme.colorScheme.primary
    ExecutiveSummaryEngine.CoverageState.PARTIAL -> MaterialTheme.colorScheme.tertiary
    ExecutiveSummaryEngine.CoverageState.MISSING -> MaterialTheme.colorScheme.error
    ExecutiveSummaryEngine.CoverageState.NOT_APPLICABLE -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
private fun findingColor(severity: Severity) = when (severity) {
    Severity.CRITICAL, Severity.HIGH -> MaterialTheme.colorScheme.error
    Severity.MEDIUM -> MaterialTheme.colorScheme.tertiary
    Severity.LOW -> MaterialTheme.colorScheme.primary
    Severity.INFORMATIONAL -> MaterialTheme.colorScheme.onSurfaceVariant
}
