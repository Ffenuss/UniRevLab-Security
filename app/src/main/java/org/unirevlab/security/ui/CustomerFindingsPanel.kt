package org.unirevlab.security.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.analysis.FindingsWorkspaceModel
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun CustomerFindingsPanel(
    report: StaticAnalysisReport,
    onOpenPatchLab: () -> Unit,
) {
    val summary = remember(report.artifact.sha256, report.findings.size) {
        FindingsWorkspaceModel.summarize(report.findings)
    }
    var queryText by remember(report.artifact.sha256) { mutableStateOf("") }
    var severity by remember(report.artifact.sha256) { mutableStateOf<Severity?>(null) }
    var category by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }
    var manualOnly by remember(report.artifact.sha256) { mutableStateOf(false) }

    val filtered = remember(report.artifact.sha256, queryText, severity, category, manualOnly) {
        FindingsWorkspaceModel.filter(
            report.findings,
            FindingsWorkspaceModel.Query(
                text = queryText,
                severities = severity?.let(::setOf) ?: Severity.entries.toSet(),
                category = category,
                manualReviewOnly = manualOnly,
            ),
        )
    }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(15.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Security Findings", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Приоритизированный список результатов полного аудита: что обнаружено, почему это важно, чем подтверждается и что рекомендуется исправить.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Всего ${summary.total} · Critical ${summary.critical} · High ${summary.high} · Medium ${summary.medium} · Low ${summary.low} · Info ${summary.informational}",
                fontWeight = FontWeight.SemiBold,
            )
            if (summary.manualReview > 0) {
                Text("Ручная проверка требуется: ${summary.manualReview}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    OutlinedTextField(
        value = queryText,
        onValueChange = { queryText = it.take(200) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        label = { Text("Поиск: finding / компонент / API / evidence / CWE…") },
    )

    Text("Severity", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(selected = severity == null, onClick = { severity = null }, label = { Text("Все") })
        Severity.entries.forEach { item ->
            FilterChip(
                selected = severity == item,
                onClick = { severity = if (severity == item) null else item },
                label = { Text(severityLabel(item)) },
            )
        }
        FilterChip(
            selected = manualOnly,
            onClick = { manualOnly = !manualOnly },
            label = { Text("Только manual review") },
        )
    }

    if (summary.categories.isNotEmpty()) {
        Text("Категория", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(selected = category == null, onClick = { category = null }, label = { Text("Все") })
            summary.categories.forEach { item ->
                FilterChip(
                    selected = category == item,
                    onClick = { category = if (category == item) null else item },
                    label = { Text(item) },
                )
            }
        }
    }

    Text(
        "Показано: ${filtered.size} из ${summary.total}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    if (filtered.isEmpty()) {
        Card(shape = RoundedCornerShape(16.dp)) {
            Text(
                if (report.findings.isEmpty()) {
                    "Текущие правила не сформировали findings. Это не является доказательством отсутствия уязвимостей — смотрите также Protection Matrix и coverage полного аудита."
                } else {
                    "По выбранным фильтрам результатов нет."
                },
                modifier = Modifier.padding(14.dp),
            )
        }
        return
    }

    filtered.forEach { finding ->
        CustomerFindingCard(finding, onOpenPatchLab)
    }
}

@Composable
private fun CustomerFindingCard(
    finding: Finding,
    onOpenPatchLab: () -> Unit,
) {
    Card(shape = RoundedCornerShape(18.dp)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(finding.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text("${finding.id} · ${finding.category}", style = MaterialTheme.typography.bodySmall)
                }
                Text(
                    severityLabel(finding.severity),
                    fontWeight = FontWeight.Bold,
                    color = findingSeverityColor(finding.severity),
                )
            }

            Text("Confidence: ${finding.confidence}", style = MaterialTheme.typography.labelMedium)
            Text(finding.description, style = MaterialTheme.typography.bodyMedium)

            if (finding.evidence.isNotEmpty()) {
                Text("Evidence", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                finding.evidence.take(6).forEach { evidence ->
                    Text(
                        "• ${evidence.source} · ${evidence.location}\n  ${evidence.value}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (finding.evidence.size > 6) {
                    Text("… ещё ${finding.evidence.size - 6} evidence items", style = MaterialTheme.typography.bodySmall)
                }
            }

            Text("Remediation", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(finding.remediation, style = MaterialTheme.typography.bodySmall)

            if (finding.references.isNotEmpty()) {
                Text(
                    "References: ${finding.references.joinToString(" · ") { "${it.standard} ${it.id}" }}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (finding.requiresManualReview) {
                Text(
                    "MANUAL REVIEW · автоматического доказательства недостаточно",
                    color = MaterialTheme.colorScheme.tertiary,
                    fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Button(onClick = onOpenPatchLab, modifier = Modifier.fillMaxWidth()) {
                Text("Открыть Patch / Hook Lab")
            }
        }
    }
}

@Composable
private fun findingSeverityColor(severity: Severity) = when (severity) {
    Severity.CRITICAL, Severity.HIGH -> MaterialTheme.colorScheme.error
    Severity.MEDIUM -> MaterialTheme.colorScheme.tertiary
    Severity.LOW -> MaterialTheme.colorScheme.primary
    Severity.INFORMATIONAL -> MaterialTheme.colorScheme.onSurfaceVariant
}

private fun severityLabel(severity: Severity): String = when (severity) {
    Severity.CRITICAL -> "CRITICAL"
    Severity.HIGH -> "HIGH"
    Severity.MEDIUM -> "MEDIUM"
    Severity.LOW -> "LOW"
    Severity.INFORMATIONAL -> "INFO"
}
