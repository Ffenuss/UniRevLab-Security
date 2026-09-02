package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.DiagnosticsEngine
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun DiagnosticsPanel(report: StaticAnalysisReport) {
    val diagnostics by produceState<DiagnosticsEngine.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.findings.size,
    ) {
        value = withContext(Dispatchers.Default) { DiagnosticsEngine.run(report) }
    }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Diagnostics / Self-Test", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Проверяет согласованность уже собранных индексов, call graph, deobfuscation/mapping, findings, native и coverage. Целевое приложение при этом не запускается.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val result = diagnostics) {
                null -> Text("Запускаем внутренние проверки…", fontWeight = FontWeight.SemiBold)
                else -> {
                    Text(
                        if (result.healthy) "Analyzer state: HEALTHY" else "Analyzer state: CHECK FAILED",
                        fontWeight = FontWeight.Bold,
                        color = if (result.healthy) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    )
                    Text("PASS ${result.passed} · WARN ${result.warnings} · FAIL ${result.failed}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    diagnostics?.checks?.forEach { check ->
        Card(shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(check.title, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                    Text(
                        check.status.name,
                        fontWeight = FontWeight.Bold,
                        color = when (check.status) {
                            DiagnosticsEngine.Status.PASS -> MaterialTheme.colorScheme.primary
                            DiagnosticsEngine.Status.WARN -> MaterialTheme.colorScheme.tertiary
                            DiagnosticsEngine.Status.FAIL -> MaterialTheme.colorScheme.error
                        },
                    )
                }
                Text(check.id, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(check.detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
