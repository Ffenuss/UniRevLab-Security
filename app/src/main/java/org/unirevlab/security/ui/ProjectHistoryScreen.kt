package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.unirevlab.security.model.AssessmentHistoryEntry
import org.unirevlab.security.model.BaselineComparison
import org.unirevlab.security.model.BaselineVerdict
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun ProjectHistoryScreen(
    entries: List<AssessmentHistoryEntry>,
    baselineEntryIds: Set<String>,
    currentReport: StaticAnalysisReport?,
    currentComparison: BaselineComparison?,
    onBack: () -> Unit,
    onSetBaseline: (String) -> Unit,
    onClearBaseline: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("← Инструменты") }
            Text("Проекты / История / Baseline", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                "Каждый завершённый аудит сохраняет локальную мета-запись. Вы можете явно назначить проверенную сборку trusted baseline для package name и затем видеть, совпадает ли новый APK с ней по SHA-256 и цепочке подписания.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (currentReport != null) {
                CurrentBaselineCard(currentReport, currentComparison)
            }

            HorizontalDivider()
            Text("История анализов", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            if (entries.isEmpty()) {
                Card(shape = RoundedCornerShape(18.dp)) {
                    Text(
                        "История пока пуста. Первая запись появится после завершения полного аудита.",
                        modifier = Modifier.padding(14.dp),
                    )
                }
            } else {
                entries.forEach { entry ->
                    val isBaseline = entry.id in baselineEntryIds
                    HistoryEntryCard(
                        entry = entry,
                        isBaseline = isBaseline,
                        onSetBaseline = { onSetBaseline(entry.id) },
                        onClearBaseline = { entry.packageName?.let(onClearBaseline) },
                        onDelete = { onDelete(entry.id) },
                    )
                }
            }
        }
    }
}

@Composable
private fun CurrentBaselineCard(report: StaticAnalysisReport, comparison: BaselineComparison?) {
    val packageName = report.manifest?.packageName ?: report.artifact.sourcePackageName ?: "package не определён"
    val verdict = comparison?.verdict ?: BaselineVerdict.NO_BASELINE
    val container = when (verdict) {
        BaselineVerdict.SAME_ARTIFACT -> MaterialTheme.colorScheme.primaryContainer
        BaselineVerdict.MODIFIED -> MaterialTheme.colorScheme.tertiaryContainer
        BaselineVerdict.SIGNER_CHANGED -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = container)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("Trusted Baseline Compare", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(packageName, fontWeight = FontWeight.SemiBold)
            Text(baselineVerdictTitle(verdict), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text(baselineVerdictDetail(comparison), style = MaterialTheme.typography.bodySmall)
            comparison?.baseline?.let { baseline ->
                Text("Baseline: ${baseline.artifactDisplayName}", style = MaterialTheme.typography.bodySmall)
                Text("SHA-256 ${baseline.artifactSha256.take(20)}…", style = MaterialTheme.typography.bodySmall)
                comparison.signerContinuity?.let { sameSigner ->
                    Text("Signer continuity: ${if (sameSigner) "совпадает" else "НЕ совпадает"}", style = MaterialTheme.typography.bodySmall)
                }
                comparison.sizeDeltaBytes?.let { delta ->
                    Text("Δ size: ${if (delta >= 0) "+" else ""}$delta bytes", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun HistoryEntryCard(
    entry: AssessmentHistoryEntry,
    isBaseline: Boolean,
    onSetBaseline: () -> Unit,
    onClearBaseline: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isBaseline) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(entry.projectName.ifBlank { "Без названия проекта" }, modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold)
                if (isBaseline) Text("TRUSTED BASELINE", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
            }
            Text(entry.artifactDisplayName, fontWeight = FontWeight.SemiBold)
            Text(entry.packageName ?: "package не определён", style = MaterialTheme.typography.bodySmall)
            Text(
                "${formatHistoryTime(entry.analyzedAtEpochMs)} · version ${entry.versionName ?: "?"} (${entry.versionCode ?: "?"}) · ${entry.sourceKind}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Findings ${entry.findingCount} · C ${entry.criticalCount} · H ${entry.highCount} · M ${entry.mediumCount}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("SHA-256 ${entry.artifactSha256.take(24)}…", style = MaterialTheme.typography.bodySmall)
            Text(
                "DEX ${entry.dexFiles ?: 0} · methods ${entry.methodsIndexed ?: 0} · native ${entry.nativeLibraries ?: 0} · engine ${entry.engineVersion}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (isBaseline) {
                    Button(onClick = onClearBaseline, enabled = entry.packageName != null, modifier = Modifier.weight(1f)) { Text("Снять baseline") }
                } else {
                    Button(onClick = onSetBaseline, enabled = !entry.packageName.isNullOrBlank(), modifier = Modifier.weight(1f)) { Text("Сделать baseline") }
                }
                OutlinedButton(onClick = onDelete, modifier = Modifier.weight(1f)) { Text("Удалить") }
            }
        }
    }
}

private fun baselineVerdictTitle(verdict: BaselineVerdict): String = when (verdict) {
    BaselineVerdict.NO_BASELINE -> "Baseline не выбран"
    BaselineVerdict.SAME_ARTIFACT -> "APK совпадает с trusted baseline"
    BaselineVerdict.MODIFIED -> "APK отличается от trusted baseline"
    BaselineVerdict.SIGNER_CHANGED -> "APK отличается и signer изменён"
    BaselineVerdict.NOT_COMPARABLE -> "Baseline относится к другому package"
    BaselineVerdict.INCOMPLETE_IDENTITY -> "Недостаточно данных для сравнения"
}

private fun baselineVerdictDetail(comparison: BaselineComparison?): String = when (comparison?.verdict ?: BaselineVerdict.NO_BASELINE) {
    BaselineVerdict.NO_BASELINE -> "Назначьте проверенную историческую сборку baseline. Без этого UniRevLab не должен утверждать, что APK изменён относительно оригинала."
    BaselineVerdict.SAME_ARTIFACT -> "Полный SHA-256 текущего артефакта совпадает с явно выбранной проверенной сборкой."
    BaselineVerdict.MODIFIED -> "SHA-256 отличается. Это подтверждает изменение относительно выбранного baseline, но само по себе не означает вредоносную модификацию."
    BaselineVerdict.SIGNER_CHANGED -> "SHA-256 отличается, а известные сертификаты подписания не пересекаются. Это требует отдельной проверки происхождения сборки и signer lineage."
    BaselineVerdict.NOT_COMPARABLE -> "Сравнение заблокировано, потому что package identity не совпадает."
    BaselineVerdict.INCOMPLETE_IDENTITY -> "В baseline или текущем отчёте отсутствует надёжный package identity."
}

private fun formatHistoryTime(epochMs: Long): String = runCatching {
    SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(epochMs))
}.getOrDefault(epochMs.toString())
