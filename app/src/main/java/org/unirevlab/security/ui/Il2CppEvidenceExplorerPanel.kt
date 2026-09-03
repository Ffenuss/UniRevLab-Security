package org.unirevlab.security.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.Il2CppEvidenceExplorerModel
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun Il2CppEvidenceExplorerPanel(report: StaticAnalysisReport) {
    val result by produceState<Il2CppEvidenceExplorerModel.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.correlations?.il2cppMethods?.size,
    ) {
        value = withContext(Dispatchers.Default) {
            Il2CppEvidenceExplorerModel.build(report)
        }
    }
    var query by remember(report.artifact.sha256) { mutableStateOf("") }
    var status by remember(report.artifact.sha256) {
        mutableStateOf<Il2CppEvidenceExplorerModel.LinkStatus?>(null)
    }
    var expandedKey by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("IL2CPP Evidence Explorer", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Semantic candidate → canonical metadata identity/token → validated native/Ghidra identity. Explorer не показывает RVA/patch offsets и не генерирует изменения: это read-only evidence для review и hardening.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val current = result) {
                null -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Связываем semantic mapping с native correlation evidence…", style = MaterialTheme.typography.bodySmall)
                }
                else -> {
                    Text(
                        "Semantic ${current.semanticCandidates} · verified ${current.verified} · supported ${current.supported} · weak ${current.weak} · conflicting ${current.conflicting} · managed-only ${current.managedOnly}",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "Managed coverage ${coverageLabel(current.managedCoverageComplete)} · native dataset ${if (current.nativeDataAvailable) "available" else "not available"} · native coverage ${coverageLabel(current.nativeCoverageComplete)}",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
    }

    val current = result ?: return
    if (!current.il2cppDetected) {
        EvidenceInfoCard("IL2CPP metadata не обнаружена — Evidence Explorer неприменим к этому артефакту.")
        return
    }
    if (current.rows.isEmpty()) {
        EvidenceInfoCard(
            if (current.managedCoverageComplete) {
                "В восстановленной IL2CPP metadata semantic candidates для текущих категорий не обнаружены. Это не доказывает отсутствие чувствительной клиентской логики."
            } else {
                "IL2CPP metadata coverage неполный — отсутствие semantic candidates не подтверждено."
            },
        )
        return
    }

    OutlinedTextField(
        value = query,
        onValueChange = { query = it },
        label = { Text("Поиск: managed identity / alias / token / native function / provenance") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )

    val filters = listOf<Il2CppEvidenceExplorerModel.LinkStatus?>(null) + Il2CppEvidenceExplorerModel.LinkStatus.entries
    filters.chunked(3).forEach { rowFilters ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            rowFilters.forEach { filter ->
                FilterChip(
                    selected = status == filter,
                    onClick = { status = filter },
                    label = { Text(filter?.let(::evidenceStatusLabel) ?: "ALL") },
                    modifier = Modifier.weight(1f),
                )
            }
            repeat(3 - rowFilters.size) { Column(Modifier.weight(1f)) {} }
        }
    }

    val filtered = remember(current, query, status) {
        Il2CppEvidenceExplorerModel.filter(current, query, status)
    }
    Text(
        "Evidence rows: ${filtered.size}/${current.rows.size}${if (current.rowsTruncated) " · source truncated for UI" else ""}",
        style = MaterialTheme.typography.bodySmall,
        fontWeight = FontWeight.SemiBold,
    )

    filtered.take(MAX_VISIBLE_ROWS).forEach { row ->
        val expanded = expandedKey == row.key
        Card(
            modifier = Modifier.fillMaxWidth().clickable {
                expandedKey = if (expanded) null else row.key
            },
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(
                        "${row.semanticCategory} · ${row.kind} #${row.symbolIndex}",
                        modifier = Modifier.weight(1f),
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        evidenceStatusLabel(row.linkStatus),
                        color = evidenceStatusColor(row.linkStatus),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                Text(row.managedIdentity, style = MaterialTheme.typography.bodyMedium)
                Text("→ ${row.analystAlias}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                Text(
                    "${row.mappingBasis} · ${row.mappingConfidence}" +
                        (row.metadataToken?.let { " · token 0x${it.toString(16)}" } ?: ""),
                    style = MaterialTheme.typography.labelSmall,
                )
                row.nativeFunctionName?.let {
                    Text("Ghidra/native function: $it", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                }
                if (!expanded) {
                    Text("Нажмите, чтобы раскрыть evidence", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    row.methodIndex?.let { Text("methodIndex=$it", style = MaterialTheme.typography.bodySmall) }
                    row.nativeLibrary?.let { Text("Native library: $it", style = MaterialTheme.typography.bodySmall) }
                    row.nativeProvenance?.let {
                        Text(
                            "Correlation provenance: $it${row.nativeConfidence?.let { confidence -> " ($confidence)" } ?: ""}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (row.linkStatus == Il2CppEvidenceExplorerModel.LinkStatus.MANAGED_ONLY) {
                        Text(
                            "Native correlation не подтверждена; managed metadata evidence остаётся отдельным статическим сигналом.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    row.evidence.forEach { evidence ->
                        Text("• $evidence", style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        "Статическая identity correlation не доказывает runtime return value, entitlement result или exploitability.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
    if (filtered.size > MAX_VISIBLE_ROWS) {
        EvidenceInfoCard("На экране показаны первые $MAX_VISIBLE_ROWS совпадений. Уточните поиск или status-фильтр для точной навигации.")
    }
}

@Composable
private fun EvidenceInfoCard(text: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Text(text, modifier = Modifier.padding(13.dp), style = MaterialTheme.typography.bodySmall)
    }
}

private fun coverageLabel(complete: Boolean): String = if (complete) "COMPLETE" else "PARTIAL"

private fun evidenceStatusLabel(status: Il2CppEvidenceExplorerModel.LinkStatus): String = when (status) {
    Il2CppEvidenceExplorerModel.LinkStatus.VERIFIED -> "VERIFIED"
    Il2CppEvidenceExplorerModel.LinkStatus.SUPPORTED -> "SUPPORTED"
    Il2CppEvidenceExplorerModel.LinkStatus.WEAK -> "WEAK"
    Il2CppEvidenceExplorerModel.LinkStatus.CONFLICTING -> "CONFLICT"
    Il2CppEvidenceExplorerModel.LinkStatus.MANAGED_ONLY -> "MANAGED"
}

@Composable
private fun evidenceStatusColor(status: Il2CppEvidenceExplorerModel.LinkStatus) = when (status) {
    Il2CppEvidenceExplorerModel.LinkStatus.VERIFIED -> MaterialTheme.colorScheme.primary
    Il2CppEvidenceExplorerModel.LinkStatus.SUPPORTED -> MaterialTheme.colorScheme.secondary
    Il2CppEvidenceExplorerModel.LinkStatus.WEAK -> MaterialTheme.colorScheme.tertiary
    Il2CppEvidenceExplorerModel.LinkStatus.CONFLICTING -> MaterialTheme.colorScheme.error
    Il2CppEvidenceExplorerModel.LinkStatus.MANAGED_ONLY -> MaterialTheme.colorScheme.onSurfaceVariant
}

private const val MAX_VISIBLE_ROWS = 120
