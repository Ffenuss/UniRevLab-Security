package org.unirevlab.security.ui

import android.content.ContentResolver
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.AnalystMappingEngine
import org.unirevlab.security.analysis.DeobfuscationEngine
import org.unirevlab.security.analysis.MappingDeobfuscator
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun AutomaticDeobfuscationPanel(report: StaticAnalysisReport) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }
    var mapping by remember(report.artifact.sha256) { mutableStateOf<DeobfuscationEngine.MappingSummary?>(null) }
    var mappingError by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }
    var showBasis by remember(report.artifact.sha256) { mutableStateOf<AnalystMappingEngine.Basis?>(null) }

    val automatic by produceState<AnalystMappingEngine.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.dex?.methodsIndexed,
    ) {
        value = withContext(Dispatchers.Default) { AnalystMappingEngine.generate(report) }
    }

    val exactAliases = remember(report.artifact.sha256, mapping) {
        mapping?.let { MappingDeobfuscator.resolve(report, it) }.orEmpty()
    }

    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        val text = readMappingTextBoundedAuto(context.contentResolver, uri)
                        DeobfuscationEngine.parseMapping(text)
                    }
                }.onSuccess {
                    mapping = it
                    mappingError = null
                    status = "Внешний mapping.txt импортирован: точные имена будут иметь приоритет над analyst aliases."
                }.onFailure {
                    mapping = null
                    mappingError = it.message ?: it.javaClass.simpleName
                }
            }
        }
    }

    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val generated = automatic
        if (uri != null && generated != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt")?.bufferedWriter()?.use { writer ->
                            writer.write(generated.mappingText)
                        } ?: error("Не удалось открыть файл для записи")
                    }
                }.onSuccess {
                    status = "Analyst mapping сохранён."
                }.onFailure {
                    status = "Ошибка сохранения mapping: ${it.message ?: it.javaClass.simpleName}"
                }
            }
        }
    }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Automatic Deobfuscation", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "После полного аудита UniRevLab сам оценивает обфускацию и строит analyst mapping. Semantic aliases выводятся из xrefs/API/строк/Android-компонентов; когда evidence недостаточно, создаётся стабильный нейтральный structural alias.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val result = automatic) {
                null -> Text("Считаем обфускацию и строим mapping…", fontWeight = FontWeight.SemiBold)
                else -> {
                    Text(
                        "Obfuscation score: ${result.obfuscationScore}/100 · ${if (result.likelyObfuscated) "обфускация вероятна" else "сильная обфускация не подтверждена"}",
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        "Mapped ${result.mappedSymbols}/${result.suspectedSymbols} suspected symbols · semantic ${result.semanticMappings} · structural ${result.structuralMappings}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Coverage: ${if (result.coverageComplete) "complete bounded DEX index" else "partial / bounded"}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(
                        onClick = { exportPicker.launch("unirevlab-analyst-mapping-${report.artifact.sha256.take(8)}.txt") },
                        enabled = result.entries.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Сохранить автоматический mapping.txt")
                    }
                }
            }
        }
    }

    automatic?.let { result ->
        Text("Automatic analyst mapping", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(selected = showBasis == null, onClick = { showBasis = null }, label = { Text("Все") })
            AnalystMappingEngine.Basis.entries.forEach { basis ->
                FilterChip(
                    selected = showBasis == basis,
                    onClick = { showBasis = if (showBasis == basis) null else basis },
                    label = { Text(basis.name) },
                )
            }
        }
        val visible = result.entries.asSequence()
            .filter { showBasis == null || it.basis == showBasis }
            .take(120)
            .toList()
        if (visible.isEmpty()) {
            Card(shape = RoundedCornerShape(16.dp)) {
                Text(
                    "Под выбранным фильтром mapping entries нет.",
                    modifier = Modifier.padding(13.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        } else {
            visible.forEach { entry ->
                Card(shape = RoundedCornerShape(16.dp)) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("${entry.kind} · ${entry.basis} · ${entry.confidence}", fontWeight = FontWeight.SemiBold)
                        Text(entry.obfuscatedSymbol, style = MaterialTheme.typography.bodySmall)
                        Text("→ ${entry.alias}", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                        entry.evidence.take(2).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                    }
                }
            }
            if (result.entries.size > visible.size) {
                Text("На экране первые ${visible.size}; полный mapping сохраняется в файл.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Точный R8 / ProGuard mapping.txt", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Не обязателен. Если заказчик передал mapping.txt от своей сборки, импортируем его и показываем точные исходные имена вместо эвристических analyst aliases.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = { importPicker.launch(arrayOf("text/plain", "application/octet-stream", "*/*")) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Импортировать официальный mapping.txt") }
            mappingError?.let { Text("Ошибка mapping.txt: $it", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            mapping?.let { parsed ->
                Text(
                    "Parsed: classes ${parsed.classes.size} · members ${parsed.members.size} · exact DEX matches ${exactAliases.size} · errors ${parsed.parseErrors}${if (parsed.truncated) " · truncated" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                )
                exactAliases.take(60).forEach { alias ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text("${alias.kind} · EXACT", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
                            Text(alias.obfuscatedSymbol, style = MaterialTheme.typography.bodySmall)
                            Text("→ ${alias.originalSymbol}", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }
    }

    status?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    Text(
        "Важно: автоматически созданный mapping предназначен для навигации и анализа. Без официального R8/ProGuard mapping невозможно доказать исходные имена разработчика, поэтому UniRevLab хранит provenance и confidence для каждого alias.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun readMappingTextBoundedAuto(resolver: ContentResolver, uri: Uri): String {
    val reader = resolver.openInputStream(uri)?.bufferedReader() ?: error("Не удалось открыть mapping.txt")
    reader.use {
        val out = StringBuilder()
        val buffer = CharArray(8192)
        while (true) {
            val read = it.read(buffer)
            if (read < 0) break
            require(out.length + read <= MAX_AUTO_MAPPING_TEXT_CHARS) {
                "mapping.txt слишком большой: лимит ${MAX_AUTO_MAPPING_TEXT_CHARS / 1_000_000} MB текста"
            }
            out.append(buffer, 0, read)
        }
        return out.toString()
    }
}

private const val MAX_AUTO_MAPPING_TEXT_CHARS = 4_000_000
