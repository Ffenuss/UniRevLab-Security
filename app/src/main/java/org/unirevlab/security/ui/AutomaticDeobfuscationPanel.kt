package org.unirevlab.security.ui

import android.content.ContentResolver
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import org.unirevlab.security.analysis.FullMappingEngine
import org.unirevlab.security.analysis.MappingDeobfuscator
import org.unirevlab.security.analysis.SemanticRecoveryEngine
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

    val semanticRecovery by produceState<SemanticRecoveryEngine.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.dex?.methodsIndexed,
    ) {
        value = withContext(Dispatchers.Default) { SemanticRecoveryEngine.generate(report) }
    }

    val fullMapping by produceState<FullMappingEngine.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.dex?.methodsIndexed,
        key3 = mapping,
    ) {
        value = withContext(Dispatchers.Default) { FullMappingEngine.generate(report, mapping) }
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
                        writeText(context.contentResolver, uri, generated.mappingText)
                    }
                }.onSuccess {
                    status = "Analyst mapping сохранён."
                }.onFailure {
                    status = "Ошибка сохранения mapping: ${it.message ?: it.javaClass.simpleName}"
                }
            }
        }
    }

    val exportOriginalStylePicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val generated = fullMapping
        if (uri != null && generated != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        writeText(context.contentResolver, uri, generated.originalStyleMappingText)
                    }
                }.onSuccess {
                    status = "Полный reconstructed mapping сохранён в original-style формате."
                }.onFailure {
                    status = "Ошибка сохранения полного mapping: ${it.message ?: it.javaClass.simpleName}"
                }
            }
        }
    }

    val exportProvenancePicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val generated = fullMapping
        if (uri != null && generated != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        writeText(context.contentResolver, uri, generated.provenanceMappingText)
                    }
                }.onSuccess {
                    status = "Mapping с provenance/confidence сохранён."
                }.onFailure {
                    status = "Ошибка сохранения provenance mapping: ${it.message ?: it.javaClass.simpleName}"
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
                "После полного аудита UniRevLab сам оценивает обфускацию, выводит semantic aliases из xrefs/API/строк/Android-компонентов и строит стабильный analyst mapping. Если заказчик даёт официальный R8/ProGuard mapping.txt, точные имена автоматически получают приоритет.",
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
                    OutlinedButton(
                        onClick = { exportPicker.launch("unirevlab-analyst-mapping-${report.artifact.sha256.take(8)}.txt") },
                        enabled = result.entries.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Сохранить compact analyst mapping")
                    }
                }
            }
        }
    }

    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Full reconstructed mapping", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Этот режим строит original-style class/member mapping для всех доступных в DEX-индексе классов и методов, а также для известных полей. Читаемые имена сохраняются, обфусцированные получают exact / semantic / structural имя с provenance.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val result = fullMapping) {
                null -> Text("Строим полный mapping…", fontWeight = FontWeight.SemiBold)
                else -> {
                    Text(
                        "Classes ${result.classesMapped} · methods ${result.methodsMapped} · fields ${result.fieldsMapped}",
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "EXACT ${result.exactSymbols} · SEMANTIC ${result.semanticSymbols} · STRUCTURAL ${result.structuralSymbols} · PRESERVED ${result.preservedSymbols}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "DEX coverage: ${if (result.dexCoverageComplete) "complete" else "partial / bounded"} · field inventory: ${if (result.fieldInventoryComplete) "complete" else "referenced fields only"}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    semanticRecovery?.let { recovery ->
                        Text(
                            "Semantic recovery: HIGH ${recovery.highConfidence} · MEDIUM ${recovery.mediumConfidence} · source ${recovery.sourceMetadataHits} · inheritance ${recovery.inheritanceHits} · resources ${recovery.resourceHits} · graph ${recovery.callGraphHits} · JNI/runtime ${recovery.jniHits + recovery.crossRuntimeHits}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    Button(
                        onClick = { exportOriginalStylePicker.launch("unirevlab-full-mapping-${report.artifact.sha256.take(8)}.mapping.txt") },
                        enabled = result.symbols.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Сохранить полный original-style mapping.txt")
                    }
                    OutlinedButton(
                        onClick = { exportProvenancePicker.launch("unirevlab-full-mapping-${report.artifact.sha256.take(8)}-provenance.txt") },
                        enabled = result.symbols.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Сохранить provenance / confidence")
                    }
                }
            }
            Text(
                "Важно: без официального mapping.txt APK не содержит гарантии исходных имён. UniRevLab может восстановить структуру и назначить доказательные семантические имена, но только EXACT-записи считаются настоящими pre-R8 именами.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
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
        "Автоматически созданный mapping предназначен для навигации и анализа. Без официального R8/ProGuard mapping невозможно доказать удалённые исходные идентификаторы, поэтому UniRevLab хранит origin, provenance и confidence для каждого реконструированного символа.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun writeText(resolver: ContentResolver, uri: Uri, text: String) {
    resolver.openOutputStream(uri, "wt")?.bufferedWriter()?.use { writer ->
        writer.write(text)
    } ?: error("Не удалось открыть файл для записи")
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
