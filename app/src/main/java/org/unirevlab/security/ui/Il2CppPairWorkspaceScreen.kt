package org.unirevlab.security.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.Il2CppMonetizationRiskEngine
import org.unirevlab.security.analysis.Il2CppPairAssessmentEngine
import org.unirevlab.security.model.AssessmentScope

@Composable
fun Il2CppPairWorkspaceScreen(
    scope: AssessmentScope,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var metadataUri by remember { mutableStateOf<Uri?>(null) }
    var libraryUri by remember { mutableStateOf<Uri?>(null) }
    var metadataName by remember { mutableStateOf<String?>(null) }
    var libraryName by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<Il2CppPairAssessmentEngine.Result?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }

    val metadataPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            metadataUri = uri
            metadataName = queryDisplayName(context, uri) ?: uri.lastPathSegment
            result = null
            error = null
        }
    }
    val libraryPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            libraryUri = uri
            libraryName = queryDisplayName(context, uri) ?: uri.lastPathSegment
            result = null
            error = null
        }
    }
    val dumpSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val current = result
        if (uri != null && current != null) {
            coroutineScope.launch {
                val save = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть файл назначения" }
                            output.write(current.managedDump.toByteArray(Charsets.UTF_8))
                            output.flush()
                        }
                    }
                }
                error = save.exceptionOrNull()?.message
            }
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("← Инструменты") }
            Text("IL2CPP Dump / Metadata", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                "Импортируйте matching global-metadata.dat и libil2cpp.so. UniRevLab восстанавливает managed types/methods/fields, оценивает обфускацию, строит analyst mapping и выделяет premium / entitlement / subscription / IAP / receipt-validation attack surface.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Card(
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Defensive mode", fontWeight = FontWeight.Bold)
                    Text(
                        "Файлы анализируются как данные: libil2cpp.so не загружается и не исполняется. Workspace не генерирует patch offsets, premium=true или инструкции разблокировки — он показывает точную клиентскую поверхность риска и evidence для исправления.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(
                    onClick = { metadataPicker.launch(arrayOf("application/octet-stream", "*/*")) },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) { Text("global-metadata.dat") }
                OutlinedButton(
                    onClick = { libraryPicker.launch(arrayOf("application/octet-stream", "*/*")) },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) { Text("libil2cpp.so") }
            }
            Text("Metadata: ${metadataName ?: "не выбран"}", style = MaterialTheme.typography.bodySmall)
            Text("Library: ${libraryName ?: "не выбрана"}", style = MaterialTheme.typography.bodySmall)

            Button(
                onClick = {
                    val meta = metadataUri
                    val lib = libraryUri
                    if (meta == null || lib == null) {
                        error = "Выберите оба файла: global-metadata.dat и libil2cpp.so"
                    } else {
                        coroutineScope.launch {
                            busy = true
                            error = null
                            val analyzed = runCatching {
                                withContext(Dispatchers.IO) {
                                    val work = File(context.cacheDir, "il2cpp-pair-${System.nanoTime()}").apply { mkdirs() }
                                    val metadataFile = File(work, "global-metadata.dat")
                                    val libraryFile = File(work, "libil2cpp.so")
                                    try {
                                        copyUriBounded(context, meta, metadataFile, MAX_METADATA_BYTES)
                                        copyUriBounded(context, lib, libraryFile, MAX_LIBRARY_BYTES)
                                        Il2CppPairAssessmentEngine.analyze(
                                            metadataFile = metadataFile,
                                            libraryFile = libraryFile,
                                            projectName = scope.projectName,
                                            organization = scope.organization,
                                        )
                                    } finally {
                                        work.deleteRecursively()
                                    }
                                }
                            }
                            result = analyzed.getOrNull()
                            error = analyzed.exceptionOrNull()?.message
                            busy = false
                        }
                    }
                },
                enabled = !busy && metadataUri != null && libraryUri != null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Анализировать IL2CPP pair") }

            if (busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Парсим metadata и ELF, восстанавливаем IL2CPP identities…", style = MaterialTheme.typography.bodySmall)
            }
            error?.let {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                    Text("Ошибка: $it", modifier = Modifier.padding(14.dp), color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }

            result?.let { current ->
                HorizontalDivider()
                Il2CppPairResultPanel(current)
                OutlinedButton(
                    onClick = { dumpSaver.launch("unirevlab-il2cpp-managed-dump-${current.aggregateSha256.take(8)}.txt") },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Сохранить managed dump") }

                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Фильтр: premium / purchase / тип / метод / поле") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                val filtered = current.risk.candidates.filter { candidate ->
                    query.isBlank() || candidate.managedIdentity.contains(query, ignoreCase = true) ||
                        candidate.category.name.contains(query, ignoreCase = true) ||
                        candidate.kind.contains(query, ignoreCase = true)
                }
                Text("Кандидаты: ${filtered.size}/${current.risk.candidates.size}", fontWeight = FontWeight.SemiBold)
                filtered.take(150).forEach { candidate -> CandidateCard(candidate) }
                if (filtered.size > 150) {
                    Text("На экране показаны первые 150; полный managed dump сохраняется отдельно.", style = MaterialTheme.typography.bodySmall)
                }

                HorizontalDivider()
                Text("IL2CPP analyst mapping", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(
                    "Aliases помогают навигации по обфусцированной metadata. CONTEXTUAL — гипотеза по контексту типа; STRUCTURAL — нейтральное имя без семантического утверждения.",
                    style = MaterialTheme.typography.bodySmall,
                )
                val mapped = current.mapping.entries.filter { entry ->
                    query.isBlank() || entry.originalIdentity.contains(query, ignoreCase = true) ||
                        entry.alias.contains(query, ignoreCase = true) ||
                        entry.semanticCategory?.contains(query, ignoreCase = true) == true ||
                        entry.basis.name.contains(query, ignoreCase = true)
                }
                Text("Mapping entries: ${mapped.size}/${current.mapping.entries.size}", fontWeight = FontWeight.SemiBold)
                mapped.take(120).forEach { entry ->
                    PairInfoCard(
                        "${entry.basis} · ${entry.confidence} · ${entry.kind} #${entry.symbolIndex}\n${entry.originalIdentity}\n→ ${entry.alias}${entry.semanticCategory?.let { " · $it" } ?: ""}",
                    )
                }
                if (mapped.size > 120) {
                    Text("Показаны первые 120 mapping entries; полный mapping включён в сохранённый managed dump.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun Il2CppPairResultPanel(current: Il2CppPairAssessmentEngine.Result) {
    val risk = current.risk
    Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("IL2CPP reconstruction", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text("Posture: ${risk.posture}", fontWeight = FontWeight.Bold)
            Text("Metadata v${risk.metadataVersion ?: "?"} · types ${risk.typeCount} · methods ${risk.methodCount} · fields ${risk.fieldCount}")
            Text("Monetization ${risk.monetizationCandidates} · validation ${risk.validationCandidates} · client-state ${risk.clientStateCandidates}")
            Text("Native correlations ${risk.nativeCorrelations} · coverage ${if (risk.coverageComplete) "COMPLETE" else "PARTIAL"}")
            Text("Native evidence: verified ${current.nativeEvidence.verified} · supported ${current.nativeEvidence.supported} · weak ${current.nativeEvidence.weak} · conflicting ${current.nativeEvidence.conflicting}")
            if (!current.nativeEvidence.correlationDataAvailable) {
                Text("Ghidra/native correlation dataset: not available in pair-only mode", style = MaterialTheme.typography.bodySmall)
            }
            Text("Obfuscation ${current.mapping.obfuscationScore}/100 · suspected ${current.mapping.suspectedSymbols} · mapped ${current.mapping.mappedSymbols}")
            Text("Semantic ${current.mapping.semanticMappings} · contextual ${current.mapping.contextualMappings} · structural ${current.mapping.structuralMappings}", style = MaterialTheme.typography.bodySmall)
            Text("Pair SHA-256 ${current.aggregateSha256.take(24)}…", style = MaterialTheme.typography.bodySmall)
        }
    }
    current.warnings.forEach { PairInfoCard("⚠ $it") }
    if (risk.recommendations.isNotEmpty()) {
        Card(shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text("Hardening actions", fontWeight = FontWeight.Bold)
                risk.recommendations.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
    if (risk.candidates.isEmpty()) {
        PairInfoCard(
            if (risk.coverageComplete) {
                "В восстановленной metadata очевидные premium/IAP/entitlement identifiers не обнаружены. Это не доказывает отсутствие монетизации."
            } else {
                "Metadata reconstruction неполный — отсутствие monetization-кандидатов не подтверждено."
            },
        )
    }
}

@Composable
private fun CandidateCard(candidate: Il2CppMonetizationRiskEngine.Candidate) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("${candidate.category} · ${candidate.kind} · ${candidate.confidence}", fontWeight = FontWeight.Bold)
            Text(candidate.managedIdentity, style = MaterialTheme.typography.bodyMedium)
            candidate.metadataToken?.let { Text("metadata token 0x${it.toString(16)}", style = MaterialTheme.typography.labelSmall) }
            candidate.nativeFunctionName?.let { Text("Native correlation: $it", style = MaterialTheme.typography.bodySmall) }
            candidate.evidence.take(4).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun PairInfoCard(text: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Text(text, modifier = Modifier.padding(13.dp), style = MaterialTheme.typography.bodySmall)
    }
}

private fun queryDisplayName(context: Context, uri: Uri): String? = runCatching {
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (index >= 0) cursor.getString(index) else null
    }
}.getOrNull()

private fun copyUriBounded(context: Context, uri: Uri, target: File, maxBytes: Long) {
    target.parentFile?.mkdirs()
    context.contentResolver.openInputStream(uri).use { input ->
        requireNotNull(input) { "Не удалось открыть выбранный файл" }
        FileOutputStream(target).buffered(128 * 1024).use { output ->
            val buffer = ByteArray(128 * 1024)
            var total = 0L
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                total += read
                require(total <= maxBytes) { "Файл превышает безопасный локальный лимит ${maxBytes / (1024 * 1024)} MiB" }
                output.write(buffer, 0, read)
            }
            output.flush()
        }
    }
    require(target.isFile && target.length() > 0L) { "Выбранный файл пуст" }
}

private const val MAX_METADATA_BYTES = 64L * 1024L * 1024L
private const val MAX_LIBRARY_BYTES = 128L * 1024L * 1024L
