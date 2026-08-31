package org.unirevlab.security.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.PatchLabEngine
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun PatchLabScreen(
    report: StaticAnalysisReport,
    initialFinding: Finding?,
    initialSourceUri: Uri?,
    onBack: () -> Unit,
    onAnalyzeBuilt: (File) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val initialTarget = remember(report, initialFinding) { PatchLabEngine.resolveTarget(report, initialFinding) }

    var sourceUri by remember(report.artifact.sha256) { mutableStateOf(initialSourceUri) }
    var workspace by remember(report.artifact.sha256) { mutableStateOf<PatchLabEngine.Workspace?>(null) }
    var selectedDex by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.dexEntry) }
    var classes by remember(report.artifact.sha256) { mutableStateOf<List<String>>(emptyList()) }
    var selectedClass by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.classDescriptor) }
    var selectedMethodName by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.methodName) }
    var selectedPrototype by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.prototype) }
    var classQuery by remember { mutableStateOf("") }
    var smaliText by remember { mutableStateOf("") }
    var originalSmaliText by remember { mutableStateOf("") }
    var built by remember { mutableStateOf<PatchLabEngine.BuildResult?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val sourcePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            sourceUri = uri
            workspace = null
            classes = emptyList()
            smaliText = ""
            originalSmaliText = ""
            built = null
            status = "Исходный APK выбран. Подготовьте workspace."
            error = null
        }
    }

    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
        val file = built?.signedApk
        if (uri != null && file != null) {
            scope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть файл назначения" }
                            file.inputStream().buffered(128 * 1024).use { input -> input.copyTo(output, 128 * 1024) }
                            output.flush()
                        }
                    }
                }
                error = result.exceptionOrNull()?.message
                if (result.isSuccess) status = "Тестовый APK экспортирован."
            }
        }
    }

    fun prepareWorkspace() {
        val uri = sourceUri ?: return
        scope.launch {
            busy = true
            error = null
            status = "Копирование и проверка исходного APK…"
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.prepare(context, uri, report) } }
            result.getOrNull()?.let { ws ->
                workspace = ws
                if (selectedDex !in ws.dexEntries) selectedDex = initialTarget?.dexEntry?.takeIf { it in ws.dexEntries } ?: ws.dexEntries.firstOrNull()
                selectedClass = initialTarget?.classDescriptor
                selectedMethodName = initialTarget?.methodName
                selectedPrototype = initialTarget?.prototype
                status = "Workspace готов: DEX=${ws.dexEntries.size}, native=${ws.nativeEntries.size}."
            }
            error = result.exceptionOrNull()?.message
            busy = false
        }
    }

    fun disassembleCurrentDex() {
        val ws = workspace ?: return
        val dex = selectedDex ?: return
        scope.launch {
            busy = true
            error = null
            status = "baksmali: разбор $dex…"
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.disassembleDex(ws, dex) } }
            result.getOrNull()?.let { list ->
                classes = list
                val preferred = initialTarget?.classDescriptor?.takeIf { it in list }
                if (selectedClass !in list) selectedClass = preferred ?: list.firstOrNull()
                status = "DEX разобран: ${list.size} классов."
            }
            error = result.exceptionOrNull()?.message
            busy = false
        }
    }

    fun loadCurrentClass() {
        val ws = workspace ?: return
        val dex = selectedDex ?: return
        val cls = selectedClass ?: return
        scope.launch {
            busy = true
            error = null
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.loadClass(ws, dex, cls) } }
            result.getOrNull()?.let {
                smaliText = it
                originalSmaliText = it
                status = "Открыт $cls из $dex"
            }
            error = result.exceptionOrNull()?.message
            busy = false
        }
    }

    fun saveCurrentClass() {
        val ws = workspace ?: return
        val dex = selectedDex ?: return
        val cls = selectedClass ?: return
        scope.launch {
            busy = true
            error = null
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.saveClass(ws, dex, cls, smaliText) } }
            if (result.isSuccess) {
                originalSmaliText = smaliText
                built = null
                status = "Изменения сохранены в workspace: $dex / $cls"
            }
            error = result.exceptionOrNull()?.message
            busy = false
        }
    }

    fun buildApk() {
        val ws = workspace ?: return
        scope.launch {
            busy = true
            error = null
            built = null
            status = "smali → DEX → APK → тестовая подпись…"
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.build(ws) } }
            result.getOrNull()?.let {
                built = it
                status = "Готов тестовый APK. Изменено: ${it.changedEntries.joinToString()}"
            }
            error = result.exceptionOrNull()?.message
            busy = false
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) { Text("← К отчёту") }
                Text("Patch / Hook Lab", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(2f))
            }
            Text(
                "Лабораторный режим для авторизованной проверки. Исходный APK не меняется; собирается отдельная тестовая версия с отдельной подписью.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            initialFinding?.let { finding ->
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f))) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text("Из Finding", fontWeight = FontWeight.SemiBold)
                        Text("${finding.severity}: ${finding.title}")
                        Text(finding.id, style = MaterialTheme.typography.bodySmall)
                        initialTarget?.methodLabel?.let { Text("Цель: $it", style = MaterialTheme.typography.bodySmall) }
                        initialTarget?.nativeEntry?.let { Text("Native: $it", style = MaterialTheme.typography.bodySmall) }
                    }
                }
            }

            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            status?.let { Text(it, color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall) }
            error?.let { Text("Ошибка: $it", color = MaterialTheme.colorScheme.error) }

            Text("1. Исходный APK", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(sourceUri?.lastPathSegment ?: "APK не выбран", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(
                onClick = { sourcePicker.launch(arrayOf("application/vnd.android.package-archive", "application/zip", "application/octet-stream")) },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (sourceUri == null) "Выбрать исходный APK" else "Выбрать другой APK") }
            Button(onClick = ::prepareWorkspace, enabled = sourceUri != null && !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Подготовить Patch Lab workspace")
            }

            workspace?.let { ws ->
                HorizontalDivider()
                Text("2. DEX / класс / метод", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("SHA-256 исходника: ${ws.artifactSha256}", style = MaterialTheme.typography.bodySmall)
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ws.dexEntries.forEach { dex ->
                        if (dex == selectedDex) Button(onClick = { selectedDex = dex; classes = emptyList(); smaliText = "" }) { Text(dex) }
                        else OutlinedButton(onClick = { selectedDex = dex; classes = emptyList(); smaliText = "" }) { Text(dex) }
                    }
                }
                Button(onClick = ::disassembleCurrentDex, enabled = selectedDex != null && !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Разобрать выбранный DEX в Smali")
                }

                if (classes.isNotEmpty()) {
                    OutlinedTextField(
                        value = classQuery,
                        onValueChange = { classQuery = it.take(180) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Поиск класса") },
                    )
                    val filtered = remember(classes, classQuery, selectedClass) {
                        val q = classQuery.trim().lowercase()
                        when {
                            q.length >= 2 -> classes.asSequence().filter { it.lowercase().contains(q) }.take(80).toList()
                            selectedClass != null -> listOfNotNull(selectedClass).filter { it in classes } + classes.take(24).filter { it != selectedClass }
                            else -> classes.take(25)
                        }
                    }
                    filtered.distinct().forEach { cls ->
                        OutlinedButton(
                            onClick = {
                                selectedClass = cls
                                val firstMethod = report.dex?.methods?.firstOrNull { it.dexEntry == selectedDex && it.declaringClass == cls }
                                selectedMethodName = firstMethod?.name
                                selectedPrototype = firstMethod?.prototype
                                smaliText = ""
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(if (cls == selectedClass) "✓ $cls" else cls) }
                    }
                    Button(onClick = ::loadCurrentClass, enabled = selectedClass != null && !busy, modifier = Modifier.fillMaxWidth()) {
                        Text("Открыть Smali-класс")
                    }
                }

                val classMethods = remember(report, selectedDex, selectedClass) {
                    report.dex?.methods.orEmpty().filter { it.dexEntry == selectedDex && it.declaringClass == selectedClass }.take(160)
                }
                if (classMethods.isNotEmpty()) {
                    Text("Методы из RE-индекса", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    classMethods.forEach { method ->
                        OutlinedButton(
                            onClick = { selectedMethodName = method.name; selectedPrototype = method.prototype },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            val mark = if (method.name == selectedMethodName && method.prototype == selectedPrototype) "✓ " else ""
                            Text("$mark${method.name}${method.prototype}")
                        }
                    }
                }

                if (smaliText.isNotBlank()) {
                    HorizontalDivider()
                    Text("3. Редактор / test hook", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("${selectedClass ?: ""}  ${selectedMethodName.orEmpty()}${selectedPrototype.orEmpty()}", style = MaterialTheme.typography.bodySmall)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                val name = selectedMethodName
                                val proto = selectedPrototype
                                if (name != null && proto != null) {
                                    runCatching { PatchLabEngine.addEntryLogHook(smaliText, name, proto, initialFinding?.id) }
                                        .onSuccess { smaliText = it; error = null; status = "Добавлен test Log hook в $name$proto" }
                                        .onFailure { error = it.message }
                                }
                            },
                            enabled = selectedMethodName != null && selectedPrototype != null && !busy,
                            modifier = Modifier.weight(1f),
                        ) { Text("+ Log hook") }
                        OutlinedButton(
                            onClick = {
                                val name = selectedMethodName
                                val proto = selectedPrototype
                                if (name != null && proto != null) {
                                    runCatching { PatchLabEngine.forceBooleanReturn(smaliText, name, proto, false) }
                                        .onSuccess { smaliText = it; error = null; status = "Добавлен test return=false в $name$proto" }
                                        .onFailure { error = it.message }
                                }
                            },
                            enabled = selectedPrototype?.endsWith(")Z") == true && !busy,
                            modifier = Modifier.weight(1f),
                        ) { Text("return false") }
                    }
                    OutlinedTextField(
                        value = smaliText,
                        onValueChange = { smaliText = it },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 420.dp),
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        label = { Text("Smali — можно редактировать вручную") },
                    )
                    Text(
                        if (smaliText == originalSmaliText) "Нет несохранённых изменений" else "Есть несохранённые изменения",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(onClick = ::saveCurrentClass, enabled = smaliText.isNotBlank() && smaliText != originalSmaliText && !busy, modifier = Modifier.fillMaxWidth()) {
                        Text("Сохранить патч класса")
                    }
                }

                if (ws.nativeEntries.isNotEmpty()) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Native workspace", fontWeight = FontWeight.SemiBold)
                            Text("Найдено ELF/.so: ${ws.nativeEntries.size}. Замена .so уже поддержана engine; UI выбора replacement-файла будет следующим слоем.", style = MaterialTheme.typography.bodySmall)
                            ws.nativeEntries.take(8).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }

                HorizontalDivider()
                Text("4. Сборка и проверка", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("Сборка удаляет старые APK signatures и подписывает отдельным лабораторным тестовым ключом.", style = MaterialTheme.typography.bodySmall)
                Button(onClick = ::buildApk, enabled = (ws.modifiedDexEntries.isNotEmpty() || ws.replacements.isNotEmpty()) && !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Собрать и подписать тестовый APK")
                }
                built?.let { result ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f))) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("Тестовая сборка готова", fontWeight = FontWeight.Bold)
                            Text("SHA-256: ${result.sha256}", style = MaterialTheme.typography.bodySmall)
                            Text("Signer: ${result.signerLabel}", style = MaterialTheme.typography.bodySmall)
                            Text("Изменения: ${result.changedEntries.joinToString()}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    OutlinedButton(
                        onClick = {
                            val name = report.artifact.displayName.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"), "_").take(72)
                            exportPicker.launch("${name}-unirevlab-patched.apk")
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Экспортировать APK") }
                    OutlinedButton(
                        onClick = {
                            runCatching {
                                val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", result.signedApk)
                                val intent = Intent(Intent.ACTION_VIEW)
                                    .setDataAndType(uri, "application/vnd.android.package-archive")
                                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                                context.startActivity(intent)
                            }.onFailure { error = it.message }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Установить тестовую сборку") }
                    Button(onClick = { onAnalyzeBuilt(result.signedApk) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Повторно проанализировать и сравнить")
                    }
                }
            }
        }
    }
}
