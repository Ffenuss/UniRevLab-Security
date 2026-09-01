package org.unirevlab.security.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.RuntimeStateLabEngine

@Composable
fun RuntimeStateLabPanel(
    busy: Boolean,
    onStatus: (String) -> Unit,
    onError: (String?) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var treeUri by remember { mutableStateOf<Uri?>(null) }
    var query by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<RuntimeStateLabEngine.SearchReport?>(null) }
    var searching by remember { mutableStateOf(false) }
    var showResults by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<RuntimeStateLabEngine.StateHit?>(null) }
    var editValue by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf(false) }

    val treePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            runCatching { context.contentResolver.takePersistableUriPermission(uri, flags) }
            treeUri = uri
            report = null
            selected = null
            onError(null)
            onStatus("Runtime State Lab: папка данных выбрана")
        }
    }

    fun runSearch(openResults: Boolean = true) {
        val uri = treeUri ?: return
        scope.launch {
            searching = true
            onError(null)
            val result = runCatching {
                withContext(Dispatchers.IO) { RuntimeStateLabEngine.search(context, uri, query) }
            }
            result.getOrNull()?.let {
                report = it
                if (openResults) showResults = true
                onStatus("Runtime State Lab: найдено ${it.hits.size}; файлов ${it.filesScanned}; SQLite-таблиц ${it.sqliteTablesScanned}")
            }
            result.exceptionOrNull()?.let { onError(it.message) }
            searching = false
        }
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.30f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Runtime State Lab — реальные локальные сохранения", fontWeight = FontWeight.Bold)
            Text(
                "Ищет key/value в локальных данных цели: SharedPreferences XML, JSON, properties/INI/text и SQLite. " +
                    "Совпадение идёт и по имени ключа, и по текущему значению. * показывает все распознанные значения. " +
                    "Перед первой записью создаётся backup.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Для установленной цели используйте её snapshot/backup или debug-директорию, если Android не дал прямой доступ к private sandbox. " +
                    "Импортированный APK сам по себе не содержит runtime-сохранения пользователя.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = { treePicker.launch(treeUri) },
                enabled = !busy && !searching && !editing,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (treeUri == null) "Подключить snapshot / папку данных" else "Выбрать другой snapshot / папку") }
            treeUri?.let { Text(it.toString(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }

            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(220) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Ключ или значение: premium, score, hp, money, 1250…") },
                supportingText = { Text("Введите минимум 2 символа. * = показать все распознанные key/value.") },
            )
            Button(
                onClick = { runSearch(true) },
                enabled = treeUri != null && (query.trim() == "*" || query.trim().length >= 2) && !busy && !searching && !editing,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Искать в локальных сохранениях") }
            if (searching) LinearProgressIndicator(Modifier.fillMaxWidth())

            report?.let { current ->
                Text(
                    "Найдено: ${current.hits.size} · файлов: ${current.filesScanned} · SQLite-таблиц: ${current.sqliteTablesScanned}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (current.hits.isNotEmpty()) {
                    OutlinedButton(onClick = { showResults = true }, modifier = Modifier.fillMaxWidth()) {
                        Text("Открыть все результаты (${current.hits.size})")
                    }
                }
                if (current.warnings.isNotEmpty()) {
                    Text("Предупреждений: ${current.warnings.size}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    val currentReport = report
    if (showResults && currentReport != null) {
        Dialog(
            onDismissRequest = { if (!editing) showResults = false },
            properties = DialogProperties(usePlatformDefaultWidth = false),
        ) {
            Surface(Modifier.fillMaxSize().padding(10.dp), tonalElevation = 3.dp) {
                Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Runtime State: ${currentReport.hits.size}", fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        OutlinedButton(onClick = { showResults = false }, enabled = !editing) { Text("Закрыть") }
                    }
                    Text("Результаты не обрезаются: список виртуализирован и показывает все найденные записи.", style = MaterialTheme.typography.bodySmall)
                    HorizontalDivider()
                    LazyColumn(
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        items(currentReport.hits, key = { it.id }) { hit ->
                            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))) {
                                Column(Modifier.padding(9.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    Text("${hit.format} · ${hit.valueType}", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                    Text(hit.path, style = MaterialTheme.typography.bodySmall)
                                    Text(hit.key, fontWeight = FontWeight.SemiBold)
                                    Text(hit.value, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                                    Button(
                                        onClick = {
                                            selected = hit
                                            editValue = hit.value
                                        },
                                        enabled = hit.writable && !editing,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) { Text(if (hit.writable) "Открыть и редактировать" else "Только чтение") }
                                }
                            }
                        }
                    }
                    if (currentReport.warnings.isNotEmpty()) {
                        Text("Не удалось прочитать ${currentReport.warnings.size} элементов. Они не считаются найденными результатами.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }

    val hit = selected
    if (hit != null) {
        Dialog(
            onDismissRequest = { if (!editing) selected = null },
            properties = DialogProperties(usePlatformDefaultWidth = false),
        ) {
            Surface(Modifier.fillMaxSize().padding(18.dp), tonalElevation = 4.dp) {
                Column(Modifier.fillMaxSize().padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    Text("Редактор локального значения", fontWeight = FontWeight.Bold)
                    Text(hit.path, style = MaterialTheme.typography.bodySmall)
                    Text("${hit.format} · ${hit.key} · ${hit.valueType}", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = editValue,
                        onValueChange = { editValue = it },
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        label = { Text("Новое значение") },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    )
                    if (editing) LinearProgressIndicator(Modifier.fillMaxWidth())
                    Button(
                        onClick = {
                            scope.launch {
                                editing = true
                                onError(null)
                                val result = runCatching {
                                    withContext(Dispatchers.IO) { RuntimeStateLabEngine.edit(context, hit, editValue) }
                                }
                                result.getOrNull()?.let { updated ->
                                    selected = updated
                                    editValue = updated.value
                                    report = report?.copy(hits = report!!.hits.map { if (it.id == hit.id) updated else it })
                                    onStatus("Runtime State: сохранено ${updated.key} = ${updated.value}; backup создан")
                                }
                                result.exceptionOrNull()?.let { onError(it.message) }
                                editing = false
                            }
                        },
                        enabled = hit.writable && editValue != hit.value && !editing && !busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Сохранить значение") }
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                editing = true
                                onError(null)
                                val result = runCatching {
                                    withContext(Dispatchers.IO) { RuntimeStateLabEngine.restore(context, hit.documentUri) }
                                }
                                result.onSuccess {
                                    onStatus("Runtime State: исходный файл восстановлен из backup")
                                    selected = null
                                    runSearch(false)
                                }.onFailure { onError(it.message) }
                                editing = false
                            }
                        },
                        enabled = RuntimeStateLabEngine.hasBackup(context, hit.documentUri) && !editing && !busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Восстановить исходный файл из backup") }
                    OutlinedButton(onClick = { selected = null }, enabled = !editing, modifier = Modifier.fillMaxWidth()) { Text("Назад к результатам") }
                }
            }
        }
    }
}
