package org.unirevlab.security.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Switch
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.unirevlab.security.model.InstalledAppDescriptor

@Composable
fun InstalledAppsScreen(
    language: AppLanguage,
    apps: List<InstalledAppDescriptor>,
    isLoading: Boolean,
    error: String?,
    onBack: () -> Unit,
    onReload: () -> Unit,
    onSelect: (InstalledAppDescriptor) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var includeSystem by remember { mutableStateOf(false) }
    val filtered = remember(apps, query, includeSystem) {
        val q = query.trim().lowercase()
        apps.filter { app ->
            (includeSystem || !app.isSystem) &&
                (q.isBlank() || app.label.lowercase().contains(q) || app.packageName.lowercase().contains(q))
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(language.text("Установленные приложения", "Installed applications"), style = MaterialTheme.typography.headlineMedium)
            Text(language.text("Выберите пакет. UniRevLab автоматически обработает base и все split APK, не запуская приложение.", "Select a package. UniRevLab automatically processes the base and every split APK without executing the application."))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(language.text("Поиск по названию или имени пакета", "Search by label or package name")) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(language.text("Показывать системные приложения", "Show system applications"), modifier = Modifier.weight(1f))
                Switch(checked = includeSystem, onCheckedChange = { includeSystem = it })
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onBack) { Text(language.text("Назад", "Back")) }
                Button(onClick = onReload, enabled = !isLoading) { Text(if (isLoading) language.text("Загрузка…", "Loading…") else language.text("Обновить", "Refresh")) }
            }
            if (error != null) Text("${language.text("Ошибка", "Error")}: $error", color = MaterialTheme.colorScheme.error)
            Text(language.text("Найдено: ${filtered.size} из ${apps.size}", "Found: ${filtered.size} of ${apps.size}"), style = MaterialTheme.typography.bodySmall)
            LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(filtered, key = { it.packageName }) { app ->
                    Card(
                        Modifier.fillMaxWidth().clickable(enabled = !isLoading) { onSelect(app) }
                    ) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(app.label, style = MaterialTheme.typography.titleMedium)
                            Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                            Text(language.text("Версия: ${app.versionName ?: "—"} (${app.versionCode})", "Version: ${app.versionName ?: "—"} (${app.versionCode})"))
                            Text("APK: ${app.apkCount}${if (app.splitApkPaths.isNotEmpty()) " · split=${app.splitApkPaths.size}" else ""}")
                            Text(if (app.isSystem) language.text("Системное", "System") else language.text("Пользовательское", "User"), style = MaterialTheme.typography.bodySmall)
                            app.installerPackageName?.let { Text("Installer: $it", style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
        }
    }
}
