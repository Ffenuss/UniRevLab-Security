package org.unirevlab.security.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.model.InstalledAppDescriptor

@Composable
fun InstalledAppsScreen(
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
        Column(Modifier.fillMaxSize().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Установленные приложения", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("base.apk и split APK анализируются как единый пакет без запуска приложения.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(200) },
                label = { Text("Название или package name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = includeSystem, onCheckedChange = { includeSystem = it })
                Text("Показывать системные приложения")
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) { Text("Назад") }
                Button(onClick = onReload, enabled = !isLoading, modifier = Modifier.weight(1f)) {
                    Text(if (isLoading) "Загрузка…" else "Обновить")
                }
            }
            if (error != null) Text("Ошибка: $error", color = MaterialTheme.colorScheme.error)
            Text("Найдено: ${filtered.size} из ${apps.size}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
            LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(filtered, key = { it.packageName }) { app ->
                    Card(
                        Modifier.fillMaxWidth().clickable(enabled = !isLoading) { onSelect(app) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.62f)),
                    ) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(app.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                            Text("Версия: ${app.versionName ?: "—"} (${app.versionCode})")
                            Text("APK: ${app.apkCount}${if (app.splitApkPaths.isNotEmpty()) " · split=${app.splitApkPaths.size}" else ""}")
                            Text(if (app.isSystem) "Системное приложение" else "Пользовательское приложение", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            app.installerPackageName?.let { Text("Installer: $it", style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
        }
    }
}
