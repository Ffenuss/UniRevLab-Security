package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

internal data class PatchMethodChoice(
    val name: String,
    val prototype: String,
) {
    val label: String get() = "$name$prototype"
}

@Composable
internal fun PatchStringPickerDialog(
    title: String,
    items: List<String>,
    selected: String?,
    onDismiss: () -> Unit,
    onSelect: (String) -> Unit,
    searchLabel: String = "Поиск",
) {
    var query by remember(title, items) { mutableStateOf("") }
    val filtered = remember(items, query) {
        val q = query.trim()
        if (q.isBlank()) items else items.filter { it.contains(q, ignoreCase = true) }
    }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize().padding(10.dp), tonalElevation = 3.dp) {
            Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(title, fontWeight = FontWeight.Bold)
                        Text("Показано ${filtered.size} из ${items.size}", style = MaterialTheme.typography.bodySmall)
                    }
                    OutlinedButton(onClick = onDismiss) { Text("Закрыть") }
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it.take(240) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text(searchLabel) },
                )
                HorizontalDivider()
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(filtered, key = { it }) { item ->
                        val isSelected = item == selected
                        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (isSelected) 0.72f else 0.38f))) {
                            Button(
                                onClick = { onSelect(item) },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(if (isSelected) "✓ $item" else item, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun PatchMethodPickerDialog(
    methods: List<PatchMethodChoice>,
    selectedName: String?,
    selectedPrototype: String?,
    onDismiss: () -> Unit,
    onSelect: (PatchMethodChoice) -> Unit,
) {
    var query by remember(methods) { mutableStateOf("") }
    val filtered = remember(methods, query) {
        val q = query.trim()
        if (q.isBlank()) methods else methods.filter { it.label.contains(q, ignoreCase = true) }
    }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize().padding(10.dp), tonalElevation = 3.dp) {
            Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text("Методы класса", fontWeight = FontWeight.Bold)
                        Text("Показано ${filtered.size} из ${methods.size}", style = MaterialTheme.typography.bodySmall)
                    }
                    OutlinedButton(onClick = onDismiss) { Text("Закрыть") }
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it.take(240) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Поиск метода / prototype") },
                )
                HorizontalDivider()
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(filtered, key = { it.label }) { method ->
                        val selected = method.name == selectedName && method.prototype == selectedPrototype
                        Button(onClick = { onSelect(method) }, modifier = Modifier.fillMaxWidth()) {
                            Text(if (selected) "✓ ${method.label}" else method.label, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }
        }
    }
}
