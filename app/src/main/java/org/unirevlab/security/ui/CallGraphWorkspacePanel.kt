package org.unirevlab.security.ui

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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import org.unirevlab.security.analysis.DexCallGraph
import org.unirevlab.security.model.StaticAnalysisReport

@Composable
fun CallGraphWorkspacePanel(report: StaticAnalysisReport, onOpenFullReport: () -> Unit) {
    val dex = report.dex
    if (dex == null) {
        CallGraphInfoCard("DEX index отсутствует — Call Graph недоступен для этого объекта.")
        return
    }

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rootQuery by remember(report.artifact.sha256) { mutableStateOf("") }
    var targetQuery by remember(report.artifact.sha256) { mutableStateOf("") }
    var root by remember(report.artifact.sha256) { mutableStateOf<DexCallGraph.MethodNode?>(null) }
    var target by remember(report.artifact.sha256) { mutableStateOf<DexCallGraph.MethodNode?>(null) }
    var includeIncoming by remember(report.artifact.sha256) { mutableStateOf(false) }
    var status by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }

    val rootMatches = remember(rootQuery, dex.methods.size) {
        DexCallGraph.findMethods(dex, rootQuery, limit = 10)
    }
    val targetMatches = remember(targetQuery, dex.methods.size) {
        DexCallGraph.findMethods(dex, targetQuery, limit = 10)
    }

    val slice by produceState<DexCallGraph.Slice?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = root?.key,
        key3 = includeIncoming,
    ) {
        value = root?.let { selected ->
            withContext(Dispatchers.Default) {
                DexCallGraph.reachableSlice(
                    dex = dex,
                    roots = setOf(selected.key),
                    maxDepth = 4,
                    maxNodes = 350,
                    includeIncoming = includeIncoming,
                )
            }
        }
    }

    val path by produceState<DexCallGraph.Path?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = root?.key,
        key3 = target?.key,
    ) {
        value = if (root != null && target != null) {
            withContext(Dispatchers.Default) {
                DexCallGraph.shortestPath(
                    dex = dex,
                    start = requireNotNull(root).key,
                    target = requireNotNull(target).key,
                    maxDepth = 20,
                    maxVisited = 50_000,
                )
            }
        } else null
    }

    val exportDot = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val current = slice
        if (uri != null && current != null) {
            scope.launch {
                runCatching {
                    val dot = withContext(Dispatchers.Default) { DexCallGraph.toDot(current) }
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt")?.bufferedWriter()?.use { it.write(dot) }
                            ?: error("Не удалось открыть DOT для записи")
                    }
                }.onSuccess { status = "Call Graph DOT сохранён." }
                    .onFailure { status = "Ошибка DOT export: ${it.message ?: it.javaClass.simpleName}" }
            }
        }
    }

    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("DEX Call Graph Workspace", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "Навигация по уже собранным invoke-xrefs: локальный subgraph, callers/callees, кратчайший путь между методами и DOT export. Код целевого приложения не исполняется.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("Methods ${dex.methods.size} · call edges ${dex.callXrefs.size}", fontWeight = FontWeight.SemiBold)
        }
    }

    Text("1. Корневой метод", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
    OutlinedTextField(
        value = rootQuery,
        onValueChange = { rootQuery = it.take(180) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        label = { Text("Class / method / signature") },
    )
    rootMatches.take(8).forEach { node ->
        OutlinedButton(
            onClick = { root = node; rootQuery = node.signature },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(node.signature, style = MaterialTheme.typography.bodySmall) }
    }
    root?.let { selected ->
        CallGraphInfoCard("ROOT\n${selected.signature}\n${selected.key.dexEntry} · method_id=${selected.key.methodIndex}")
    }

    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = !includeIncoming,
            onClick = { includeIncoming = false },
            label = { Text("Callees") },
        )
        FilterChip(
            selected = includeIncoming,
            onClick = { includeIncoming = true },
            label = { Text("Callers + callees") },
        )
    }

    root?.let {
        when (val current = slice) {
            null -> CallGraphInfoCard("Строим bounded subgraph…")
            else -> {
                Text("Subgraph: ${current.nodes.size} nodes · ${current.edges.size} edges${if (current.truncated) " · truncated" else ""}", fontWeight = FontWeight.SemiBold)
                Button(
                    onClick = { exportDot.launch("unirevlab-callgraph-${report.artifact.sha256.take(8)}.dot") },
                    enabled = current.nodes.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Экспортировать Graphviz DOT") }
                current.nodes.take(40).forEachIndexed { index, node ->
                    Text("${index + 1}. ${node.signature}", style = MaterialTheme.typography.bodySmall)
                }
                if (current.nodes.size > 40) {
                    Text("… ещё ${current.nodes.size - 40} nodes; полный граф — в DOT.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    Text("2. Кратчайший путь", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
    OutlinedTextField(
        value = targetQuery,
        onValueChange = { targetQuery = it.take(180) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        label = { Text("Target class / method / signature") },
    )
    targetMatches.take(8).forEach { node ->
        OutlinedButton(
            onClick = { target = node; targetQuery = node.signature },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(node.signature, style = MaterialTheme.typography.bodySmall) }
    }
    target?.let { selected ->
        CallGraphInfoCard("TARGET\n${selected.signature}\n${selected.key.dexEntry} · method_id=${selected.key.methodIndex}")
    }

    if (root != null && target != null) {
        val currentPath = path
        if (currentPath == null) {
            CallGraphInfoCard("Путь в bounded call graph не найден в пределах depth=20 / visited=50000 либо ещё вычисляется.")
        } else {
            Text("Shortest path: ${currentPath.edges.size} calls", fontWeight = FontWeight.Bold)
            currentPath.nodes.forEachIndexed { index, node ->
                Text("${index + 1}. ${node.signature}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    status?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    OutlinedButton(onClick = onOpenFullReport, modifier = Modifier.fillMaxWidth()) {
        Text("Открыть полный RE Browser / Ghidra correlation")
    }
}

@Composable
private fun CallGraphInfoCard(text: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Text(text, modifier = Modifier.padding(13.dp), style = MaterialTheme.typography.bodySmall)
    }
}
