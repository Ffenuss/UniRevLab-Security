#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def insert_after(text: str, anchor: str, addition: str, label: str) -> str:
    if addition.strip() in text:
        return text
    if anchor not in text:
        raise RuntimeError(f"{label}: anchor not found")
    return text.replace(anchor, anchor + addition, 1)


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    text = insert_after(
        text,
        "package org.unirevlab.security.ui\n\n",
        "import android.content.ContentResolver\n"
        "import android.net.Uri\n",
        "Android imports",
    )
    text = insert_after(
        text,
        "import androidx.compose.foundation.verticalScroll\n",
        "import androidx.activity.compose.rememberLauncherForActivityResult\n"
        "import androidx.activity.result.contract.ActivityResultContracts\n",
        "activity result imports",
    )
    text = insert_after(
        text,
        "import androidx.compose.runtime.Composable\n",
        "import androidx.compose.runtime.getValue\n"
        "import androidx.compose.runtime.mutableStateOf\n",
        "compose state imports 1",
    )
    text = insert_after(
        text,
        "import androidx.compose.runtime.remember\n",
        "import androidx.compose.runtime.setValue\n",
        "compose state imports 2",
    )
    text = insert_after(
        text,
        "import androidx.compose.ui.Modifier\n",
        "import androidx.compose.ui.platform.LocalContext\n",
        "LocalContext import",
    )
    text = insert_after(
        text,
        "import org.unirevlab.security.analysis.AnalysisRunState\n",
        "import org.unirevlab.security.analysis.DeobfuscationEngine\n"
        "import org.unirevlab.security.analysis.MappingDeobfuscator\n",
        "deobfuscation imports",
    )

    text = replace_once(
        text,
        '    DEX("DEX / Logic", "Methods, strings, xrefs, call graph and code index", "DEX"),\n',
        '    DEX("DEX / Logic", "Methods, strings, xrefs, call graph and code index", "DEX"),\n'
        '    DEOBFUSCATION("Deobfuscation", "Obfuscation score, semantic aliases and R8 mapping", "DEOB"),\n',
        "deobfuscation tool enum",
    )

    text = text.replace(
        "DEX/xrefs + protection matrix + serialization + Native/JNI",
        "DEX/xrefs + deobfuscation + protection matrix + serialization + Native/JNI",
    )

    text = replace_once(
        text,
        "                ProductTool.DEX -> DexToolPanel(report)\n",
        "                ProductTool.DEX -> DexToolPanel(report)\n"
        "                ProductTool.DEOBFUSCATION -> DeobfuscationToolPanel(report)\n",
        "deobfuscation tool route",
    )

    panel = r'''
@Composable
private fun DeobfuscationToolPanel(report: StaticAnalysisReport) {
    val context = LocalContext.current
    val heuristic = remember(report.artifact.sha256) { DeobfuscationEngine.analyze(report) }
    var mapping by remember(report.artifact.sha256) { mutableStateOf<DeobfuscationEngine.MappingSummary?>(null) }
    var mappingError by remember(report.artifact.sha256) { mutableStateOf<String?>(null) }
    val mappingPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                val text = readMappingTextBounded(context.contentResolver, uri)
                DeobfuscationEngine.parseMapping(text)
            }.onSuccess {
                mapping = it
                mappingError = null
            }.onFailure {
                mapping = null
                mappingError = it.message ?: it.javaClass.simpleName
            }
        }
    }
    val exactAliases = remember(report.artifact.sha256, mapping) {
        mapping?.let { MappingDeobfuscator.resolve(report, it) }.orEmpty()
    }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Static Deobfuscation", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Сначала оцениваем степень обфускации, затем строим неразрушающие semantic aliases по DEX xrefs/API/строкам. Это рабочие имена для анализа, а не утверждение о восстановлении исходных названий.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Obfuscation score: ${heuristic.score}/100 · ${if (heuristic.likelyObfuscated) "вероятно обфусцировано" else "сильная обфускация не подтверждена"}",
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "Classes: ${heuristic.obfuscatedClasses}/${heuristic.classesAnalyzed} · methods: ${heuristic.obfuscatedMethods}/${heuristic.methodsAnalyzed} · opaque strings: ${heuristic.opaqueStringIndicators}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "DEX coverage: ${if (heuristic.coverageComplete) "полный индекс" else "ограниченный/неполный"}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }

    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("R8 / ProGuard mapping.txt", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Если заказчик предоставляет mapping.txt своей релизной сборки, UniRevLab сопоставляет его с DEX и показывает точные исходные имена классов/методов/полей.",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = { mappingPicker.launch(arrayOf("text/plain", "application/octet-stream", "*/*")) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Импортировать mapping.txt") }
            mappingError?.let { Text("Ошибка mapping.txt: $it", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            mapping?.let { parsed ->
                Text(
                    "Parsed: classes ${parsed.classes.size} · members ${parsed.members.size} · exact DEX matches ${exactAliases.size} · errors ${parsed.parseErrors}${if (parsed.truncated) " · truncated" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                )
                exactAliases.take(80).forEach { alias ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Column(Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("${alias.kind} · EXACT", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
                            Text(alias.obfuscatedSymbol, style = MaterialTheme.typography.bodySmall)
                            Text("→ ${alias.originalSymbol}", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }
    }

    Text("Semantic aliases", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
    if (heuristic.aliases.isEmpty()) {
        InfoCard("Надёжные semantic aliases по текущему DEX-индексу не выведены. Это лучше, чем придумывать названия без достаточного evidence.")
    } else {
        heuristic.aliases.forEach { alias ->
            Card(shape = RoundedCornerShape(16.dp)) {
                Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${alias.kind} · ${alias.confidence}", fontWeight = FontWeight.SemiBold)
                    Text(alias.original, style = MaterialTheme.typography.bodySmall)
                    Text("→ ${alias.suggestedAlias}", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
                    alias.reasons.take(3).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}

private fun readMappingTextBounded(resolver: ContentResolver, uri: Uri): String {
    val reader = resolver.openInputStream(uri)?.bufferedReader()
        ?: error("Не удалось открыть mapping.txt")
    reader.use {
        val out = StringBuilder()
        val buffer = CharArray(8192)
        while (true) {
            val read = it.read(buffer)
            if (read < 0) break
            require(out.length + read <= MAX_MAPPING_TEXT_CHARS) {
                "mapping.txt слишком большой: лимит ${MAX_MAPPING_TEXT_CHARS / 1_000_000} MB текста"
            }
            out.append(buffer, 0, read)
        }
        return out.toString()
    }
}

private const val MAX_MAPPING_TEXT_CHARS = 4_000_000

'''
    if "private fun DeobfuscationToolPanel" not in text:
        anchor = "@Composable\nprivate fun SigningToolPanel(report: StaticAnalysisReport) {\n"
        if anchor not in text:
            raise RuntimeError("deobfuscation panel anchor not found")
        text = text.replace(anchor, panel + anchor, 1)

    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.26.4 deobfuscation UI applied")
    else:
        print("v0.26.4 deobfuscation UI already present")


if __name__ == "__main__":
    main()
