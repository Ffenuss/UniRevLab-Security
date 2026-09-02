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


def replace_function(text: str, start_marker: str, end_marker: str, replacement: str, label: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        if replacement.strip() in text:
            return text
        raise RuntimeError(f"{label}: start marker not found")
    end = text.find(end_marker, start + len(start_marker))
    if end < 0:
        raise RuntimeError(f"{label}: end marker not found")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:]


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    # Remove the old deobfuscation panel left behind after AutomaticDeobfuscationPanel became canonical.
    legacy_start = "@Composable\nprivate fun DeobfuscationToolPanel(report: StaticAnalysisReport) {"
    legacy_end = "@Composable\nprivate fun SigningToolPanel(report: StaticAnalysisReport) {"
    if legacy_start in text:
        start = text.index(legacy_start)
        end = text.index(legacy_end, start)
        text = text[:start] + text[end:]

    # Clean imports that only existed for the deleted legacy panel.
    for line in (
        "import android.content.ContentResolver\n",
        "import android.net.Uri\n",
        "import androidx.activity.compose.rememberLauncherForActivityResult\n",
        "import androidx.activity.result.contract.ActivityResultContracts\n",
        "import androidx.compose.runtime.mutableStateOf\n",
        "import androidx.compose.runtime.rememberCoroutineScope\n",
        "import androidx.compose.runtime.setValue\n",
        "import androidx.compose.ui.platform.LocalContext\n",
        "import org.unirevlab.security.analysis.DeobfuscationEngine\n",
        "import org.unirevlab.security.analysis.MappingDeobfuscator\n",
        "import kotlinx.coroutines.launch\n",
    ):
        text = text.replace(line, "")

    if "import androidx.compose.runtime.produceState\n" not in text:
        text = text.replace("import androidx.compose.runtime.remember\n", "import androidx.compose.runtime.remember\nimport androidx.compose.runtime.produceState\n", 1)
    if "import org.unirevlab.security.BuildConfig\n" not in text:
        text = text.replace("import org.unirevlab.security.R\n", "import org.unirevlab.security.R\nimport org.unirevlab.security.BuildConfig\n", 1)

    text = replace_once(
        text,
        '    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),\n',
        '    EXECUTIVE("Executive Summary", "Customer risk, coverage, attack surface and next actions", "EXEC"),\n'
        '    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),\n',
        "executive tool enum",
    )
    text = replace_once(
        text,
        "                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)\n",
        "                ProductTool.EXECUTIVE -> ExecutiveSummaryPanel(report)\n"
        "                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)\n",
        "executive tool route",
    )

    text = text.replace("Full Automatic APK Audit", "Полный автоматический аудит")
    text = text.replace("Tools Dashboard", "Инструменты")
    text = text.replace("Последний объект", "Последний анализ")
    text = text.replace(
        "Один прогон: archive + Manifest + permissions/IPC + DEX/xrefs + deobfuscation + protection matrix + serialization + Native/JNI + runtimes + IL2CPP + network security + signatures + SBOM/CVE + findings.",
        "Один прогон строит единый security index: archive, Manifest/IPC, DEX/xrefs, deobfuscation, protection matrix, serialization, Native/JNI, runtimes, IL2CPP, network security, signatures, SBOM/CVE и findings. После анализа автоматически доступен Executive Summary.",
    )
    text = text.replace('Text(if (report == null) "APK / Bundle" else "Другой файл")', 'Text(if (report == null) "Файл / APK / Bundle" else "Другой файл")')
    text = text.replace('Text("Установленное")', 'Text("Установленное приложение")')

    text = replace_once(
        text,
        '            Text(scope.organization, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)\n',
        '            Text(scope.organization, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)\n'
        '            Text("v${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)\n',
        "version in product header",
    )

    text = text.replace(
        '            Text("Findings: ${report.findings.size} · Critical: $critical · High: $high", style = MaterialTheme.typography.bodySmall)\n',
        '            Text("Риск: ${dashboardRiskLabel(report)} · находок ${report.findings.size} · Critical $critical · High $high", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)\n',
    )

    protection_snapshot = r'''@Composable
private fun ProtectionSnapshot(report: StaticAnalysisReport) {
    val posture by produceState<ProtectionPostureEngine.Posture?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.findings.size,
    ) {
        value = withContext(Dispatchers.Default) { ProtectionPostureEngine.scan(report) }
    }
    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Security Posture Snapshot", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            when (val current = posture) {
                null -> Text("Сводим root/debug/hook/signature/integrity сигналы…", style = MaterialTheme.typography.bodySmall)
                else -> {
                    Text(
                        "Проверки приложения: есть ${current.presentCount} · не обнаружено ${current.notDetectedCount} · неизвестно ${current.unknownCount}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    current.checks.take(6).forEach { check ->
                        Text("${statusLabel(check.status)}  ${check.title}", style = MaterialTheme.typography.bodySmall)
                    }
                    Text("Полная матрица — в инструменте Protection Matrix.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}'''
    text = replace_function(
        text,
        "@Composable\nprivate fun ProtectionSnapshot(report: StaticAnalysisReport) {",
        "@Composable\nprivate fun ToolCard(",
        protection_snapshot,
        "async protection snapshot",
    )

    # Dynamic tool cards show what the current APK actually contains instead of generic Open labels.
    text = text.replace(
        "                            enabled = report != null,\n                            modifier = Modifier.weight(1f),",
        "                            enabled = report != null,\n                            report = report,\n                            modifier = Modifier.weight(1f),",
    )
    text = text.replace(
        "private fun ToolCard(tool: ProductTool, enabled: Boolean, modifier: Modifier, onClick: () -> Unit) {",
        "private fun ToolCard(tool: ProductTool, enabled: Boolean, report: StaticAnalysisReport?, modifier: Modifier, onClick: () -> Unit) {",
    )
    text = text.replace(
        '            Text(if (enabled) "Открыть →" else "Нужен полный аудит", style = MaterialTheme.typography.labelMedium)\n',
        '            Text(\n'
        '                if (enabled && report != null) productToolMetric(tool, report) else "Нужен полный аудит",\n'
        '                style = MaterialTheme.typography.labelMedium,\n'
        '                color = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,\n'
        '            )\n',
    )

    protection_matrix = r'''@Composable
private fun ProtectionMatrixPanel(report: StaticAnalysisReport) {
    val posture by produceState<ProtectionPostureEngine.Posture?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.findings.size,
    ) {
        value = withContext(Dispatchers.Default) { ProtectionPostureEngine.scan(report) }
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Что именно проверяет приложение", fontWeight = FontWeight.Bold)
            Text(
                "Матрица отвечает на вопрос «есть ли в APK такая проверка». Она не утверждает, что текущий телефон рутован или что APK изменён: целевое приложение не запускается, а факт изменения требует доверенного baseline.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val current = posture) {
                null -> Text("Строим матрицу защит…", style = MaterialTheme.typography.bodySmall)
                else -> Text("DEX coverage: ${if (current.dexCoverageComplete) "полный индекс" else "ограниченный/неполный"}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    posture?.checks?.forEach { check ->
        Card(shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(check.title, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                    Text(statusLabel(check.status), color = statusColor(check.status), fontWeight = FontWeight.Bold)
                }
                Text("Confidence: ${check.confidence}", style = MaterialTheme.typography.labelSmall)
                Text(check.explanation, style = MaterialTheme.typography.bodySmall)
                check.evidence.take(5).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}'''
    text = replace_function(
        text,
        "@Composable\nprivate fun ProtectionMatrixPanel(report: StaticAnalysisReport) {",
        "@Composable\nprivate fun SerializationInspectorPanel(report: StaticAnalysisReport) {",
        protection_matrix,
        "async protection matrix",
    )

    serialization_panel = r'''@Composable
private fun SerializationInspectorPanel(report: StaticAnalysisReport) {
    val result by produceState<SerializationInspector.Report?>(
        initialValue = null,
        key1 = report.artifact.sha256,
    ) {
        value = withContext(Dispatchers.Default) { SerializationInspector.scan(report) }
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Static Deserialization Inspector", fontWeight = FontWeight.Bold)
            Text(
                "Никакие объекты из APK не создаются и payload не исполняется. Инструмент ищет реальные decode/readObject/fromJson/parseFrom точки и связывает их с caller'ами.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (val current = result) {
                null -> Text("Индексируем serialization/deserialization surfaces…", style = MaterialTheme.typography.bodySmall)
                else -> {
                    Text("Frameworks: ${current.frameworks.size} · deserializers: ${current.deserializeCount} · serializers: ${current.serializeCount}")
                    Text("High-risk: ${current.highRiskCount} · reachable from exported graph: ${current.externallyReachableCount}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    result?.let { current ->
        if (current.surfaces.isEmpty()) {
            Card {
                Text(
                    if (current.coverageComplete) "Известные serialization/deserialization entry points в полном DEX-индексе не обнаружены." else "DEX coverage неполный — отсутствие десериализаторов не подтверждено.",
                    modifier = Modifier.padding(14.dp),
                )
            }
        } else {
            current.surfaces.forEach { surface ->
                Card(shape = RoundedCornerShape(16.dp)) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("${surface.framework} · ${surface.direction} · ${surface.risk}", fontWeight = FontWeight.SemiBold)
                        Text("Caller: ${surface.caller}", style = MaterialTheme.typography.bodySmall)
                        Text("Callee: ${surface.callee}", style = MaterialTheme.typography.bodySmall)
                        if (surface.externallyReachable) Text("Reachability: возможно достижим из exported component graph", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        Text(surface.reason, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}'''
    text = replace_function(
        text,
        "@Composable\nprivate fun SerializationInspectorPanel(report: StaticAnalysisReport) {",
        "@Composable\nprivate fun ManifestToolPanel(report: StaticAnalysisReport) {",
        serialization_panel,
        "async serialization panel",
    )

    helper = r'''
private fun dashboardRiskLabel(report: StaticAnalysisReport): String = when {
    report.findings.any { it.severity.name == "CRITICAL" } -> "CRITICAL"
    report.findings.any { it.severity.name == "HIGH" } -> "HIGH"
    report.findings.any { it.severity.name == "MEDIUM" } -> "MEDIUM"
    report.findings.any { it.severity.name == "LOW" } -> "LOW"
    report.findings.isNotEmpty() -> "INFO"
    else -> "NO RULE-BASED FINDINGS"
}

private fun productToolMetric(tool: ProductTool, report: StaticAnalysisReport): String {
    val manifest = report.manifest
    val dex = report.dex
    return when (tool) {
        ProductTool.EXECUTIVE -> "Риск ${dashboardRiskLabel(report)} · coverage + next actions →"
        ProductTool.PROTECTION -> "Root · debug · hook · signature · integrity →"
        ProductTool.DIAGNOSTICS -> "DEX errors ${dex?.parseErrors ?: 0} · native errors ${report.native?.parseErrors ?: 0} →"
        ProductTool.FINDINGS -> {
            val critical = report.findings.count { it.severity.name == "CRITICAL" }
            val high = report.findings.count { it.severity.name == "HIGH" }
            "C $critical · H $high · всего ${report.findings.size} →"
        }
        ProductTool.MANIFEST -> "Exported ${manifest?.components?.count { it.exported } ?: 0} · deep links ${manifest?.deepLinks?.size ?: 0} →"
        ProductTool.DEX -> "Methods ${dex?.methodsIndexed ?: 0} · call xrefs ${dex?.callXrefs?.size ?: 0} →"
        ProductTool.DEOBFUSCATION -> {
            val shortNames = dex?.methods?.count { it.name.length <= 2 } ?: 0
            "Opaque/short methods $shortNames · auto mapping →"
        }
        ProductTool.SERIALIZATION -> "Inspect ${dex?.callXrefs?.size ?: 0} call xrefs for decoders →"
        ProductTool.SIGNING -> "Schemes ${manifest?.signingSchemes?.joinToString()?.ifBlank { "?" } ?: "?"} · certs ${manifest?.signingCertificates?.size ?: 0} →"
        ProductTool.NETWORK -> "Cleartext ${if (manifest?.usesCleartextTraffic == true) "YES" else "NO"} · pin-set ${manifest?.networkSecurity?.pinSetPresent ?: false} →"
        ProductTool.NATIVE -> "Libraries ${report.native?.librariesScanned ?: 0} · JNI ${report.native?.jniBridges?.size ?: 0} →"
        ProductTool.RUNTIME -> "Profiles ${report.runtimes?.profiles?.size ?: 0} · IL2CPP ${report.il2cpp?.detected ?: false} →"
        ProductTool.SUPPLY_CHAIN -> "Components ${report.supplyChain?.components?.size ?: 0} · advisories ${report.supplyChain?.vulnerabilities?.size ?: 0} →"
        ProductTool.RE_BROWSER -> "Call edges ${dex?.callXrefs?.size ?: 0} · blocks ${dex?.basicBlocks?.size ?: 0} →"
        ProductTool.PATCH_LAB -> "Trace · diff · rebuild · installability →"
        ProductTool.FULL_REPORT -> "${report.findings.size} findings · полный evidence/export →"
    }
}
'''
    if "private fun dashboardRiskLabel(" not in text:
        anchor = "private fun statusLabel(status: ProtectionPostureEngine.Status): String = when (status) {"
        if anchor not in text:
            raise RuntimeError("product metric helper anchor not found")
        text = text.replace(anchor, helper + "\n" + anchor, 1)

    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.28.0 product polish applied")
    else:
        print("v0.28.0 product polish already present")


if __name__ == "__main__":
    main()
