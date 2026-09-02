package org.unirevlab.security.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.unirevlab.security.R
import org.unirevlab.security.analysis.AnalysisRunState
import org.unirevlab.security.analysis.ProtectionPostureEngine
import org.unirevlab.security.analysis.SerializationInspector
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.StaticAnalysisReport

enum class ProductTool(
    val title: String,
    val subtitle: String,
    val badge: String,
) {
    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),
    MANIFEST("Manifest / IPC", "Permissions, exported components, providers, deep links", "APK"),
    DEX("DEX / Logic", "Methods, strings, xrefs, call graph and code index", "DEX"),
    SERIALIZATION("Serialization", "Serializable, Parcelable, JSON, Protobuf and object decoders", "DATA"),
    SIGNING("Signatures / Integrity", "APK signing schemes, certificates and self-check signals", "SIG"),
    NETWORK("Network Security", "Cleartext policy, Network Security Config and TLS pinning", "TLS"),
    NATIVE("Native / JNI", "ELF, JNI bridges, symbols and hardening", "JNI"),
    RUNTIME("Runtime / Game Engines", "IL2CPP, Unity Mono, Flutter, Hermes and Unreal", "RUN"),
    SUPPLY_CHAIN("SBOM / CVE", "Dependencies, native libraries and advisory matches", "SBOM"),
    RE_BROWSER("RE / Call Graph", "Cross-references, basic blocks and Ghidra correlation", "RE"),
    PATCH_LAB("Patch / Hook Lab", "Authorized trace, diff, rebuild and installability checks", "LAB"),
    FULL_REPORT("Full Technical Report", "All collected evidence, findings, exports and advanced views", "ALL"),
}

@Composable
fun ToolsHomeScreen(
    scope: AssessmentScope,
    report: StaticAnalysisReport?,
    analysisState: AnalysisRunState,
    isInspecting: Boolean,
    error: String?,
    onAnalyzeFile: () -> Unit,
    onAnalyzeInstalled: () -> Unit,
    onOpenTool: (ProductTool) -> Unit,
    onOpenFullReport: () -> Unit,
    onOpenPatchLab: () -> Unit,
    onOpenHelp: () -> Unit,
    onCancelAnalysis: () -> Unit,
    onNewAssessment: () -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ProductHeader(scope)

            FullAuditHero(
                report = report,
                analysisState = analysisState,
                isInspecting = isInspecting,
                onAnalyzeFile = onAnalyzeFile,
                onAnalyzeInstalled = onAnalyzeInstalled,
                onCancel = onCancelAnalysis,
            )

            error?.let {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                    Text("Ошибка: $it", modifier = Modifier.padding(14.dp), color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }

            report?.let { current ->
                LatestAssessmentCard(current)
                ProtectionSnapshot(current)
            }

            Text("Tools Dashboard", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                if (report == null) {
                    "Сначала выберите APK/пакет и запустите полный аудит. После этого каждый модуль откроется как отдельный инструмент по тем же собранным данным."
                } else {
                    "Отдельные инструменты используют единый индекс полного аудита — повторно сканировать APK для переключения разделов не нужно."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ProductTool.entries.chunked(2).forEach { rowTools ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    rowTools.forEach { tool ->
                        ToolCard(
                            tool = tool,
                            enabled = report != null,
                            modifier = Modifier.weight(1f),
                            onClick = {
                                when (tool) {
                                    ProductTool.FULL_REPORT -> onOpenFullReport()
                                    ProductTool.PATCH_LAB -> onOpenPatchLab()
                                    else -> onOpenTool(tool)
                                }
                            },
                        )
                    }
                    if (rowTools.size == 1) {
                        Column(Modifier.weight(1f)) { }
                    }
                }
            }

            HorizontalDivider()
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(onClick = onOpenHelp, modifier = Modifier.weight(1f)) { Text("Справка") }
                OutlinedButton(onClick = onNewAssessment, enabled = !isInspecting, modifier = Modifier.weight(1f)) { Text("Новый проект") }
            }
        }
    }
}

@Composable
private fun ProductHeader(scope: AssessmentScope) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = painterResource(R.drawable.unirevlab_logo),
            contentDescription = "UniRevLab Security",
            modifier = Modifier.size(64.dp),
        )
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text("UniRevLab Security", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(scope.projectName, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            Text(scope.organization, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun FullAuditHero(
    report: StaticAnalysisReport?,
    analysisState: AnalysisRunState,
    isInspecting: Boolean,
    onAnalyzeFile: () -> Unit,
    onAnalyzeInstalled: () -> Unit,
    onCancel: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Full Automatic APK Audit", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(
                "Один прогон: archive + Manifest + permissions/IPC + DEX/xrefs + protection matrix + serialization + Native/JNI + runtimes + IL2CPP + network security + signatures + SBOM/CVE + findings.",
                style = MaterialTheme.typography.bodyMedium,
            )

            when (analysisState) {
                is AnalysisRunState.Running -> {
                    Text("${analysisState.progress.stage.title} — ${analysisState.progress.percent}%", fontWeight = FontWeight.SemiBold)
                    LinearProgressIndicator(
                        progress = { analysisState.progress.percent / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(analysisState.progress.detail, style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("Отменить анализ") }
                }
                is AnalysisRunState.Cancelling -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Остановка анализа запрошена…", style = MaterialTheme.typography.bodySmall)
                }
                else -> {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = onAnalyzeFile, enabled = !isInspecting, modifier = Modifier.weight(1f)) {
                            Text(if (report == null) "APK / Bundle" else "Другой файл")
                        }
                        OutlinedButton(onClick = onAnalyzeInstalled, enabled = !isInspecting, modifier = Modifier.weight(1f)) {
                            Text("Установленное")
                        }
                    }
                    if (report != null) {
                        Text("Последний полный аудит готов. Ниже доступны отдельные инструменты.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun LatestAssessmentCard(report: StaticAnalysisReport) {
    val packageName = report.manifest?.packageName ?: report.artifact.sourcePackageName ?: "package не определён"
    val critical = report.findings.count { it.severity.name == "CRITICAL" }
    val high = report.findings.count { it.severity.name == "HIGH" }
    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("Последний объект", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(report.artifact.displayName, fontWeight = FontWeight.Bold)
            Text(packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Findings: ${report.findings.size} · Critical: $critical · High: $high", style = MaterialTheme.typography.bodySmall)
            Text("SHA-256 ${report.artifact.sha256.take(20)}…", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ProtectionSnapshot(report: StaticAnalysisReport) {
    val posture = remember(report.artifact.sha256, report.findings.size) { ProtectionPostureEngine.scan(report) }
    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Security Posture Snapshot", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Проверки приложения: есть ${posture.presentCount} · не обнаружено ${posture.notDetectedCount} · неизвестно ${posture.unknownCount}",
                style = MaterialTheme.typography.bodyMedium,
            )
            posture.checks.take(6).forEach { check ->
                Text("${statusLabel(check.status)}  ${check.title}", style = MaterialTheme.typography.bodySmall)
            }
            Text("Полная матрица — в инструменте Protection Matrix.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ToolCard(tool: ProductTool, enabled: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Card(
        modifier = modifier.clickable(enabled = enabled, onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (enabled) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text(tool.badge, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
            Text(tool.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(tool.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(if (enabled) "Открыть →" else "Нужен полный аудит", style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
fun ProductToolScreen(
    report: StaticAnalysisReport,
    tool: ProductTool,
    onBack: () -> Unit,
    onOpenPatchLab: () -> Unit,
    onOpenFullReport: () -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("← Tools Dashboard") }
            Text(tool.title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(tool.subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

            when (tool) {
                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)
                ProductTool.SERIALIZATION -> SerializationInspectorPanel(report)
                ProductTool.MANIFEST -> ManifestToolPanel(report)
                ProductTool.DEX -> DexToolPanel(report)
                ProductTool.SIGNING -> SigningToolPanel(report)
                ProductTool.NETWORK -> NetworkToolPanel(report)
                ProductTool.NATIVE -> NativeToolPanel(report)
                ProductTool.RUNTIME -> RuntimeToolPanel(report)
                ProductTool.SUPPLY_CHAIN -> SupplyChainToolPanel(report)
                ProductTool.RE_BROWSER -> ReverseEngineeringToolPanel(report, onOpenFullReport)
                ProductTool.PATCH_LAB -> Button(onClick = onOpenPatchLab, modifier = Modifier.fillMaxWidth()) { Text("Открыть Patch / Hook Lab") }
                ProductTool.FULL_REPORT -> Button(onClick = onOpenFullReport, modifier = Modifier.fillMaxWidth()) { Text("Открыть полный технический отчёт") }
            }
        }
    }
}

@Composable
private fun ProtectionMatrixPanel(report: StaticAnalysisReport) {
    val posture = remember(report.artifact.sha256, report.findings.size) { ProtectionPostureEngine.scan(report) }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Что именно проверяет приложение", fontWeight = FontWeight.Bold)
            Text(
                "Матрица отвечает на вопрос «есть ли в APK такая проверка». Она не утверждает, что текущий телефон рутован или что APK изменён: целевое приложение не запускается, а факт изменения требует доверенного baseline.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("DEX coverage: ${if (posture.dexCoverageComplete) "полный индекс" else "ограниченный/неполный"}", style = MaterialTheme.typography.bodySmall)
        }
    }
    posture.checks.forEach { check ->
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
}

@Composable
private fun SerializationInspectorPanel(report: StaticAnalysisReport) {
    val result = remember(report.artifact.sha256) { SerializationInspector.scan(report) }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Static Deserialization Inspector", fontWeight = FontWeight.Bold)
            Text(
                "Никакие объекты из APK не создаются и payload не исполняется. Инструмент ищет реальные decode/readObject/fromJson/parseFrom точки и связывает их с caller'ами.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("Frameworks: ${result.frameworks.size} · deserializers: ${result.deserializeCount} · serializers: ${result.serializeCount}")
            Text("High-risk: ${result.highRiskCount} · reachable from exported graph: ${result.externallyReachableCount}", style = MaterialTheme.typography.bodySmall)
        }
    }
    if (result.surfaces.isEmpty()) {
        Card {
            Text(
                if (result.coverageComplete) "Известные serialization/deserialization entry points в полном DEX-индексе не обнаружены." else "DEX coverage неполный — отсутствие десериализаторов не подтверждено.",
                modifier = Modifier.padding(14.dp),
            )
        }
    } else {
        result.surfaces.forEach { surface ->
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

@Composable
private fun ManifestToolPanel(report: StaticAnalysisReport) {
    val manifest = report.manifest
    if (manifest == null) {
        InfoCard("AndroidManifest metadata недоступны.")
        return
    }
    MetricCard("Package", manifest.packageName)
    MetricCard("SDK", "min ${manifest.minSdk ?: "?"} · target ${manifest.targetSdk ?: "?"}")
    MetricCard("Permissions", "${manifest.requestedPermissions.size} requested · ${manifest.dangerousPermissions.size} dangerous")
    MetricCard("Exported components", manifest.components.count { it.exported }.toString())
    MetricCard("Deep links", manifest.deepLinks.size.toString())
    MetricCard("Providers", manifest.providers.size.toString())
    manifest.components.filter { it.exported }.take(40).forEach {
        InfoCard("${it.kind}: ${it.name}\nexported=true${if (it.permissions.isNotEmpty()) "\npermissions=${it.permissions.joinToString()}" else ""}")
    }
}

@Composable
private fun DexToolPanel(report: StaticAnalysisReport) {
    val dex = report.dex
    if (dex == null) {
        InfoCard("DEX не обнаружен.")
        return
    }
    MetricCard("DEX files", "${dex.dexFilesScanned}/${dex.dexFilesDiscovered}")
    MetricCard("Methods", "${dex.methodsIndexed}/${dex.methodsDeclared}")
    MetricCard("Code bodies", dex.codeMethods.size.toString())
    MetricCard("Call xrefs", dex.callXrefs.size.toString())
    MetricCard("String xrefs", dex.stringXrefs.size.toString())
    MetricCard("Field / type xrefs", "${dex.fieldXrefs.size} / ${dex.typeXrefs.size}")
    MetricCard("Basic blocks", dex.basicBlocks.size.toString())
    InfoCard("HTTP URLs: ${dex.httpUrls.size} · HTTPS URLs: ${dex.httpsUrls.size} · secret candidates: ${dex.secretCandidates.size}\nParse errors: ${dex.parseErrors} · truncated=${dex.truncated}")
}

@Composable
private fun SigningToolPanel(report: StaticAnalysisReport) {
    val manifest = report.manifest
    if (manifest == null) {
        InfoCard("Signing metadata недоступны.")
        return
    }
    MetricCard("Signing schemes", manifest.signingSchemes.joinToString().ifBlank { "не определены" })
    MetricCard("Certificates", manifest.signingCertificates.size.toString())
    manifest.signingCertificates.take(10).forEach { cert ->
        InfoCard("SHA-256 ${cert.sha256}\n${cert.subjectDn ?: "subject unknown"}\n${cert.publicKeyAlgorithm ?: "key ?"} ${cert.publicKeySizeBits ?: "?"} bit")
    }
    val posture = remember(report.artifact.sha256) { ProtectionPostureEngine.scan(report) }
    posture.checks.filter { it.id in setOf("SIGNATURE_SELF_CHECK", "APK_SELF_INTEGRITY", "PLAY_INTEGRITY", "APK_SIGNATURE_STATE", "BASELINE_TAMPER_STATUS") }
        .forEach { check -> InfoCard("${statusLabel(check.status)} · ${check.title}\n${check.explanation}") }
}

@Composable
private fun NetworkToolPanel(report: StaticAnalysisReport) {
    val manifest = report.manifest
    if (manifest == null) {
        InfoCard("Network manifest metadata недоступны.")
        return
    }
    MetricCard("usesCleartextTraffic", manifest.usesCleartextTraffic.toString())
    MetricCard("Network Security Config", (manifest.networkSecurityConfigConfigured == true).toString())
    val network = manifest.networkSecurity
    if (network != null) {
        MetricCard("Pin set", network.pinSetPresent.toString())
        MetricCard("Debug overrides", network.debugOverridesPresent.toString())
        MetricCard("Trust anchors", network.trustAnchors.size.toString())
        MetricCard("Domain configs", network.domainConfigs.size.toString())
        network.domainConfigs.take(30).forEach { cfg ->
            InfoCard("domains=${cfg.domains.joinToString()}\nincludeSubdomains=${cfg.includeSubdomains}\ncleartext=${cfg.cleartextTrafficPermitted}")
        }
    }
    val pinning = remember(report.artifact.sha256) { ProtectionPostureEngine.scan(report) }.checks.first { it.id == "TLS_PINNING" }
    InfoCard("${statusLabel(pinning.status)} · ${pinning.title}\n${pinning.explanation}")
}

@Composable
private fun NativeToolPanel(report: StaticAnalysisReport) {
    val native = report.native
    if (native == null || native.libraries.isEmpty()) {
        InfoCard("Native ELF libraries не обнаружены.")
        return
    }
    MetricCard("Libraries", "${native.librariesScanned}/${native.librariesDiscovered}")
    MetricCard("JNI bridges", native.jniBridges.size.toString())
    native.libraries.take(30).forEach { lib ->
        InfoCard(
            "${lib.entryName} · ${lib.abi}\nRELRO=${lib.hasGnuRelro} · BIND_NOW=${lib.bindNow} · canary=${lib.hasStackCanaryImport} · execStack=${lib.executableStack}\nJNI symbols=${lib.jniSymbols.size} · imports=${lib.importedSymbols.size} · exports=${lib.exportedSymbols.size}",
        )
    }
}

@Composable
private fun RuntimeToolPanel(report: StaticAnalysisReport) {
    val profiles = report.runtimes?.profiles.orEmpty()
    MetricCard("Runtime profiles", profiles.size.toString())
    profiles.forEach { InfoCard("${it.kind} · ${it.confidence}\n${it.indicators.take(8).joinToString()}") }
    report.il2cpp?.let { MetricCard("IL2CPP", "detected=${it.detected} · confidence=${it.confidence} · libs=${it.libil2cppLibraries.size}") }
    report.runtimeArtifacts?.flutter?.let { MetricCard("Flutter", "detected=${it.detected} · confidence=${it.confidence}") }
    report.runtimeArtifacts?.hermes?.let { MetricCard("Hermes", "detected=${it.detected} · confidence=${it.confidence} · bytecode=${it.bytecodeFiles.size}") }
    report.runtimeArtifacts?.unityMono?.let { MetricCard("Unity Mono", "detected=${it.detected} · confidence=${it.confidence} · assemblies=${it.assemblies.size}") }
    report.runtimeArtifacts?.unreal?.let { MetricCard("Unreal", "detected=${it.detected} · confidence=${it.confidence} · containers=${it.containers.size}") }
}

@Composable
private fun SupplyChainToolPanel(report: StaticAnalysisReport) {
    val supply = report.supplyChain
    if (supply == null) {
        InfoCard("Supply-chain inventory недоступен.")
        return
    }
    MetricCard("Components", supply.components.size.toString())
    MetricCard("Native dependencies", supply.nativeDependencies.size.toString())
    MetricCard("Matched vulnerabilities", supply.vulnerabilities.size.toString())
    supply.vulnerabilities.take(40).forEach { vuln ->
        InfoCard("${vuln.severity} · ${vuln.advisoryId}\n${vuln.componentId} ${vuln.componentVersion}\n${vuln.summary}")
    }
    if (supply.vulnerabilities.isEmpty()) {
        supply.components.take(40).forEach { component -> InfoCard("${component.name} ${component.version ?: "?"}\n${component.ecosystem} · confidence=${component.confidence}") }
    }
}

@Composable
private fun ReverseEngineeringToolPanel(report: StaticAnalysisReport, onOpenFullReport: () -> Unit) {
    val dex = report.dex
    MetricCard("DEX call xrefs", dex?.callXrefs?.size?.toString() ?: "0")
    MetricCard("Basic blocks", dex?.basicBlocks?.size?.toString() ?: "0")
    MetricCard("Ghidra libraries", report.ghidra.size.toString())
    MetricCard("Cross-runtime correlations", report.correlations?.links?.size?.toString() ?: "0")
    InfoCard("Полный RE Browser, поиск xrefs, CallGraph и импорт Ghidra остаются в техническом отчёте. В следующем UI-шаге RE Browser будет вынесен в собственный полноэкранный workspace.")
    Button(onClick = onOpenFullReport, modifier = Modifier.fillMaxWidth()) { Text("Открыть RE Browser в полном отчёте") }
}

@Composable
private fun MetricCard(title: String, value: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Row(Modifier.fillMaxWidth().padding(13.dp), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(title, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            Text(value, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun InfoCard(text: String) {
    Card(shape = RoundedCornerShape(16.dp)) {
        Text(text, modifier = Modifier.padding(13.dp), style = MaterialTheme.typography.bodySmall)
    }
}

private fun statusLabel(status: ProtectionPostureEngine.Status): String = when (status) {
    ProtectionPostureEngine.Status.PRESENT -> "ЕСТЬ"
    ProtectionPostureEngine.Status.NOT_DETECTED -> "НЕ ОБНАРУЖЕНО"
    ProtectionPostureEngine.Status.UNKNOWN -> "НЕИЗВЕСТНО"
    ProtectionPostureEngine.Status.NOT_APPLICABLE -> "N/A"
}

@Composable
private fun statusColor(status: ProtectionPostureEngine.Status) = when (status) {
    ProtectionPostureEngine.Status.PRESENT -> MaterialTheme.colorScheme.primary
    ProtectionPostureEngine.Status.NOT_DETECTED -> MaterialTheme.colorScheme.secondary
    ProtectionPostureEngine.Status.UNKNOWN -> MaterialTheme.colorScheme.error
    ProtectionPostureEngine.Status.NOT_APPLICABLE -> MaterialTheme.colorScheme.onSurfaceVariant
}
