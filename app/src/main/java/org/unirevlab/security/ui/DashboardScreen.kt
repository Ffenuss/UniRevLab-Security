package org.unirevlab.security.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.produceState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.unirevlab.security.R
import org.unirevlab.security.analysis.ReBrowserIndex
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.AssessmentDiff
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.DexReIndex
import org.unirevlab.security.model.NativeReIndex
import org.unirevlab.security.model.GhidraReIndex
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.RuntimeSummary
import org.unirevlab.security.model.RuntimeArtifactSummary
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.model.SupplyChainSummary

@Composable
fun DashboardScreen(
    scope: AssessmentScope,
    report: StaticAnalysisReport?,
    comparison: AssessmentDiff?,
    isInspecting: Boolean,
    error: String?,
    onPickArtifact: () -> Unit,
    onPickInstalledApp: () -> Unit,
    onOpenHelp: () -> Unit,
    onCancelAnalysis: () -> Unit,
    onImportGhidraResults: () -> Unit,
    onImportAdvisoryFeed: () -> Unit,
    coordinatorSyncStatus: String?,
    onSyncCoordinator: (String, String) -> Unit,
    onSaveReport: () -> Unit,
    onSaveCycloneDx: () -> Unit,
    onSaveSpdx: () -> Unit,
    onNewAssessment: () -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            DashboardHeader(scope)

            Text("Быстрые действия", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionCard(
                    number = "01",
                    title = "Анализ файла",
                    subtitle = "APK / AAB / APKS / XAPK",
                    buttonText = if (isInspecting) "Анализ…" else "Выбрать файл",
                    enabled = !isInspecting,
                    onClick = onPickArtifact,
                    modifier = Modifier.weight(1f),
                )
                ActionCard(
                    number = "02",
                    title = "Установленное",
                    subtitle = "base.apk + split APK",
                    buttonText = "Выбрать пакет",
                    enabled = !isInspecting,
                    onClick = onPickInstalledApp,
                    modifier = Modifier.weight(1f),
                )
            }
            OutlinedButton(onClick = onOpenHelp, modifier = Modifier.fillMaxWidth()) {
                Text("?  Справка и функции — что делает каждая кнопка")
            }

            if (isInspecting) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)),
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Анализ выполняется", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Text(
                            "DEX/native задачи выполняются ограниченно параллельно; повторно доступные факты переиспользуются по SHA-256.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedButton(onClick = onCancelAnalysis, modifier = Modifier.fillMaxWidth()) {
                            Text("Отменить анализ")
                        }
                    }
                }
            }

            if (error != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.error.copy(alpha = 0.12f)),
                ) {
                    Text("Ошибка: $error", modifier = Modifier.padding(14.dp), color = MaterialTheme.colorScheme.error)
                }
            }

            if (report != null) {
                Text("Результаты", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                var selectedSection by remember(report.artifact.sha256) { mutableStateOf(ResultSection.OVERVIEW) }
                ResultSectionSelector(selectedSection) { selectedSection = it }
                when (selectedSection) {
                    ResultSection.OVERVIEW -> {
                        ArtifactCard(report.artifact)
                        OverviewCard(report)
                    }
                    ResultSection.MANIFEST -> report.manifest?.let { ManifestCard(it) }
                        ?: Text("Manifest metadata недоступны для этого артефакта.")
                    ResultSection.DEX -> report.dex?.let {
                        DexCard(it)
                        DexSearchCard(it)
                    } ?: Text("DEX не обнаружен.")
                    ResultSection.RE_BROWSER -> ReBrowserSection(report)
                    ResultSection.DIFF -> comparison?.let { AssessmentDiffCard(it) }
                        ?: Text("Для сравнения проанализируйте вторую версию того же package в рамках текущего Assessment.")
                    ResultSection.NATIVE -> {
                        report.native?.let {
                            NativeCard(it)
                            NativeSearchCard(it)
                        } ?: Text("Native ELF libraries не обнаружены.")
                        report.il2cpp?.let { Il2CppCard(it) }
                    }
                    ResultSection.RUNTIME -> {
                        report.runtimes?.let { RuntimeProfilesCard(it) } ?: Text("Специализированный runtime не определён.")
                        report.runtimeArtifacts?.let { RuntimeArtifactsCard(it) }
                    }
                    ResultSection.SUPPLY_CHAIN -> report.supplyChain?.let { SupplyChainCard(it) }
                        ?: Text("Supply-chain inventory недоступен.")
                    ResultSection.FINDINGS -> FindingsSection(report.findings)
                }

                Text("Дополнительные инструменты", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                if (scope.reverseEngineering) {
                    OutlinedButton(onClick = onImportGhidraResults, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {
                        Text("Импортировать Ghidra result JSON")
                    }
                }
                OutlinedButton(onClick = onImportAdvisoryFeed, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {
                    Text("Импортировать advisory feed JSON")
                }

                CoordinatorCard(
                    isInspecting = isInspecting,
                    status = coordinatorSyncStatus,
                    onSync = onSyncCoordinator,
                )

                Text("Экспорт", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                OutlinedButton(onClick = onSaveReport, modifier = Modifier.fillMaxWidth()) {
                    Text("JSON — полный детерминированный отчёт")
                }
                OutlinedButton(onClick = onSaveCycloneDx, modifier = Modifier.fillMaxWidth()) {
                    Text("CycloneDX 1.6 — SBOM")
                }
                OutlinedButton(onClick = onSaveSpdx, modifier = Modifier.fillMaxWidth()) {
                    Text("SPDX 3.0.1 — JSON-LD")
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
                ) {
                    Text(
                        "Целевой APK не запускается. Manifest, DEX, native, runtime и supply-chain данные анализируются статически; тяжёлые RE-индексы формируются вне UI-потока.",
                        modifier = Modifier.padding(14.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            HorizontalDivider()
            OutlinedButton(onClick = onNewAssessment, modifier = Modifier.fillMaxWidth()) {
                Text("Новый Assessment")
            }
        }
    }
}

@Composable
private fun DashboardHeader(scope: AssessmentScope) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.72f)),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Image(
                painter = painterResource(R.drawable.unirevlab_logo),
                contentDescription = "UniRevLab Security",
                modifier = Modifier.size(70.dp),
            )
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text("UniRevLab Security", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(scope.projectName, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                Text("${scope.organization} · ${scope.modesLabel()}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (scope.purpose.isNotBlank()) Text(scope.purpose, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ActionCard(
    number: String,
    title: String,
    subtitle: String,
    buttonText: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.62f)),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(number, color = MaterialTheme.colorScheme.secondary, fontWeight = FontWeight.Bold)
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text(buttonText) }
        }
    }
}

@Composable
private fun CoordinatorCard(
    isInspecting: Boolean,
    status: String?,
    onSync: (String, String) -> Unit,
) {
    var coordinatorUrl by remember { mutableStateOf("") }
    var coordinatorApiKey by remember { mutableStateOf("") }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Self-hosted Coordinator", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            OutlinedTextField(
                value = coordinatorUrl,
                onValueChange = { coordinatorUrl = it.take(2048) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Coordinator URL") },
                supportingText = { Text("HTTPS; localhost/emulator допускается для лаборатории") },
            )
            OutlinedTextField(
                value = coordinatorApiKey,
                onValueChange = { coordinatorApiKey = it.take(512) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                label = { Text("API key") },
            )
            Button(
                onClick = { onSync(coordinatorUrl, coordinatorApiKey) },
                enabled = !isInspecting && coordinatorUrl.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Синхронизировать Assessment / Ghidra") }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary) }
        }
    }
}

private enum class ResultSection(val label: String) {
    OVERVIEW("Обзор"),
    MANIFEST("Manifest"),
    DEX("DEX"),
    RE_BROWSER("RE Browser"),
    DIFF("Version diff"),
    NATIVE("Native"),
    RUNTIME("Runtime"),
    SUPPLY_CHAIN("SBOM"),
    FINDINGS("Findings"),
}

@Composable
private fun ResultSectionSelector(selected: ResultSection, onSelect: (ResultSection) -> Unit) {
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ResultSection.entries.forEach { section ->
            if (section == selected) {
                Button(onClick = { onSelect(section) }) { Text(section.label) }
            } else {
                OutlinedButton(onClick = { onSelect(section) }) { Text(section.label) }
            }
        }
    }
}

@Composable
private fun OverviewCard(report: StaticAnalysisReport) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Security overview", style = MaterialTheme.typography.titleLarge)
            Metric("Findings", report.findings.size.toString())
            Metric("Critical", report.findings.count { it.severity.name == "CRITICAL" }.toString())
            Metric("High", report.findings.count { it.severity.name == "HIGH" }.toString())
            Metric("Medium", report.findings.count { it.severity.name == "MEDIUM" }.toString())
            Metric("DEX methods", report.dex?.methodsIndexed?.toString() ?: "—")
            Metric("Native libraries", report.native?.librariesScanned?.toString() ?: "—")
            Metric("Dependencies", report.supplyChain?.components?.size?.toString() ?: "—")
            val profiles = report.runtimes?.profiles.orEmpty().joinToString { it.kind }
            Metric("Runtime", profiles.ifBlank { "standard Android / unknown" })
        }
    }
}

@Composable
private fun ArtifactCard(artifact: ArtifactSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Artifact fingerprint", style = MaterialTheme.typography.titleLarge)
            Metric("Источник", if (artifact.sourceKind == "INSTALLED_APP") "Установленное приложение" else "Файл")
            Metric("Файл / приложение", artifact.displayName)
            artifact.sourcePackageName?.let { Metric("Package", it) }
            artifact.sourceInstallerPackageName?.let { Metric("Installer", it) }
            if (artifact.splitApkCount > 0) Metric("Split APK", artifact.splitApkCount.toString())
            Metric("Размер", artifact.sizeBytes?.let(::formatBytes) ?: "неизвестно")
            Metric("SHA-256", artifact.sha256)
            Metric("Архивных записей", artifact.archiveEntries?.toString() ?: "не ZIP/APK")
            Metric("DEX", artifact.dexFiles?.toString() ?: "—")
            Metric("Native .so", artifact.nativeLibraries?.toString() ?: "—")
            Metric("AndroidManifest.xml", artifact.hasAndroidManifest?.toString() ?: "—")
            Metric("Опасные archive paths", artifact.suspiciousArchivePaths?.toString() ?: "—")
            if (artifact.truncatedArchiveScan) {
                Text("Скан списка файлов остановлен по защитному лимиту.", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun ManifestCard(manifest: ManifestSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Android manifest", style = MaterialTheme.typography.titleLarge)
            Metric("Package", manifest.packageName)
            Metric("Version", "${manifest.versionName ?: "—"} (${manifest.versionCode})")
            Metric("SDK", "min=${manifest.minSdk ?: "—"}, target=${manifest.targetSdk ?: "—"}")
            Metric("Debuggable", manifest.debuggable.toString())
            Metric("Allow backup", manifest.allowBackup.toString())
            Metric("Cleartext allowed", manifest.usesCleartextTraffic.toString())
            Metric("Network Security Config", manifest.networkSecurityConfigConfigured?.toString() ?: "не определено")
            manifest.networkSecurity?.let { network ->
                Metric("Network config XML", network.configEntries.joinToString().ifBlank { "не найден" })
                network.resolvedManifestEntry?.let { Metric("Resolved resource", it) }
                Metric("Base cleartext", network.baseCleartextTrafficPermitted?.toString() ?: "default")
                Metric("Domain configs", network.domainConfigs.size.toString())
                Metric("Trust anchors", network.trustAnchors.size.toString())
                Metric("User CAs (production)", network.trustAnchors.count { it.source.equals("user", true) && !it.inDebugOverrides }.toString())
                Metric("Debug overrides", network.debugOverridesPresent.toString())
                Metric("Pin set", network.pinSetPresent.toString())
                network.domainConfigs.filter { it.cleartextTrafficPermitted == true }.take(8).forEach { domain ->
                    Text("• cleartext domain: ${domain.domains.joinToString().ifBlank { "<unresolved>" }}", style = MaterialTheme.typography.bodySmall)
                }
            }
            Metric("Permissions", manifest.requestedPermissions.size.toString())
            Metric("Dangerous permissions", manifest.dangerousPermissions.size.toString())
            Metric("Declared custom permissions", manifest.declaredPermissions.size.toString())
            Metric("Deep-link filters", manifest.deepLinks.size.toString())
            Metric("Components", manifest.components.size.toString())
            Metric("Exported", manifest.components.count { it.exported }.toString())
            Metric("Signing cert SHA-256", manifest.signingCertificateSha256.firstOrNull() ?: "не определён")
            Metric("Signing schemes", manifest.signingSchemes.joinToString().ifBlank { "не определены" })
            if (manifest.signingBlockIds.isNotEmpty()) Metric("Signing block IDs", manifest.signingBlockIds.joinToString())
            if (manifest.signingCertificateSha256.size > 1) {
                Metric("Certificates/history", manifest.signingCertificateSha256.size.toString())
            }
            if (manifest.dangerousPermissions.isNotEmpty()) {
                Text("Dangerous permissions", style = MaterialTheme.typography.titleMedium)
                manifest.dangerousPermissions.take(16).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
            val exported = manifest.components.filter { it.exported }
            if (exported.isNotEmpty()) {
                Text("Exported components", style = MaterialTheme.typography.titleMedium)
                exported.take(20).forEach { c ->
                    Text("• ${c.kind}: ${c.name}${if (c.permissions.isNotEmpty()) " · ${c.permissions.joinToString()}" else ""}", style = MaterialTheme.typography.bodySmall)
                }
            }
            if (manifest.deepLinks.isNotEmpty()) {
                Text("Deep links / App Links", style = MaterialTheme.typography.titleMedium)
                manifest.deepLinks.take(20).forEach { link ->
                    val target = link.schemes.flatMap { scheme ->
                        if (link.hosts.isEmpty()) listOf("$scheme://") else link.hosts.map { host -> "$scheme://$host" }
                    }.joinToString()
                    Text("• ${link.componentName}: $target · autoVerify=${link.autoVerify}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun DexCard(dex: DexSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("DEX index", style = MaterialTheme.typography.titleLarge)
            Metric("DEX scanned", "${dex.dexFilesScanned}/${dex.dexFilesDiscovered}")
            Metric("Strings scanned", "${dex.stringsScanned}/${dex.stringsDeclared}")
            Metric("Types indexed", "${dex.typesIndexed}/${dex.typesDeclared}")
            Metric("Classes indexed", "${dex.classesIndexed}/${dex.classesDeclared}")
            Metric("Methods indexed", "${dex.methodsIndexed}/${dex.methodsDeclared}")
            Metric("Native method declarations", dex.nativeMethods.size.toString())
            Metric("Methods with code", dex.codeMethods.size.toString())
            Metric("Call xrefs", dex.callXrefs.size.toString())
            Metric("String xrefs", dex.stringXrefs.size.toString())
            Metric("Type xrefs", dex.typeXrefs.size.toString())
            Metric("Field xrefs", dex.fieldXrefs.size.toString())
            Metric("Basic blocks", dex.basicBlocks.size.toString())
            Metric("Tracked constants", dex.constants.size.toString())
            Metric("Invoke observations", dex.invokeObservations.size.toString())
            Metric("HTTP URLs", dex.httpUrls.size.toString())
            Metric("HTTPS URLs", dex.httpsUrls.size.toString())
            Metric("Secret candidates", dex.secretCandidates.size.toString())
            Metric("Parse errors", dex.parseErrors.toString())
            if (dex.truncated) {
                Text("DEX inventory частичный: достигнут защитный лимит.", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}


@Composable
private fun DexSearchCard(dex: DexSummary) {
    var query by remember { mutableStateOf("") }
    val normalized = query.trim().lowercase()
    val results = if (normalized.length < 2) emptyList() else buildList {
        dex.classes.asSequence()
            .filter { it.descriptor.lowercase().contains(normalized) }
            .take(8)
            .forEach { add("CLASS  ${it.descriptor}") }
        dex.methods.asSequence()
            .filter { (it.declaringClass + " " + it.name + " " + it.prototype).lowercase().contains(normalized) }
            .take(8)
            .forEach { add("METHOD ${it.declaringClass}->${it.name}${it.prototype}") }
        dex.stringXrefs.asSequence()
            .filter { it.value.lowercase().contains(normalized) }
            .take(8)
            .forEach { add("STRING ${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}: ${it.value}") }
        dex.fieldXrefs.asSequence()
            .filter { (it.declaringClass + " " + it.fieldName + " " + it.fieldType).lowercase().contains(normalized) }
            .take(8)
            .forEach { add("FIELD  ${it.declaringClass}->${it.fieldName}:${it.fieldType} [${it.kind}]") }
        dex.callXrefs.asSequence()
            .filter { (it.calleeClass + " " + it.calleeName + " " + it.callerClass + " " + it.callerName).lowercase().contains(normalized) }
            .take(8)
            .forEach { add("CALL   ${it.callerClass}->${it.callerName} → ${it.calleeClass}->${it.calleeName}") }
    }.take(24)

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("DEX search / xrefs", style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(160) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Class / method / string / field") },
            )
            if (normalized.length in 1..1) {
                Text("Введите минимум 2 символа.", style = MaterialTheme.typography.bodySmall)
            }
            results.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (normalized.length >= 2 && results.isEmpty()) {
                Text("Совпадений в локальном bounded-index не найдено.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun NativeCard(native: NativeSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Native ELF / JNI", style = MaterialTheme.typography.titleLarge)
            Metric("Libraries scanned", "${native.librariesScanned}/${native.librariesDiscovered}")
            Metric("Parse errors", native.parseErrors.toString())
            Metric("JNI bridge declarations", native.jniBridges.size.toString())
            Metric("Static JNI matches", native.jniBridges.count { it.resolution == "STATIC_SYMBOL_MATCH" }.toString())
            Metric("Dynamic registration candidates", native.jniBridges.count { it.resolution == "DYNAMIC_REGISTRATION_POSSIBLE" }.toString())
            Metric("Executable-stack libraries", native.libraries.count { it.executableStack == true }.toString())
            Metric("Libraries without RELRO", native.libraries.count { it.parseError == null && !it.hasGnuRelro }.toString())
            Metric("Native secret candidates", native.libraries.sumOf { it.secretCandidates.size }.toString())
            native.libraries.take(8).forEach { lib ->
                Text("${lib.abi} • ${lib.entryName} • ${lib.machine} • JNI=${lib.jniSymbols.size}", style = MaterialTheme.typography.bodySmall)
            }
            if (native.libraries.size > 8) {
                Text("… ещё ${native.libraries.size - 8} libraries", style = MaterialTheme.typography.bodySmall)
            }
            if (native.truncated) {
                Text("Native inventory частичный: достигнут защитный лимит.", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun NativeSearchCard(native: NativeSummary) {
    var query by remember { mutableStateOf("") }
    val q = query.trim().lowercase()
    val results = if (q.length < 2) emptyList() else buildList {
        native.libraries.asSequence()
            .filter { (it.entryName + " " + it.machine + " " + it.abi).lowercase().contains(q) }
            .take(6).forEach { add("LIB    ${it.entryName} · ${it.abi}/${it.machine}") }
        native.libraries.asSequence().flatMap { lib -> lib.exportedSymbols.asSequence().map { lib to it } }
            .filter { (_, sym) -> sym.name.lowercase().contains(q) }
            .take(10).forEach { (lib, sym) -> add("EXPORT ${lib.entryName}: ${sym.name} @ ${sym.virtualAddress?.let { "0x" + it.toString(16) } ?: "?"}") }
        native.libraries.asSequence().flatMap { lib -> lib.importedSymbols.asSequence().map { lib to it } }
            .filter { (_, sym) -> sym.name.lowercase().contains(q) }
            .take(10).forEach { (lib, sym) -> add("IMPORT ${lib.entryName}: ${sym.name}") }
        native.jniBridges.asSequence()
            .filter { (it.declaringClass + " " + it.methodName + " " + (it.nativeSymbol ?: "")).lowercase().contains(q) }
            .take(10).forEach { add("JNI    ${it.declaringClass}->${it.methodName}${it.prototype} → ${it.nativeSymbol ?: it.resolution}") }
        native.libraries.asSequence().flatMap { lib -> lib.httpUrls.asSequence().map { lib.entryName to it } }
            .filter { it.second.lowercase().contains(q) }
            .take(8).forEach { add("URL    ${it.first}: ${it.second}") }
    }.take(32)

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Native symbols / JNI search", style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(160) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Library / import / export / JNI / URL") },
            )
            if (q.length == 1) Text("Введите минимум 2 символа.", style = MaterialTheme.typography.bodySmall)
            results.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (q.length >= 2 && results.isEmpty()) Text("Совпадений в native index не найдено.", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun Il2CppCard(il2cpp: Il2CppSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Unity IL2CPP", style = MaterialTheme.typography.titleLarge)
            Metric("Detected", il2cpp.detected.toString())
            Metric("Confidence", il2cpp.confidence)
            Metric("libil2cpp.so", il2cpp.libil2cppLibraries.size.toString())
            Metric("IL2CPP API symbols", il2cpp.il2cppApiSymbols.size.toString())
            Metric("Registration symbol candidates", il2cpp.registrationCandidates.size.toString())
            Metric("Metadata version", il2cpp.metadata?.metadataVersion?.toString() ?: "—")
            Metric("Assembly candidates", il2cpp.metadata?.assemblyNameCandidates?.size?.toString() ?: "—")
            Metric("Managed-name candidates", il2cpp.metadata?.managedNameCandidates?.size?.toString() ?: "—")
            Metric("Metadata layout", il2cpp.metadata?.layoutProfile ?: "—")
            Metric("Reconstructed types", il2cpp.metadata?.typeDefinitions?.size?.toString() ?: "—")
            Metric("Reconstructed methods", il2cpp.metadata?.methodDefinitions?.size?.toString() ?: "—")
            il2cpp.metadata?.typeDefinitions?.take(4)?.forEach { type ->
                Text("${type.fullName} • methods=${type.methodCount} • fields=${type.fieldCount}", style = MaterialTheme.typography.bodySmall)
            }
            val unityVersion = il2cpp.metadata?.unityVersionCandidates?.firstOrNull()
            if (unityVersion != null) Metric("Unity version candidate", unityVersion)
            if (il2cpp.truncated) {
                Text("IL2CPP inventory частичный: достигнут защитный лимит.", color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun RuntimeProfilesCard(runtimes: RuntimeSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Runtime / framework profiles", style = MaterialTheme.typography.titleLarge)
            runtimes.profiles.forEach { profile ->
                Metric(profile.kind, profile.confidence)
                Text(profile.indicators.joinToString(" • "), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun RuntimeArtifactsCard(runtime: RuntimeArtifactSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Runtime-specific artifacts", style = MaterialTheme.typography.titleLarge)
            runtime.flutter?.let { flutter ->
                Text("Flutter", style = MaterialTheme.typography.titleMedium)
                Metric("Confidence", flutter.confidence)
                Metric("Flutter assets", flutter.assetCount.toString())
                Metric("libapp.so", flutter.appLibraries.size.toString())
                Metric("AOT likely", flutter.aotLikely.toString())
            }
            runtime.hermes?.let { hermes ->
                Text("Hermes / React Native", style = MaterialTheme.typography.titleMedium)
                Metric("Confidence", hermes.confidence)
                Metric("HBC files", hermes.bytecodeFiles.size.toString())
                hermes.bytecodeFiles.firstOrNull()?.let { hbc ->
                    Metric("HBC version", hbc.bytecodeVersion?.toString() ?: "—")
                    Metric("Functions", hbc.functionCount?.toString() ?: "—")
                    Metric("Function headers indexed", hbc.functionsScanned.toString())
                    Metric("Strings", hbc.stringCount?.toString() ?: "—")
                    Metric("Structured prefix", hbc.structuredPrefixBytes?.let(::formatBytes) ?: "—")
                }
            }
            runtime.unityMono?.let { mono ->
                Text("Unity Mono / managed assemblies", style = MaterialTheme.typography.titleMedium)
                Metric("Confidence", mono.confidence)
                Metric("Assemblies", mono.assemblies.size.toString())
                Metric("Valid CLI metadata", mono.assemblies.count { it.cliMetadataPresent }.toString())
                Metric("Managed TypeDefs", mono.assemblies.sumOf { it.typeDefinitions.size }.toString())
                Metric("Managed MethodDefs", mono.assemblies.sumOf { it.methodDefinitions.size }.toString())
                Metric("AssemblyRefs", mono.assemblies.sumOf { it.assemblyReferences.size }.toString())
            }
            runtime.unreal?.let { unreal ->
                Text("Unreal Engine", style = MaterialTheme.typography.titleMedium)
                Metric("Confidence", unreal.confidence)
                Metric("Native engine libraries", unreal.engineLibraries.size.toString())
                Metric("PAK/IoStore containers", unreal.containers.size.toString())
            }
        }
    }
}

@Composable
private fun SupplyChainCard(supply: SupplyChainSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Supply chain / SBOM", style = MaterialTheme.typography.titleLarge)
            Metric("Components", supply.components.size.toString())
            Metric("Components with exact version", supply.components.count { it.version != null }.toString())
            Metric("Components with purl", supply.components.count { it.purl != null }.toString())
            Metric("Native DT_NEEDED", supply.nativeDependencies.size.toString())
            Metric("Matched advisories", supply.vulnerabilities.size.toString())
            supply.advisoryFeed?.let { feed ->
                Metric("Advisory feed", "${feed.feedId} • ${feed.source}")
                Metric("Feed SHA-256", feed.sha256)
                Metric("Feed generated", feed.generatedAt)
            }
            supply.vulnerabilities.take(8).forEach { match ->
                Text("${match.severity} • ${match.advisoryId} • ${match.componentId}@${match.componentVersion}", style = MaterialTheme.typography.bodySmall)
            }
            if (supply.vulnerabilities.size > 8) Text("… ещё ${supply.vulnerabilities.size - 8} advisory matches", style = MaterialTheme.typography.bodySmall)
            supply.components.take(10).forEach { component ->
                Text(
                    "${component.name}${component.version?.let { " $it" } ?: ""} • ${component.ecosystem} • ${component.confidence}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (supply.components.size > 10) {
                Text("… ещё ${supply.components.size - 10} components", style = MaterialTheme.typography.bodySmall)
            }
            if (supply.truncated) Text("Supply-chain inventory частичный: достигнут защитный лимит.", color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun FindingsSection(findings: List<Finding>) {
    Text("Findings (${findings.size})", style = MaterialTheme.typography.titleLarge)
    if (findings.isEmpty()) {
        Text("Manifest-level правила текущего движка не обнаружили проблем. Это не означает, что приложение полностью безопасно.")
        return
    }
    findings.forEach { finding ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text("${finding.severity}: ${finding.title}", style = MaterialTheme.typography.titleMedium)
                Text("${finding.id} • ${finding.category} • confidence=${finding.confidence}")
                Text(finding.description)
                finding.evidence.take(4).forEach { evidence ->
                    Text("• ${evidence.location}: ${evidence.value}", style = MaterialTheme.typography.bodySmall)
                }
                if (finding.evidence.size > 4) {
                    Text("… ещё ${finding.evidence.size - 4} evidence items", style = MaterialTheme.typography.bodySmall)
                }
                Text("Исправление: ${finding.remediation}")
                if (finding.requiresManualReview) {
                    Text("Требуется ручная проверка", color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

@Composable
private fun Metric(name: String, value: String) {
    Text("$name: $value", style = MaterialTheme.typography.bodyMedium)
}

private fun AssessmentScope.modesLabel(): String = buildList {
    if (staticAnalysis) add("Static")
    if (reverseEngineering) add("RE")
    if (dynamicAnalysis) add("Dynamic Lab")
    if (networkTesting) add("Network/API")
}.joinToString()

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kib = bytes / 1024.0
    if (kib < 1024) return "%.1f KiB".format(kib)
    return "%.1f MiB".format(kib / 1024.0)
}

@Composable
private fun rememberDebouncedQuery(value: String, delayMs: Long = 160L): String {
    var debounced by remember { mutableStateOf(value) }
    LaunchedEffect(value) {
        delay(delayMs)
        debounced = value
    }
    return debounced
}

@Composable
private fun ReBrowserSection(report: StaticAnalysisReport) {
    report.dex?.let { dex ->
        val indexState = produceState<DexReIndex?>(initialValue = null, dex, report.correlations) {
            value = withContext(Dispatchers.Default) { ReBrowserIndex.buildDex(dex, report.correlations) }
        }
        val index = indexState.value
        if (index == null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("DEX RE Browser", style = MaterialTheme.typography.titleLarge)
                    Text("Подготовка индекса…", style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            var query by remember { mutableStateOf("") }
            val debouncedQuery = rememberDebouncedQuery(query)
            var selectedPackage by remember(index) { mutableStateOf(index.packages.firstOrNull()?.name) }
            var selectedClass by remember(index, selectedPackage) { mutableStateOf(index.packages.firstOrNull { it.name == selectedPackage }?.classes?.firstOrNull()?.descriptor) }
            val pkg = index.packages.firstOrNull { it.name == selectedPackage }
            val cls = pkg?.classes?.firstOrNull { it.descriptor == selectedClass }
            val searchResults = remember(index, debouncedQuery) { ReBrowserIndex.searchDex(index, debouncedQuery, 20) }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("DEX RE Browser", style = MaterialTheme.typography.titleLarge)
                    Metric("Packages", index.packages.size.toString())
                    Metric("Methods", index.methodCount.toString())
                    Metric("Xrefs", index.xrefCount.toString())
                    OutlinedTextField(value=query,onValueChange={query=it.take(160)},modifier=Modifier.fillMaxWidth(),singleLine=true,label={Text("Search package/class/method/xref")})
                    searchResults.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text("Packages", style = MaterialTheme.typography.titleMedium)
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        index.packages.take(60).forEach { p ->
                            if (p.name == selectedPackage) Button(onClick={ selectedPackage=p.name; selectedClass=p.classes.firstOrNull()?.descriptor }) { Text(p.name) }
                            else OutlinedButton(onClick={ selectedPackage=p.name; selectedClass=p.classes.firstOrNull()?.descriptor }) { Text(p.name) }
                        }
                    }
                    pkg?.let { p ->
                        Text("Classes", style = MaterialTheme.typography.titleMedium)
                        p.classes.take(80).forEach { c ->
                            OutlinedButton(onClick={selectedClass=c.descriptor}, modifier=Modifier.fillMaxWidth()) { Text(c.descriptor) }
                        }
                    }
                    cls?.let { c ->
                        Text("Methods in ${c.descriptor}", style = MaterialTheme.typography.titleMedium)
                        c.methods.take(120).forEach { m ->
                            Text("${m.name}${m.prototype} • blocks=${m.basicBlockCount} • callers=${m.callers.size} • callees=${m.callees.size}", style = MaterialTheme.typography.bodySmall)
                            m.callers.take(3).forEach { Text("  ← $it", style = MaterialTheme.typography.bodySmall) }
                            m.callees.take(3).forEach { Text("  → $it", style = MaterialTheme.typography.bodySmall) }
                            m.strings.take(2).forEach { Text("  str: $it", style = MaterialTheme.typography.bodySmall) }
                            m.nativeTargets.take(3).forEach { Text("  JNI → $it", style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
        }
    }

    report.native?.let { native ->
        val indexState = produceState<NativeReIndex?>(initialValue = null, native) {
            value = withContext(Dispatchers.Default) { ReBrowserIndex.buildNative(native) }
        }
        val index = indexState.value
        if (index == null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("Native RE Browser", style = MaterialTheme.typography.titleLarge)
                    Text("Подготовка индекса…", style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            var query by remember { mutableStateOf("") }
            val debouncedQuery = rememberDebouncedQuery(query)
            val q = debouncedQuery.trim().lowercase()
            val results = remember(index, q) {
                if (q.length < 2) emptyList() else index.symbols.asSequence()
                    .filter { (it.library+" "+it.name+" "+it.kind).lowercase().contains(q) }
                    .take(80).toList()
            }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("Native RE Browser", style = MaterialTheme.typography.titleLarge)
                    Metric("Libraries", index.libraries.size.toString())
                    Metric("Symbols", index.symbols.size.toString())
                    Metric("JNI bridges", index.jniBridges.size.toString())
                    OutlinedTextField(value=query,onValueChange={query=it.take(160)},modifier=Modifier.fillMaxWidth(),singleLine=true,label={Text("Search native symbol / library")})
                    results.forEach { s -> Text("${s.kind} ${s.library}: ${s.name} @ ${s.virtualAddress?.let { "0x"+it.toString(16) } ?: "?"}", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }

    if (report.ghidra.isNotEmpty()) {
        val indexState = produceState<GhidraReIndex?>(initialValue = null, report.ghidra, report.correlations) {
            value = withContext(Dispatchers.Default) { ReBrowserIndex.buildGhidra(report.ghidra, report.correlations) }
        }
        val index = indexState.value
        if (index == null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("Ghidra deep native browser", style = MaterialTheme.typography.titleLarge)
                    Text("Подготовка индекса…", style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            var query by remember { mutableStateOf("") }
            val debouncedQuery = rememberDebouncedQuery(query)
            val results = remember(index, debouncedQuery) { ReBrowserIndex.searchGhidra(index, debouncedQuery, 80) }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text("Ghidra deep native browser", style = MaterialTheme.typography.titleLarge)
                    Metric("Libraries", index.libraries.size.toString())
                    Metric("Functions", index.functions.size.toString())
                    Metric("Xrefs", index.xrefCount.toString())
                    Metric("JNI registrations", index.jniRegistrationCount.toString())
                    Metric("IL2CPP registrations", index.il2cppRegistrationCount.toString())
                    Metric("IL2CPP codegen calls", index.il2cppCodegenCallCount.toString())
                    Metric("IL2CPP pointer tables", index.il2cppPointerTableCount.toString())
                    report.correlations?.let { c ->
                        Metric("DEX↔JNI resolved", "${c.dexNativeMethodsResolved}/${c.dexNativeMethodsConsidered}")
                        Metric("IL2CPP methods↔RVA", "${c.il2cppMethodsResolved}/${c.il2cppMethodsConsidered}")
                    }
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it.take(160) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Function / JNI / IL2CPP / library") },
                    )
                    results.forEach { fn ->
                        Text(
                            "${fn.libraryEntry} @ 0x${fn.rva.toString(16)} • ${fn.name} • ${fn.signature} • blocks=${fn.cfgBlockCount} • xrefs=${fn.incomingXrefs}/${fn.outgoingXrefs}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        fn.jniRegistrations.take(2).forEach { Text("  JNI $it", style = MaterialTheme.typography.bodySmall) }
                        fn.il2cppRegistrations.take(2).forEach { Text("  IL2CPP $it", style = MaterialTheme.typography.bodySmall) }
                        fn.crossRuntimeLinks.take(3).forEach { Text("  LINK $it", style = MaterialTheme.typography.bodySmall) }
                        fn.decompilerPreview?.takeIf { it.isNotBlank() }?.let {
                            Text("  decompiler: ${it.take(240)}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    if (debouncedQuery.trim().length >= 2 && results.isEmpty()) {
                        Text("Совпадений в Ghidra result index не найдено.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun AssessmentDiffCard(diff: AssessmentDiff) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text("Version security diff", style = MaterialTheme.typography.titleLarge)
            Metric("Package", diff.packageName ?: "—")
            Metric("Versions", "${diff.fromVersion ?: "?"} → ${diff.toVersion ?: "?"}")
            Metric("Added", diff.addedCount.toString())
            Metric("Removed", diff.removedCount.toString())
            Metric("Changed", diff.changedCount.toString())
            Metric("Signer changed", diff.signerChanged.toString())
            diff.items.take(120).forEach { item ->
                Text("${item.change} • ${item.category} • ${item.key}${item.severityHint?.let { " • $it" } ?: ""}", style = MaterialTheme.typography.bodySmall)
            }
            if(diff.items.size>120) Text("… ещё ${diff.items.size-120} diff items", style = MaterialTheme.typography.bodySmall)
        }
    }
}
