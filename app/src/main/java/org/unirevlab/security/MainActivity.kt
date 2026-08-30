package org.unirevlab.security

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import org.unirevlab.security.analysis.LocalArtifactInspector
import org.unirevlab.security.analysis.GhidraResultIntegrator
import org.unirevlab.security.analysis.ExternalAdvisoryFeedImporter
import org.unirevlab.security.analysis.VulnerabilityAdvisoryCorrelator
import org.unirevlab.security.analysis.GhidraResultJsonParser
import org.unirevlab.security.analysis.AssessmentDiffEngine
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.SbomExporter
import org.unirevlab.security.data.AgreementStore
import org.unirevlab.security.data.InstalledAppRepository
import org.unirevlab.security.data.CoordinatorSyncClient
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.AssessmentDiff
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.ui.AgreementScreen
import org.unirevlab.security.ui.AssessmentScreen
import org.unirevlab.security.ui.DashboardScreen
import org.unirevlab.security.ui.InstalledAppsScreen
import org.unirevlab.security.ui.HelpScreen
import org.unirevlab.security.ui.UniRevLabTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            UniRevLabTheme {
                UniRevLabApp()
            }
        }
    }
}

private enum class Route { AGREEMENT, SCOPE, DASHBOARD, INSTALLED_APPS, HELP }

@Composable
private fun UniRevLabApp() {
    val context = LocalContext.current
    val agreementStore = remember { AgreementStore(context.applicationContext) }
    val installedRepository = remember { InstalledAppRepository(context.applicationContext) }
    val inspector = remember { LocalArtifactInspector(context.applicationContext) }
    var route by remember { mutableStateOf(if (agreementStore.isAccepted()) Route.SCOPE else Route.AGREEMENT) }
    var scope by remember { mutableStateOf<AssessmentScope?>(null) }
    var report by remember { mutableStateOf<StaticAnalysisReport?>(null) }
    var previousReport by remember { mutableStateOf<StaticAnalysisReport?>(null) }
    var comparison by remember { mutableStateOf<AssessmentDiff?>(null) }
    var isInspecting by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var agreementError by remember { mutableStateOf<String?>(null) }
    var installedApps by remember { mutableStateOf<List<InstalledAppDescriptor>>(emptyList()) }
    var installedAppsLoading by remember { mutableStateOf(false) }
    var installedAppsError by remember { mutableStateOf<String?>(null) }
    var coordinatorSyncStatus by remember { mutableStateOf<String?>(null) }
    var inspectionJob by remember { mutableStateOf<Job?>(null) }
    val coroutineScope = rememberCoroutineScope()

    fun runInspection(block: () -> StaticAnalysisReport) {
        inspectionJob?.cancel()
        inspectionJob = coroutineScope.launch {
            isInspecting = true
            error = null
            try {
                val next = runInterruptible(Dispatchers.IO) { block() }
                val previous = report
                previousReport = previous
                comparison = if (previous != null && sameApplication(previous, next)) {
                    AssessmentDiffEngine.diff(previous, next)
                } else null
                report = next
            } catch (_: CancellationException) {
                error = "Анализ отменён"
            } catch (failure: Exception) {
                error = failure.message ?: failure::class.java.simpleName
            } finally {
                isInspecting = false
                inspectionJob = null
            }
        }
    }

    fun reloadInstalledApps() {
        coroutineScope.launch {
            installedAppsLoading = true
            installedAppsError = null
            val result = runCatching { withContext(Dispatchers.IO) { installedRepository.load() } }
            installedApps = result.getOrDefault(emptyList())
            installedAppsError = result.exceptionOrNull()?.message
            installedAppsLoading = false
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: SecurityException) {
                // Some providers grant only temporary access; inspection still works in this callback lifecycle.
            }
            runInspection { inspector.inspect(uri, requireNotNull(scope)) }
        }
    }

    val ghidraResultPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                isInspecting = true
                error = null
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri).use { input ->
                            requireNotNull(input) { "Не удалось открыть Ghidra result JSON" }
                            val values = GhidraResultJsonParser.parse(input)
                            GhidraResultIntegrator.attach(current, values)
                        }
                    }
                }
                result.getOrNull()?.let { report = it }
                error = result.exceptionOrNull()?.message
                isInspecting = false
            }
        }
    }

    val advisoryFeedPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                isInspecting = true
                error = null
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri).use { input ->
                            requireNotNull(input) { "Не удалось открыть advisory feed JSON" }
                            val feed = ExternalAdvisoryFeedImporter.parse(input)
                            VulnerabilityAdvisoryCorrelator.attach(current, feed)
                        }
                    }
                }
                result.getOrNull()?.let { report = it }
                error = result.exceptionOrNull()?.message
                isInspecting = false
            }
        }
    }

    val reportSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть файл отчёта" }
                            output.write(ReportJsonExporter.export(current).toByteArray(Charsets.UTF_8))
                        }
                    }
                }
                error = result.exceptionOrNull()?.message
            }
        }
    }

    val cycloneDxSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть CycloneDX SBOM" }
                            output.write(SbomExporter.exportCycloneDx16(current).toByteArray(Charsets.UTF_8))
                        }
                    }
                }
                error = result.exceptionOrNull()?.message
            }
        }
    }

    val spdxSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/ld+json")) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть SPDX SBOM" }
                            output.write(SbomExporter.exportSpdx301JsonLd(current).toByteArray(Charsets.UTF_8))
                        }
                    }
                }
                error = result.exceptionOrNull()?.message
            }
        }
    }

    when (route) {
        Route.AGREEMENT -> AgreementScreen(error = agreementError) { signerName ->
            val result = runCatching { agreementStore.accept(signerName) }
            agreementError = result.exceptionOrNull()?.message
            if (result.isSuccess) route = Route.SCOPE
        }
        Route.SCOPE -> AssessmentScreen { created ->
            scope = created
            report = null
            previousReport = null
            comparison = null
            route = Route.DASHBOARD
        }
        Route.DASHBOARD -> DashboardScreen(
            scope = requireNotNull(scope),
            report = report,
            comparison = comparison,
            isInspecting = isInspecting,
            error = error,
            onPickArtifact = {
                picker.launch(arrayOf(
                    "application/vnd.android.package-archive",
                    "application/zip",
                    "application/octet-stream",
                ))
            },
            onPickInstalledApp = {
                route = Route.INSTALLED_APPS
                if (installedApps.isEmpty()) reloadInstalledApps()
            },
            onOpenHelp = { route = Route.HELP },
            onCancelAnalysis = { inspectionJob?.cancel() },
            onImportGhidraResults = {
                ghidraResultPicker.launch(arrayOf("application/json", "application/octet-stream"))
            },
            onImportAdvisoryFeed = {
                advisoryFeedPicker.launch(arrayOf("application/json", "application/octet-stream"))
            },
            coordinatorSyncStatus = coordinatorSyncStatus,
            onSyncCoordinator = { coordinatorUrl, coordinatorApiKey ->
                val current = report
                if (current != null) {
                    coroutineScope.launch {
                        isInspecting = true
                        error = null
                        coordinatorSyncStatus = "Coordinator sync…"
                        val result = runCatching { withContext(Dispatchers.IO) { CoordinatorSyncClient.sync(coordinatorUrl, current, coordinatorApiKey) } }
                        result.getOrNull()?.let { receipt ->
                            report = receipt.report
                            coordinatorSyncStatus = "Sync OK: Ghidra=${receipt.pulledGhidraLibraries}, history=${receipt.historyItems}, audit=${receipt.auditTailHash?.take(12) ?: "legacy"}, ${receipt.generatedAt}"
                        }
                        result.exceptionOrNull()?.let { failure ->
                            error = failure.message
                            coordinatorSyncStatus = "Sync failed"
                        }
                        isInspecting = false
                    }
                }
            },
            onSaveReport = {
                val safeName = report?.artifact?.displayName?.substringBeforeLast('.')?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(80) ?: "assessment"
                reportSaver.launch("$safeName-unirevlab-report.json")
            },
            onSaveCycloneDx = {
                val safeName = report?.artifact?.displayName?.substringBeforeLast('.')?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(80) ?: "assessment"
                cycloneDxSaver.launch("$safeName-bom.cdx.json")
            },
            onSaveSpdx = {
                val safeName = report?.artifact?.displayName?.substringBeforeLast('.')?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(80) ?: "assessment"
                spdxSaver.launch("$safeName-bom.spdx.jsonld")
            },
            onNewAssessment = {
                scope = null
                report = null
                previousReport = null
                comparison = null
                coordinatorSyncStatus = null
                route = Route.SCOPE
            },
        )
        Route.HELP -> HelpScreen(onBack = { route = Route.DASHBOARD })
        Route.INSTALLED_APPS -> InstalledAppsScreen(
            apps = installedApps,
            isLoading = installedAppsLoading,
            error = installedAppsError,
            onBack = { route = Route.DASHBOARD },
            onReload = { reloadInstalledApps() },
            onSelect = { app ->
                route = Route.DASHBOARD
                runInspection { inspector.inspectInstalledApp(app, requireNotNull(scope)) }
            },
        )
    }
}

private fun sameApplication(a: StaticAnalysisReport, b: StaticAnalysisReport): Boolean {
    val pa = a.manifest?.packageName ?: a.artifact.sourcePackageName
    val pb = b.manifest?.packageName ?: b.artifact.sourcePackageName
    return pa != null && pa == pb
}
