package org.unirevlab.security

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import org.unirevlab.security.analysis.AnalysisManager
import org.unirevlab.security.analysis.AnalysisRunState
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
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.ui.AgreementScreen
import org.unirevlab.security.ui.AnalysisProgressDialog
import org.unirevlab.security.ui.AssessmentScreen
import org.unirevlab.security.ui.DashboardScreen
import org.unirevlab.security.ui.InstalledAppsScreen
import org.unirevlab.security.ui.HelpScreen
import org.unirevlab.security.ui.PatchLabScreen
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

private enum class Route { AGREEMENT, SCOPE, DASHBOARD, INSTALLED_APPS, HELP, PATCH_LAB }

@Composable
private fun UniRevLabApp() {
    val context = LocalContext.current
    val agreementStore = remember { AgreementStore(context.applicationContext) }
    val installedRepository = remember { InstalledAppRepository(context.applicationContext) }
    remember(context.applicationContext) { AnalysisManager.apply { initialize(context.applicationContext) } }
    val analysisState by AnalysisManager.state.collectAsState()
    val analysisActive = analysisState is AnalysisRunState.Running || analysisState is AnalysisRunState.Cancelling
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
    var patchFinding by remember { mutableStateOf<Finding?>(null) }
    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(analysisState) {
        when (val state = analysisState) {
            is AnalysisRunState.Running -> {
                scope = state.assessmentScope
                route = Route.DASHBOARD
            }
            is AnalysisRunState.Cancelling -> {
                scope = state.assessmentScope
                route = Route.DASHBOARD
            }
            is AnalysisRunState.Completed -> {
                val next = state.report
                val previous = report
                previousReport = previous
                comparison = if (previous != null && sameApplication(previous, next)) {
                    AssessmentDiffEngine.diff(previous, next)
                } else null
                scope = next.assessment
                report = next
                error = null
                route = Route.DASHBOARD
                AnalysisManager.clearTerminalState()
            }
            else -> Unit
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

    val notificationPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    fun requestAnalysisNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } catch (_: SecurityException) {
                // Some providers grant only temporary access; inspection still works in this callback lifecycle.
            }
            lastArtifactUri = uri
            requestAnalysisNotificationPermission()
            AnalysisManager.startFile(uri, requireNotNull(scope))
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
                        val temp = File.createTempFile("unirevlab-report-export-", ".json", context.cacheDir)
                        try {
                            temp.bufferedWriter(Charsets.UTF_8, 128 * 1024).use { writer ->
                                ReportJsonExporter.write(current, writer)
                            }
                            require(temp.length() > 2L) { "Сериализованный отчёт пуст" }
                            context.contentResolver.openOutputStream(uri, "wt").use { output ->
                                requireNotNull(output) { "Не удалось открыть файл отчёта" }
                                temp.inputStream().buffered(128 * 1024).use { input ->
                                    input.copyTo(output, 128 * 1024)
                                }
                                output.flush()
                            }
                        } finally {
                            temp.delete()
                        }
                    }
                }
                result.exceptionOrNull()?.let {
                    runCatching { context.contentResolver.delete(uri, null, null) }
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
            isInspecting = isInspecting || analysisActive,
            analysisState = analysisState,
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
            onOpenPatchLab = { finding ->
                patchFinding = finding
                route = Route.PATCH_LAB
            },
            onCancelAnalysis = { AnalysisManager.cancel() },
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
                if (!analysisActive) {
                    scope = null
                    report = null
                    previousReport = null
                    comparison = null
                    coordinatorSyncStatus = null
                    route = Route.SCOPE
                }
            },
        )
        Route.HELP -> HelpScreen(onBack = { route = Route.DASHBOARD })
        Route.PATCH_LAB -> {
            val currentReport = report
            if (currentReport == null) {
                route = Route.DASHBOARD
            } else {
                PatchLabScreen(
                    report = currentReport,
                    initialFinding = patchFinding,
                    initialSourceUri = lastArtifactUri,
                    onBack = { route = Route.DASHBOARD },
                    onAnalyzeBuilt = { file ->
                        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
                        patchFinding = null
                        route = Route.DASHBOARD
                        requestAnalysisNotificationPermission()
                        AnalysisManager.startFile(uri, requireNotNull(scope))
                    },
                )
            }
        }
        Route.INSTALLED_APPS -> InstalledAppsScreen(
            apps = installedApps,
            isLoading = installedAppsLoading,
            error = installedAppsError,
            onBack = { route = Route.DASHBOARD },
            onReload = { reloadInstalledApps() },
            onSelect = { app ->
                route = Route.DASHBOARD
                lastArtifactUri = null
                requestAnalysisNotificationPermission()
                AnalysisManager.startInstalled(app, requireNotNull(scope))
            },
        )
    }

    AnalysisProgressDialog(
        state = analysisState,
        onCancel = { AnalysisManager.cancel() },
        onCloseTerminal = { AnalysisManager.clearTerminalState() },
    )
}

private fun sameApplication(a: StaticAnalysisReport, b: StaticAnalysisReport): Boolean {
    val pa = a.manifest?.packageName ?: a.artifact.sourcePackageName
    val pb = b.manifest?.packageName ?: b.artifact.sourcePackageName
    return pa != null && pa == pb
}
