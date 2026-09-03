package org.unirevlab.security

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.work.WorkInfo
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.unirevlab.security.data.AgreementStore
import org.unirevlab.security.data.AuditJobRepository
import org.unirevlab.security.data.InstalledAppRepository
import org.unirevlab.security.model.AuditProfile
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditSourceSpec
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.ui.AgreementScreen
import org.unirevlab.security.ui.AuditProfileScreen
import org.unirevlab.security.ui.AutoAuditScreen
import org.unirevlab.security.ui.InstalledAppsScreen
import org.unirevlab.security.ui.UniRevLabTheme
import org.unirevlab.security.work.AuditScheduler

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            UniRevLabTheme { UniRevLabApp() }
        }
    }
}

private enum class Route { AGREEMENT, PROFILE, HOME, INSTALLED_APPS }

@Composable
private fun UniRevLabApp() {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val agreementStore = remember { AgreementStore(appContext) }
    val jobs = remember { AuditJobRepository(appContext) }
    val installedRepository = remember { InstalledAppRepository(appContext) }
    val workManager = remember { WorkManager.getInstance(appContext) }
    var profile by remember { mutableStateOf(jobs.loadProfile()) }
    var route by remember {
        mutableStateOf(
            when {
                !agreementStore.isAccepted() -> Route.AGREEMENT
                profile == null -> Route.PROFILE
                else -> Route.HOME
            }
        )
    }
    var authorityConfirmed by remember { mutableStateOf(false) }
    var jobId by remember { mutableStateOf(jobs.currentJobId()) }
    var workId by remember { mutableStateOf(jobs.currentWorkId()) }
    var auditState by remember { mutableStateOf(jobId?.let(jobs::loadState)) }
    var summary by remember { mutableStateOf(jobId?.let(jobs::loadSummary)) }
    var isRunning by remember { mutableStateOf(auditState?.stage?.isTerminal() == false && workId != null) }
    var error by remember { mutableStateOf<String?>(null) }
    var installedApps by remember { mutableStateOf<List<InstalledAppDescriptor>>(emptyList()) }
    var installedLoading by remember { mutableStateOf(false) }
    var installedError by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<Pair<String, String>?>(null) }
    val coroutineScope = rememberCoroutineScope()

    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    fun start(source: AuditSourceSpec) {
        val currentProfile = profile
        if (!authorityConfirmed || currentProfile == null) {
            error = "Подтвердите полномочия и заполните профиль аудита"
            return
        }
        val result = runCatching {
            val spec = jobs.createJob(currentProfile, source)
            val request = AuditScheduler.enqueue(appContext, spec.jobId)
            jobs.rememberWork(spec.jobId, request.id)
            spec.jobId to request.id
        }
        result.onSuccess { (newJobId, newWorkId) ->
            requestNotificationPermission()
            jobId = newJobId
            workId = newWorkId
            auditState = jobs.loadState(newJobId)
            summary = null
            isRunning = true
            error = null
            route = Route.HOME
        }.onFailure { failure ->
            error = failure.message ?: "Не удалось создать задание"
        }
    }

    fun reloadInstalledApps() {
        coroutineScope.launch {
            installedLoading = true
            installedError = null
            val result = runCatching { withContext(Dispatchers.IO) { installedRepository.load() } }
            installedApps = result.getOrDefault(emptyList())
            installedError = result.exceptionOrNull()?.message
            installedLoading = false
        }
    }

    LaunchedEffect(workId) {
        val observedWorkId = workId ?: return@LaunchedEffect
        while (isActive) {
            val info = runCatching {
                withContext(Dispatchers.IO) { workManager.getWorkInfoById(observedWorkId).get() }
            }.getOrNull()
            val observedJobId = jobId
            if (observedJobId != null) {
                jobs.loadState(observedJobId)?.let { auditState = it }
                jobs.loadSummary(observedJobId)?.let { summary = it }
            }
            if (info == null || info.state.isFinished) {
                isRunning = false
                authorityConfirmed = false
                info?.outputData?.getString(org.unirevlab.security.work.AuditWorker.KEY_ERROR)?.let { error = it }
                break
            }
            isRunning = info.state == WorkInfo.State.RUNNING || info.state == WorkInfo.State.ENQUEUED || info.state == WorkInfo.State.BLOCKED
            delay(WORK_POLL_INTERVAL_MS)
        }
    }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            start(
                AuditSourceSpec(
                    kind = AuditSourceKind.FILE_URI,
                    displayName = displayName(context, uri),
                    uri = uri.toString(),
                )
            )
        }
    }

    val fileSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val selection = pendingExport
        val currentJob = jobId
        pendingExport = null
        if (uri != null && selection != null && currentJob != null) {
            coroutineScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        val source = jobs.outputFile(currentJob, selection.first)
                        require(source.isFile) { "Результат ещё не сформирован" }
                        context.contentResolver.openOutputStream(uri, "wt").use { output ->
                            requireNotNull(output) { "Не удалось открыть файл назначения" }
                            source.inputStream().buffered().use { input -> input.copyTo(output) }
                        }
                    }
                }
                error = result.exceptionOrNull()?.message
            }
        }
    }

    when (route) {
        Route.AGREEMENT -> AgreementScreen(error = error) { signerName ->
            val result = runCatching { agreementStore.accept(signerName) }
            error = result.exceptionOrNull()?.message
            if (result.isSuccess) route = if (profile == null) Route.PROFILE else Route.HOME
        }
        Route.PROFILE -> AuditProfileScreen(initial = profile) { updated ->
            val result = runCatching { jobs.saveProfile(updated) }
            result.onSuccess {
                profile = updated
                error = null
                route = Route.HOME
            }.onFailure { error = it.message }
        }
        Route.INSTALLED_APPS -> InstalledAppsScreen(
            apps = installedApps,
            isLoading = installedLoading,
            error = installedError,
            onBack = { route = Route.HOME },
            onReload = ::reloadInstalledApps,
            onSelect = { app ->
                start(
                    AuditSourceSpec(
                        kind = AuditSourceKind.INSTALLED_APP,
                        displayName = app.label,
                        packageName = app.packageName,
                        baseApkPath = app.baseApkPath,
                        splitApkPaths = app.splitApkPaths,
                        versionName = app.versionName,
                        versionCode = app.versionCode,
                        installerPackageName = app.installerPackageName,
                    )
                )
            },
        )
        Route.HOME -> AutoAuditScreen(
            profile = requireNotNull(profile),
            authorityConfirmed = authorityConfirmed,
            state = auditState,
            summary = summary,
            isRunning = isRunning,
            error = error,
            onAuthorityChanged = { authorityConfirmed = it },
            onPickInstalled = {
                route = Route.INSTALLED_APPS
                reloadInstalledApps()
            },
            onPickFile = {
                filePicker.launch(
                    arrayOf(
                        "application/vnd.android.package-archive",
                        "application/zip",
                        "application/octet-stream",
                    )
                )
            },
            onCancel = {
                workId?.let { AuditScheduler.cancel(appContext, it) }
                isRunning = false
            },
            onEditProfile = { route = Route.PROFILE },
            onExport = { fileName ->
                val fileLabel = exportName(fileName, summary?.displayName)
                pendingExport = fileName to fileLabel
                fileSaver.launch(fileLabel)
            },
        )
    }
}

private fun AuditStage.isTerminal(): Boolean =
    this == AuditStage.COMPLETE || this == AuditStage.CANCELLED || this == AuditStage.FAILED

private fun displayName(context: android.content.Context, uri: Uri): String {
    val fromProvider = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }.getOrNull()
    return fromProvider?.takeIf { it.isNotBlank() } ?: uri.lastPathSegment?.substringAfterLast('/') ?: "selected-artifact.apk"
}

private fun exportName(fileName: String, displayName: String?): String {
    val safeTarget = displayName.orEmpty()
        .substringBeforeLast('.')
        .replace(Regex("[^A-Za-z0-9А-Яа-я._-]+"), "-")
        .trim('-')
        .take(48)
        .ifBlank { "audit" }
    return "$safeTarget-$fileName"
}

private const val WORK_POLL_INTERVAL_MS = 650L
