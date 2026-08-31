package org.unirevlab.security.analysis

import android.content.Context
import android.net.Uri
import java.io.InterruptedIOException
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Process-scoped owner for the heavy local analysis job.
 *
 * The Activity only observes [state]. This keeps the job and its visible progress attached to the
 * process when Compose/Activity is recreated while the foreground service keeps the process alive.
 */
object AnalysisManager {
    private val lock = Any()
    private val nextRunId = AtomicLong(System.currentTimeMillis())
    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val mutableState = MutableStateFlow<AnalysisRunState>(AnalysisRunState.Idle)

    val state: StateFlow<AnalysisRunState> = mutableState.asStateFlow()

    @Volatile private var appContext: Context? = null
    @Volatile private var inspector: LocalArtifactInspector? = null
    @Volatile private var store: AnalysisRunStore? = null
    @Volatile private var activeJob: Job? = null
    private var lastPersistAtMs: Long = 0L
    private var lastPersistStage: AnalysisStage? = null

    fun initialize(context: Context) {
        if (appContext != null) return
        synchronized(lock) {
            if (appContext != null) return
            val application = context.applicationContext
            appContext = application
            inspector = LocalArtifactInspector(application)
            store = AnalysisRunStore(application)

            val stale = store?.load()
            if (stale?.status == AnalysisRunStore.STATUS_RUNNING || stale?.status == AnalysisRunStore.STATUS_CANCELLING) {
                val message = buildString {
                    append("Предыдущий анализ был прерван системой, принудительной остановкой или перезапуском устройства")
                    stale.stage?.let { append(" на этапе «$it»") }
                    stale.percent?.let { append(" ($it%)") }
                    stale.detail?.takeIf { it.isNotBlank() }?.let { append(". Последняя операция: $it") }
                    append(". Запустите анализ снова; доступные кэшированные результаты будут переиспользованы автоматически.")
                }
                mutableState.value = AnalysisRunState.Interrupted(
                    targetLabel = stale.targetLabel,
                    message = message,
                    previousPercent = stale.percent,
                    previousStage = stale.stage,
                )
                store?.writeTerminal(AnalysisRunStore.STATUS_INTERRUPTED, stale.targetLabel, message)
            }
        }
    }

    fun startFile(uri: Uri, assessmentScope: AssessmentScope) {
        val context = requireContext()
        val targetLabel = uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: "APK / архив"
        start(targetLabel, assessmentScope) { progress ->
            requireNotNull(inspector).inspect(uri, assessmentScope, progress)
        }
        AnalysisForegroundService.start(context)
    }

    fun startInstalled(app: InstalledAppDescriptor, assessmentScope: AssessmentScope) {
        val context = requireContext()
        val targetLabel = "${app.label} (${app.packageName})"
        start(targetLabel, assessmentScope) { progress ->
            requireNotNull(inspector).inspectInstalledApp(app, assessmentScope, progress)
        }
        AnalysisForegroundService.start(context)
    }

    fun cancel() {
        val job: Job
        synchronized(lock) {
            job = activeJob ?: return
            val current = mutableState.value
            if (current is AnalysisRunState.Cancelling) return
            val cancelling = when (current) {
                is AnalysisRunState.Running -> AnalysisRunState.Cancelling(
                    runId = current.runId,
                    targetLabel = current.targetLabel,
                    assessmentScope = current.assessmentScope,
                    progress = current.progress.copy(
                        detail = "Запрос на отмену принят. Прерываем активные DEX/native задачи и очищаем временные файлы…",
                        updatedAtEpochMs = System.currentTimeMillis(),
                    ),
                )
                else -> return
            }
            mutableState.value = cancelling
            persistRunning(cancelling.targetLabel, cancelling.progress, cancelling = true, force = true)
        }
        // runInterruptible interrupts the actual inspector thread. The inspector in turn cancels
        // its executor Futures, so work does not continue invisibly after the UI job is cancelled.
        job.cancel(CancellationException("Analysis cancelled by user"))
    }

    fun clearTerminalState() {
        synchronized(lock) {
            if (activeJob == null) {
                mutableState.value = AnalysisRunState.Idle
                store?.clear()
            }
        }
    }

    fun isRunningInProcess(): Boolean = activeJob?.isActive == true

    private fun start(
        targetLabel: String,
        assessmentScope: AssessmentScope,
        block: (onProgress: (AnalysisProgress) -> Unit) -> StaticAnalysisReport,
    ) {
        val runId = nextRunId.incrementAndGet()
        val startedAt = System.currentTimeMillis()
        val initialProgress = AnalysisProgress(
            stage = AnalysisStage.PREPARING,
            percent = 0,
            detail = "Запуск анализа…",
            startedAtEpochMs = startedAt,
        )

        synchronized(lock) {
            check(activeJob?.isActive != true) { "Другой анализ уже выполняется" }
            mutableState.value = AnalysisRunState.Running(runId, targetLabel, assessmentScope, initialProgress)
            persistRunning(targetLabel, initialProgress, force = true)
        }

        val job = managerScope.launch(start = CoroutineStart.LAZY) {
            try {
                val report = runInterruptible(Dispatchers.IO) {
                    block { progress -> publishProgress(runId, targetLabel, progress) }
                }
                synchronized(lock) {
                    if (currentRunId() == runId) {
                        mutableState.value = AnalysisRunState.Completed(runId, targetLabel, report)
                        store?.writeTerminal(AnalysisRunStore.STATUS_COMPLETED, targetLabel, "100% · Готово")
                        activeJob = null
                    }
                }
            } catch (_: CancellationException) {
                markCancelled(runId, targetLabel)
            } catch (_: InterruptedIOException) {
                markCancelled(runId, targetLabel)
            } catch (failure: Exception) {
                synchronized(lock) {
                    if (currentRunId() == runId) {
                        val message = failure.message ?: failure::class.java.simpleName
                        mutableState.value = AnalysisRunState.Failed(runId, targetLabel, message)
                        store?.writeTerminal(AnalysisRunStore.STATUS_FAILED, targetLabel, message)
                        activeJob = null
                    }
                }
            } finally {
                if (currentRunId() == runId && activeJob == null) {
                    appContext?.let(AnalysisForegroundService::stop)
                }
            }
        }
        synchronized(lock) {
            activeJob = job
        }
        job.start()
    }

    private fun markCancelled(runId: Long, targetLabel: String) {
        synchronized(lock) {
            if (currentRunId() == runId) {
                mutableState.value = AnalysisRunState.Cancelled(runId, targetLabel)
                store?.writeTerminal(AnalysisRunStore.STATUS_CANCELLED, targetLabel, "Анализ отменён пользователем")
                activeJob = null
            }
        }
    }

    private fun publishProgress(runId: Long, targetLabel: String, progress: AnalysisProgress) {
        synchronized(lock) {
            when (val current = mutableState.value) {
                is AnalysisRunState.Running -> if (current.runId == runId) {
                    if (progress.percent < current.progress.percent) return
                    val normalized = progress.copy(percent = progress.percent.coerceIn(0, 100))
                    mutableState.value = current.copy(progress = normalized)
                    persistRunning(targetLabel, normalized)
                }
                is AnalysisRunState.Cancelling -> if (current.runId == runId) {
                    if (progress.percent < current.progress.percent) return
                    val cancellationProgress = progress.copy(
                        percent = progress.percent.coerceIn(0, 100),
                        detail = "Отмена выполняется… ${progress.detail}",
                    )
                    mutableState.value = current.copy(progress = cancellationProgress)
                    persistRunning(targetLabel, cancellationProgress, cancelling = true)
                }
                else -> Unit
            }
        }
    }

    private fun persistRunning(
        targetLabel: String,
        progress: AnalysisProgress,
        cancelling: Boolean = false,
        force: Boolean = false,
    ) {
        val now = System.currentTimeMillis()
        val stageChanged = progress.stage != lastPersistStage
        if (!force && !stageChanged && now - lastPersistAtMs < 2_000L) return
        store?.writeRunning(targetLabel, progress, cancelling)
        lastPersistAtMs = now
        lastPersistStage = progress.stage
    }

    private fun currentRunId(): Long? = when (val current = mutableState.value) {
        is AnalysisRunState.Running -> current.runId
        is AnalysisRunState.Cancelling -> current.runId
        is AnalysisRunState.Completed -> current.runId
        is AnalysisRunState.Cancelled -> current.runId
        is AnalysisRunState.Failed -> current.runId
        else -> null
    }

    private fun requireContext(): Context = requireNotNull(appContext) {
        "AnalysisManager.initialize(context) must be called first"
    }

    @Suppress("unused")
    internal fun shutdownForTests() {
        managerScope.cancel()
    }
}
