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
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Process-scoped analysis owner. The UI observes it instead of owning the heavy job itself, so
 * Activity/Compose recreation no longer silently detaches the visible state from a running scan.
 */
object AnalysisManager {
    private val lock = Any()
    private val nextRunId = AtomicLong(System.currentTimeMillis())
    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val mutableState = MutableStateFlow<AnalysisRunState>(AnalysisRunState.Idle)

    val state: StateFlow<AnalysisRunState> = mutableState.asStateFlow()

    @Volatile
    private var appContext: Context? = null
    @Volatile
    private var inspector: LocalArtifactInspector? = null
    @Volatile
    private var store: AnalysisRunStore? = null
    @Volatile
    private var activeJob: Job? = null

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
                    append("Предыдущий анализ был прерван системой или перезапуском приложения")
                    stale.stage?.let { append(" на этапе «$it»") }
                    stale.percent?.let { append(" ($it%)") }
                    append(". Запустите анализ снова. Если для этого артефакта уже успел сохраниться завершённый SHA-кэш, он будет переиспользован.")
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
        start(targetLabel) { progress ->
            requireNotNull(inspector).inspect(uri, assessmentScope, progress)
        }
        AnalysisForegroundService.start(context)
    }

    fun startInstalled(app: InstalledAppDescriptor, assessmentScope: AssessmentScope) {
        val context = requireContext()
        val targetLabel = "${app.label} (${app.packageName})"
        start(targetLabel) { progress ->
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
                    progress = current.progress.copy(
                        detail = "Запрос на отмену принят. Останавливаем активные DEX/native задачи…",
                        updatedAtEpochMs = System.currentTimeMillis(),
                    ),
                )
                else -> return
            }
            mutableState.value = cancelling
            store?.writeRunning(cancelling.targetLabel, cancelling.progress, cancelling = true)
        }
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
            activeJob?.cancel(CancellationException("Superseded by a new analysis"))
            mutableState.value = AnalysisRunState.Running(runId, targetLabel, initialProgress)
            store?.writeRunning(targetLabel, initialProgress)
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
                synchronized(lock) {
                    if (currentRunId() == runId) {
                        mutableState.value = AnalysisRunState.Cancelled(runId, targetLabel)
                        store?.writeTerminal(AnalysisRunStore.STATUS_CANCELLED, targetLabel, "Анализ отменён пользователем")
                        activeJob = null
                    }
                }
            } catch (_: InterruptedIOException) {
                synchronized(lock) {
                    if (currentRunId() == runId) {
                        mutableState.value = AnalysisRunState.Cancelled(runId, targetLabel)
                        store?.writeTerminal(AnalysisRunStore.STATUS_CANCELLED, targetLabel, "Анализ отменён пользователем")
                        activeJob = null
                    }
                }
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

    private fun publishProgress(runId: Long, targetLabel: String, progress: AnalysisProgress) {
        synchronized(lock) {
            when (val current = mutableState.value) {
                is AnalysisRunState.Running -> if (current.runId == runId) {
                    if (progress.percent < current.progress.percent) return
                    val normalized = progress.copy(percent = progress.percent.coerceIn(0, 100))
                    mutableState.value = AnalysisRunState.Running(runId, targetLabel, normalized)
                    store?.writeRunning(targetLabel, normalized)
                }
                is AnalysisRunState.Cancelling -> if (current.runId == runId) {
                    if (progress.percent < current.progress.percent) return
                    val cancellationProgress = progress.copy(
                        percent = progress.percent.coerceIn(0, 100),
                        detail = "Отмена выполняется… ${progress.detail}",
                    )
                    mutableState.value = AnalysisRunState.Cancelling(runId, targetLabel, cancellationProgress)
                    store?.writeRunning(targetLabel, cancellationProgress, cancelling = true)
                }
                else -> Unit
            }
        }
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
