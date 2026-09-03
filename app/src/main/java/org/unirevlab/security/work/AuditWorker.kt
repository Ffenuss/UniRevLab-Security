package org.unirevlab.security.work

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.ServiceInfo
import android.content.Context
import android.os.Build
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import org.unirevlab.security.R
import org.unirevlab.security.analysis.ArtifactBundleExporter
import org.unirevlab.security.analysis.CustomerReportExporter
import org.unirevlab.security.analysis.EvidencePackageSigner
import org.unirevlab.security.analysis.InspectionControl
import org.unirevlab.security.analysis.LocalArtifactInspector
import org.unirevlab.security.analysis.OffsetEvidenceExporter
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.VerificationPlanExporter
import org.unirevlab.security.data.AgreementStore
import org.unirevlab.security.data.AuditJobRepository
import org.unirevlab.security.model.AuditJobSummary
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.PersistedAuditState
import org.unirevlab.security.model.Severity
import java.util.concurrent.CancellationException

class AuditWorker(
    appContext: Context,
    parameters: WorkerParameters,
) : Worker(appContext, parameters) {
    private val repository = AuditJobRepository(appContext)
    private val notifications = appContext.getSystemService(NotificationManager::class.java)
    private var notificationSequence = 0

    override fun doWork(): Result {
        val jobId = inputData.getString(KEY_JOB_ID) ?: return Result.failure(errorData("Не указан job ID"))
        return try {
            require(AgreementStore(applicationContext).isAccepted()) { "Соглашение об авторизованном использовании не подписано" }
            createNotificationChannel()
            update(jobId, AuditStage.PREPARING, 3, "Подготовка автономного анализа")
            setForegroundAsync(foreground(jobId, 3, "Подготовка анализа")).get()

            val spec = repository.loadSpec(jobId)
            require(spec.scope.confirmsAuthority) { "В scope отсутствует подтверждение полномочий" }
            val inspector = LocalArtifactInspector(applicationContext)
            val control = InspectionControl(
                progressSink = { event ->
                    update(
                        jobId = jobId,
                        stage = AuditStage.fromCode(event.stage),
                        progress = event.progress,
                        message = event.message,
                        current = event.current,
                        total = event.total,
                    )
                },
                cancelled = { isStopped },
            )
            val report = when (spec.source.kind) {
                AuditSourceKind.FILE_URI -> inspector.inspect(
                    android.net.Uri.parse(requireNotNull(spec.source.uri)),
                    spec.scope,
                    control,
                )
                AuditSourceKind.INSTALLED_APP -> inspector.inspectInstalledApp(
                    InstalledAppDescriptor(
                        label = spec.source.displayName,
                        packageName = requireNotNull(spec.source.packageName),
                        versionName = spec.source.versionName,
                        versionCode = spec.source.versionCode ?: 0L,
                        isSystem = false,
                        isEnabled = true,
                        baseApkPath = requireNotNull(spec.source.baseApkPath),
                        splitApkPaths = spec.source.splitApkPaths,
                        installerPackageName = spec.source.installerPackageName,
                    ),
                    spec.scope,
                    control,
                )
            }

            ensureActive()
            update(jobId, AuditStage.REPORT, 89, "Сборка полного и клиентского отчётов")
            val reportFile = repository.outputFile(jobId, AuditJobRepository.REPORT_JSON)
            val customerFile = repository.outputFile(jobId, AuditJobRepository.CUSTOMER_REPORT)
            val offsetsFile = repository.outputFile(jobId, AuditJobRepository.OFFSET_EVIDENCE)
            val planFile = repository.outputFile(jobId, AuditJobRepository.VERIFICATION_PLAN)
            reportFile.writeText(ReportJsonExporter.export(report), Charsets.UTF_8)
            customerFile.writeText(CustomerReportExporter.export(report), Charsets.UTF_8)
            offsetsFile.writeText(OffsetEvidenceExporter.export(report), Charsets.UTF_8)
            planFile.writeText(VerificationPlanExporter.export(report), Charsets.UTF_8)

            ensureActive()
            update(jobId, AuditStage.ARTIFACTS, 93, "Автопоиск DEX, native и runtime-артефактов")
            val artifactResult = ArtifactBundleExporter.export(
                context = applicationContext,
                source = spec.source,
                destination = repository.outputFile(jobId, AuditJobRepository.ARTIFACT_BUNDLE),
                cancelled = { isStopped },
                onProgress = { count, name ->
                    update(jobId, AuditStage.ARTIFACTS, (93 + count / 24).coerceAtMost(97), name)
                },
            )

            ensureActive()
            update(jobId, AuditStage.SIGNING, 98, "Подпись целостности evidence-пакета")
            val signedInputs = listOf(
                reportFile,
                customerFile,
                offsetsFile,
                planFile,
                repository.outputFile(jobId, AuditJobRepository.ARTIFACT_BUNDLE),
            )
            EvidencePackageSigner.create(
                inputs = signedInputs,
                manifestFile = repository.outputFile(jobId, AuditJobRepository.EVIDENCE_MANIFEST),
                signatureFile = repository.outputFile(jobId, AuditJobRepository.EVIDENCE_SIGNATURE),
                packageFile = repository.outputFile(jobId, AuditJobRepository.SIGNED_EVIDENCE_PACKAGE),
                assessmentId = report.assessment.assessmentId,
                artifactSha256 = report.artifact.sha256,
                cancelled = { isStopped },
            )

            ensureActive()
            val summary = AuditJobSummary(
                jobId = jobId,
                completedAtEpochMs = System.currentTimeMillis(),
                displayName = report.artifact.displayName,
                packageName = report.manifest?.packageName ?: report.artifact.sourcePackageName,
                artifactSha256 = report.artifact.sha256,
                runtimeLabels = report.runtimes?.profiles.orEmpty().map { it.kind }.distinct().sorted(),
                findings = report.findings.size,
                critical = report.findings.count { it.severity == Severity.CRITICAL },
                high = report.findings.count { it.severity == Severity.HIGH },
                medium = report.findings.count { it.severity == Severity.MEDIUM },
                dexMethods = report.dex?.methodsIndexed ?: 0L,
                nativeLibraries = report.native?.librariesScanned ?: 0,
                il2cppDetected = report.il2cpp?.detected == true,
                il2cppMetadataVersion = report.il2cpp?.metadata?.metadataVersion,
                exportedArtifactCount = artifactResult.includedEntries,
                outputFiles = AuditJobRepository.OUTPUT_FILES.sorted(),
            )
            repository.writeSummary(summary)
            update(jobId, AuditStage.COMPLETE, 100, "Готово: evidence-пакет и отчёт сформированы")
            Result.success(workDataOf(KEY_JOB_ID to jobId))
        } catch (cancelled: CancellationException) {
            persistTerminal(jobId, AuditStage.CANCELLED, "Анализ отменён", null)
            Result.failure(errorData("Анализ отменён"))
        } catch (error: Throwable) {
            val message = sanitizeError(error)
            persistTerminal(jobId, AuditStage.FAILED, "Не удалось завершить анализ", message)
            Result.failure(errorData(message))
        }
    }

    override fun onStopped() {
        val jobId = inputData.getString(KEY_JOB_ID)
        if (jobId != null) persistTerminal(jobId, AuditStage.CANCELLED, "Анализ остановлен", null)
        super.onStopped()
    }

    private fun update(
        jobId: String,
        stage: AuditStage,
        progress: Int,
        message: String,
        current: Int? = null,
        total: Int? = null,
    ) {
        ensureActive()
        val safeProgress = progress.coerceIn(0, 100)
        repository.writeState(
            PersistedAuditState(jobId, stage, safeProgress, message, System.currentTimeMillis())
        )
        val data = Data.Builder()
            .putString(KEY_STAGE, stage.code)
            .putInt(KEY_PROGRESS, safeProgress)
            .putString(KEY_MESSAGE, message.take(MAX_MESSAGE_LENGTH))
            .apply {
                current?.let { putInt(KEY_CURRENT, it) }
                total?.let { putInt(KEY_TOTAL, it) }
            }
            .build()
        setProgressAsync(data)
        if (notificationSequence++ % NOTIFICATION_UPDATE_INTERVAL == 0 || stage == AuditStage.COMPLETE) {
            setForegroundAsync(foreground(jobId, safeProgress, message))
        }
    }

    private fun persistTerminal(jobId: String, stage: AuditStage, message: String, error: String?) {
        runCatching {
            repository.writeState(
                PersistedAuditState(jobId, stage, if (stage == AuditStage.COMPLETE) 100 else 0, message, System.currentTimeMillis(), error)
            )
        }
    }

    private fun foreground(jobId: String, progress: Int, message: String): ForegroundInfo {
        val cancel = WorkManager.getInstance(applicationContext).createCancelPendingIntent(id)
        val notification = Notification.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(applicationContext.getString(R.string.audit_notification_title))
            .setContentText(message.take(MAX_MESSAGE_LENGTH))
            .setProgress(100, progress.coerceIn(0, 100), false)
            .setOnlyAlertOnce(true)
            .setOngoing(progress < 100)
            .addAction(0, applicationContext.getString(R.string.audit_notification_cancel), cancel)
            .setSubText(jobId.take(8))
            .build()
        return if (Build.VERSION.SDK_INT >= 29) {
            ForegroundInfo(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            ForegroundInfo(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            notifications.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    applicationContext.getString(R.string.audit_notification_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = applicationContext.getString(R.string.audit_notification_channel_description)
                }
            )
        }
    }

    private fun ensureActive() {
        if (isStopped) throw CancellationException("Работа остановлена")
    }

    private fun sanitizeError(error: Throwable): String {
        val text = error.message?.replace('\n', ' ')?.replace('\r', ' ')?.trim().orEmpty()
        return (text.ifBlank { error::class.java.simpleName }).take(MAX_ERROR_LENGTH)
    }

    private fun errorData(message: String) = workDataOf(KEY_ERROR to message.take(MAX_ERROR_LENGTH))

    companion object {
        const val KEY_JOB_ID = "job_id"
        const val KEY_STAGE = "stage"
        const val KEY_PROGRESS = "progress"
        const val KEY_MESSAGE = "message"
        const val KEY_CURRENT = "current"
        const val KEY_TOTAL = "total"
        const val KEY_ERROR = "error"
        private const val CHANNEL_ID = "unirevlab_auto_audit"
        private const val NOTIFICATION_ID = 2601
        private const val NOTIFICATION_UPDATE_INTERVAL = 3
        private const val MAX_MESSAGE_LENGTH = 180
        private const val MAX_ERROR_LENGTH = 500
    }
}

object AuditScheduler {
    fun enqueue(context: Context, jobId: String): OneTimeWorkRequest {
        val request = OneTimeWorkRequestBuilder<AuditWorker>()
            .setInputData(workDataOf(AuditWorker.KEY_JOB_ID to jobId))
            .addTag("audit-job:$jobId")
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            uniqueName(jobId),
            ExistingWorkPolicy.REPLACE,
            request,
        )
        return request
    }

    fun cancel(context: Context, workId: java.util.UUID) {
        WorkManager.getInstance(context.applicationContext).cancelWorkById(workId)
    }

    private fun uniqueName(jobId: String) = "unirevlab-audit-$jobId"
}
