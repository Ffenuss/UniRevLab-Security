package org.unirevlab.security.work

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
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
import org.unirevlab.security.analysis.GradleModuleEvidenceExporter
import org.unirevlab.security.analysis.InspectionControl
import org.unirevlab.security.analysis.LocalArtifactInspector
import org.unirevlab.security.analysis.OffsetEvidenceExporter
import org.unirevlab.security.analysis.OffsetReadableExporter
import org.unirevlab.security.analysis.RealIl2CppDumpEngine
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
import org.unirevlab.security.model.StaticAnalysisReport
import java.io.File
import java.util.concurrent.CancellationException
import java.util.zip.ZipFile

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
            val inspectionControl = InspectionControl(
                progressSink = { event ->
                    val scaledProgress = 4 + (event.progress.coerceIn(0, 100) * 84 / 100)
                    update(
                        jobId = jobId,
                        stage = event.stage.toAuditStage(),
                        progress = scaledProgress.coerceAtMost(88),
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
                    inspectionControl,
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
                    inspectionControl,
                )
            }

            ensureActive()
            update(jobId, AuditStage.REPORT, 89, "Потоковая запись полного JSON без дублирования в памяти")
            val reportFile = repository.outputFile(jobId, AuditJobRepository.REPORT_JSON)
            val customerFile = repository.outputFile(jobId, AuditJobRepository.CUSTOMER_REPORT)
            val offsetsFile = repository.outputFile(jobId, AuditJobRepository.OFFSET_EVIDENCE)
            val readableOffsetsFile = repository.outputFile(jobId, AuditJobRepository.OFFSET_READABLE)
            val managedDumpFile = repository.outputFile(jobId, AuditJobRepository.IL2CPP_DUMP)
            val gradleEvidenceFile = repository.outputFile(jobId, AuditJobRepository.GRADLE_MODULE_EVIDENCE)
            val planFile = repository.outputFile(jobId, AuditJobRepository.VERIFICATION_PLAN)
            writeTextAtomically(reportFile) { output -> ReportJsonExporter.write(report, output) }
            update(jobId, AuditStage.REPORT, 90, "Полный JSON записан; готовим offsets и план проверок")
            offsetsFile.writeText(OffsetEvidenceExporter.export(report), Charsets.UTF_8)
            writeTextAtomically(readableOffsetsFile) { output -> OffsetReadableExporter.write(report, output) }
            planFile.writeText(VerificationPlanExporter.export(report), Charsets.UTF_8)

            ensureActive()
            update(jobId, AuditStage.GRADLE_MODULES, 91, "Поиск Gradle metadata, base/split и dynamic-feature модулей")
            val gradleEvidence = GradleModuleEvidenceExporter.export(
                context = applicationContext,
                source = spec.source,
                destination = gradleEvidenceFile,
                cancelled = { isStopped },
                onProgress = { message -> update(jobId, AuditStage.GRADLE_MODULES, 92, message) },
            )
            customerFile.writeText(CustomerReportExporter.export(report, gradleEvidence), Charsets.UTF_8)

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
            val realDump = writeRealManagedDump(
                jobId = jobId,
                artifactBundle = repository.outputFile(jobId, AuditJobRepository.ARTIFACT_BUNDLE),
                destination = managedDumpFile,
                packageDestination = repository.outputFile(jobId, AuditJobRepository.IL2CPP_DUMP_PACKAGE),
            )
            customerFile.appendText(
                "\n\n## Настоящий IL2CPP dump\n\n" +
                    if (realDump?.complete == true) {
                        "- Статус: COMPLETE\n- Engine: ${realDump.engine}\n- Metadata: v${realDump.metadataVersion}\n" +
                            "- CodeRegistration: ${realDump.codeRegistration}\n- MetadataRegistration: ${realDump.metadataRegistration}\n" +
                            "- Игровые поверхности: ${realDump.gameplaySurfaceCount}\n- Приложение/монетизация: ${realDump.applicationSurfaceCount}\n"
                    } else {
                        "- Статус: NOT_AVAILABLE\n- Причина: ${realDump?.error ?: "matching global-metadata.dat/libil2cpp.so pair not found"}\n" +
                            "- Офсеты не создавались и не угадывались.\n"
                    },
                Charsets.UTF_8,
            )

            ensureActive()
            update(jobId, AuditStage.SIGNING, 98, "Подпись целостности evidence-пакета")
            val signedInputs = listOf(
                reportFile,
                customerFile,
                offsetsFile,
                readableOffsetsFile,
                managedDumpFile,
                gradleEvidenceFile,
                planFile,
                repository.outputFile(jobId, AuditJobRepository.ARTIFACT_BUNDLE),
                repository.outputFile(jobId, AuditJobRepository.IL2CPP_DUMP_PACKAGE),
            ).filter(File::isFile)
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
                outputFiles = AuditJobRepository.OUTPUT_FILES.map { repository.outputFile(jobId, it) }.filter(File::isFile).map(File::getName).sorted(),
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
            val previousProgress = repository.loadState(jobId)?.progress ?: 0
            repository.writeState(
                PersistedAuditState(jobId, stage, if (stage == AuditStage.COMPLETE) 100 else previousProgress, message, System.currentTimeMillis(), error)
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

    private fun writeRealManagedDump(
        jobId: String,
        artifactBundle: File,
        destination: File,
        packageDestination: File,
    ): RealIl2CppDumpEngine.Result? {
        var metadataFile: File? = null
        var libraryFile: File? = null
        var nestedApkFile: File? = null
        val outputDirectory = File(destination.parentFile, ".real-il2cpp-$id")
        try {
            if (artifactBundle.isFile) {
                ZipFile(artifactBundle).use { zip ->
                    val entries = zip.entries().asSequence().filterNot { it.isDirectory }.toList()
                    val metadata = entries.firstOrNull { it.name.substringAfterLast('/').equals("global-metadata.dat", ignoreCase = true) }
                    val library = entries.filter { it.name.substringAfterLast('/').equals("libil2cpp.so", ignoreCase = true) }
                        .sortedBy { if (it.name.contains("arm64-v8a", ignoreCase = true)) 0 else 1 }
                        .firstOrNull()
                    if (metadata != null && metadata.size in 1..MAX_METADATA_FOR_DUMP_BYTES) {
                        metadataFile = copyZipEntryBounded(
                            zip,
                            metadata,
                            File(destination.parentFile, ".global-metadata-${id}.tmp"),
                            MAX_METADATA_FOR_DUMP_BYTES,
                        )
                    }
                    if (library != null && library.size in 1..MAX_LIBRARY_FOR_DUMP_BYTES) {
                        libraryFile = copyZipEntryBounded(
                            zip,
                            library,
                            File(destination.parentFile, ".libil2cpp-$id.so"),
                            MAX_LIBRARY_FOR_DUMP_BYTES,
                        )
                    }
                    if (metadataFile == null || libraryFile == null) {
                        val nestedApk = entries.asSequence()
                            .firstOrNull { it.name.endsWith(".apk", ignoreCase = true) && it.size in 1..MAX_NESTED_APK_FOR_DUMP_BYTES }
                        if (nestedApk != null) {
                            nestedApkFile = copyZipEntryBounded(
                                zip,
                                nestedApk,
                                File(destination.parentFile, ".nested-${id}.apk"),
                                MAX_NESTED_APK_FOR_DUMP_BYTES,
                            )
                            ZipFile(requireNotNull(nestedApkFile)).use { nestedZip ->
                                val nestedEntries = nestedZip.entries().asSequence().filterNot { it.isDirectory }.toList()
                                val nestedMetadata = nestedEntries.asSequence()
                                    .firstOrNull { it.name.substringAfterLast('/').equals("global-metadata.dat", ignoreCase = true) }
                                val nestedLibrary = nestedEntries.asSequence()
                                    .filter { it.name.substringAfterLast('/').equals("libil2cpp.so", ignoreCase = true) }
                                    .sortedBy { if (it.name.contains("arm64-v8a", ignoreCase = true)) 0 else 1 }
                                    .firstOrNull()
                                if (nestedMetadata != null && nestedMetadata.size in 1..MAX_METADATA_FOR_DUMP_BYTES) {
                                    metadataFile = copyZipEntryBounded(
                                        nestedZip,
                                        nestedMetadata,
                                        File(destination.parentFile, ".global-metadata-${id}.tmp"),
                                        MAX_METADATA_FOR_DUMP_BYTES,
                                    )
                                }
                                if (nestedLibrary != null && nestedLibrary.size in 1..MAX_LIBRARY_FOR_DUMP_BYTES) {
                                    libraryFile = copyZipEntryBounded(
                                        nestedZip,
                                        nestedLibrary,
                                        File(destination.parentFile, ".libil2cpp-$id.so"),
                                        MAX_LIBRARY_FOR_DUMP_BYTES,
                                    )
                                }
                            }
                        }
                    }
                }
            }
            val metadata = metadataFile ?: return null
            val library = libraryFile ?: return null
            update(jobId, AuditStage.IL2CPP, 97, "Настоящий IL2CPP dump: регистрации, методы, поля и RVA")
            val result = RealIl2CppDumpEngine.dump(metadata, library, outputDirectory)
            if (result.complete) {
                requireNotNull(result.dumpCsFile).copyTo(destination, overwrite = true)
                requireNotNull(result.packageFile).copyTo(packageDestination, overwrite = true)
            }
            return result
        } finally {
            metadataFile?.delete()
            libraryFile?.delete()
            nestedApkFile?.delete()
            outputDirectory.deleteRecursively()
            File(outputDirectory.parentFile, "${outputDirectory.name}-real-il2cpp-dump.zip").delete()
        }
    }

    private fun copyZipEntryBounded(
        zip: ZipFile,
        entry: java.util.zip.ZipEntry,
        destination: File,
        maxBytes: Long,
    ): File {
        var copied = 0L
        zip.getInputStream(entry).buffered().use { input ->
            destination.outputStream().buffered().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    ensureActive()
                    val read = input.read(buffer)
                    if (read <= 0) break
                    copied += read
                    require(copied <= maxBytes) { "Вложенный IL2CPP-артефакт превышает лимит dump" }
                    output.write(buffer, 0, read)
                }
            }
        }
        return destination
    }

    private fun writeTextAtomically(destination: File, block: (Appendable) -> Unit) {
        require(destination.parentFile?.isDirectory == true || destination.parentFile?.mkdirs() == true) {
            "Не удалось создать каталог результата"
        }
        val temporary = File(destination.parentFile, ".${destination.name}.streaming.tmp")
        if (temporary.exists()) check(temporary.delete()) { "Не удалось очистить временный файл отчёта" }
        try {
            temporary.bufferedWriter(Charsets.UTF_8, REPORT_STREAM_BUFFER_BYTES).use { output ->
                block(CancellationAwareAppendable(output) { isStopped })
            }
            if (destination.exists()) check(destination.delete()) { "Не удалось заменить предыдущий результат" }
            if (!temporary.renameTo(destination)) {
                temporary.inputStream().buffered().use { input ->
                    destination.outputStream().buffered().use { output -> input.copyTo(output) }
                }
                check(temporary.delete()) { "Не удалось завершить потоковую запись" }
            }
        } catch (error: Throwable) {
            temporary.delete()
            throw error
        }
    }

    private fun String.toAuditStage(): AuditStage = when (lowercase()) {
        "archive" -> AuditStage.ARCHIVE
        "manifest" -> AuditStage.MANIFEST
        "dex", "reachability" -> AuditStage.DEX
        "native" -> AuditStage.NATIVE
        "il2cpp", "runtime" -> AuditStage.IL2CPP
        "supply_chain" -> AuditStage.SUPPLY_CHAIN
        "report", "findings", "saving", "complete" -> AuditStage.REPORT
        else -> AuditStage.PREPARING
    }

    private class CancellationAwareAppendable(
        private val delegate: Appendable,
        private val cancelled: () -> Boolean,
    ) : Appendable {
        private var operations = 0

        override fun append(value: CharSequence?): Appendable {
            checkpoint()
            delegate.append(value)
            return this
        }

        override fun append(value: CharSequence?, startIndex: Int, endIndex: Int): Appendable {
            checkpoint()
            delegate.append(value, startIndex, endIndex)
            return this
        }

        override fun append(value: Char): Appendable {
            checkpoint()
            delegate.append(value)
            return this
        }

        private fun checkpoint() {
            operations++
            if (operations % STREAM_CANCELLATION_INTERVAL == 0 && cancelled()) {
                throw CancellationException("Потоковая запись отменена")
            }
        }
    }

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
        private const val MAX_METADATA_FOR_DUMP_BYTES = 128L * 1024L * 1024L
        private const val MAX_LIBRARY_FOR_DUMP_BYTES = 256L * 1024L * 1024L
        private const val MAX_NESTED_APK_FOR_DUMP_BYTES = 256L * 1024L * 1024L
        private const val REPORT_STREAM_BUFFER_BYTES = 128 * 1024
        private const val STREAM_CANCELLATION_INTERVAL = 256
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
