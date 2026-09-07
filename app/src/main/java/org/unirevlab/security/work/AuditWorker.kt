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
import org.unirevlab.security.analysis.ArtifactBundleExporter
import org.unirevlab.security.analysis.CustomerReportExporter
import org.unirevlab.security.analysis.CustomerActionMapExporter
import org.unirevlab.security.analysis.ModResistanceValidationExporter
import org.unirevlab.security.analysis.ConfirmedDumpOutputExporter
import org.unirevlab.security.analysis.EvidencePackageSigner
import org.unirevlab.security.analysis.GradleModuleEvidenceExporter
import org.unirevlab.security.analysis.InspectionControl
import org.unirevlab.security.analysis.Il2CppInputLocator
import org.unirevlab.security.analysis.LocalArtifactInspector
import org.unirevlab.security.analysis.RealIl2CppDumpEngine
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.VerificationPlanExporter
import org.unirevlab.security.data.AuditJobRepository
import org.unirevlab.security.data.AuditOutputNames
import org.unirevlab.security.model.AuditJobSummary
import org.unirevlab.security.model.AuditSourceSpec
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.PersistedAuditState
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport
import java.io.File
import java.util.concurrent.CancellationException

class AuditWorker(
    appContext: Context,
    parameters: WorkerParameters,
) : Worker(appContext, parameters) {
    private val repository = AuditJobRepository(appContext)
    private val notifications = appContext.getSystemService(NotificationManager::class.java)
    private var notificationSequence = 0
    private var jobLanguage = "ru"

    override fun doWork(): Result {
        val jobId = inputData.getString(KEY_JOB_ID) ?: return Result.failure(errorData("Не указан job ID"))
        return try {
            val spec = repository.loadSpec(jobId)
            val language = spec.languageCode
            jobLanguage = language
            createNotificationChannel(language)
            update(jobId, AuditStage.PREPARING, 3, tr(language, "Подготовка автономного анализа", "Preparing autonomous analysis"))
            setForegroundAsync(foreground(jobId, 3, tr(language, "Подготовка анализа", "Preparing analysis"))).get()
            val inspector = LocalArtifactInspector(applicationContext)
            val inspectionControl = InspectionControl(
                progressSink = { event ->
                    val scaledProgress = 4 + (event.progress.coerceIn(0, 100) * 84 / 100)
                    update(
                        jobId = jobId,
                        stage = event.stage.toAuditStage(),
                        progress = scaledProgress.coerceAtMost(88),
                        message = if (language == "en") englishStageMessage(event.stage, event.current, event.total) else event.message,
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
            update(jobId, AuditStage.REPORT, 89, tr(language, "Потоковая запись полного JSON без дублирования в памяти", "Streaming the full JSON without duplicating it in memory"))
            val reportFile = repository.outputFile(jobId, AuditJobRepository.REPORT_JSON)
            val customerFile = repository.outputFile(jobId, AuditJobRepository.CUSTOMER_REPORT)
            val offsetsFile = repository.outputFile(jobId, AuditJobRepository.OFFSET_EVIDENCE)
            val readableOffsetsFile = repository.outputFile(jobId, AuditJobRepository.OFFSET_READABLE)
            val managedDumpFile = repository.outputFile(jobId, AuditJobRepository.IL2CPP_DUMP)
            val gradleEvidenceFile = repository.outputFile(jobId, AuditJobRepository.GRADLE_MODULE_EVIDENCE)
            val planFile = repository.outputFile(jobId, AuditJobRepository.VERIFICATION_PLAN)
            val actionMapFile = repository.outputFile(jobId, AuditJobRepository.CUSTOMER_ACTION_MAP)
            val modResistanceFile = repository.outputFile(jobId, AuditJobRepository.MOD_RESISTANCE_VALIDATION)
            writeTextAtomically(reportFile) { output -> ReportJsonExporter.write(report, output) }
            update(jobId, AuditStage.REPORT, 90, tr(language, "Полный JSON записан; готовим офсеты и план проверок", "Full JSON written; preparing offsets and verification plan"))
            planFile.writeText(VerificationPlanExporter.export(report), Charsets.UTF_8)
            val actionMap = CustomerActionMapExporter.build(report)
            actionMapFile.writeText(actionMap.toString(2), Charsets.UTF_8)
            modResistanceFile.writeText(ModResistanceValidationExporter.export(report, actionMap, language), Charsets.UTF_8)

            ensureActive()
            update(jobId, AuditStage.GRADLE_MODULES, 91, tr(language, "Поиск Gradle metadata, base/split и dynamic-feature модулей", "Discovering Gradle metadata, base/split, and dynamic-feature modules"))
            val gradleEvidence = GradleModuleEvidenceExporter.export(
                context = applicationContext,
                source = spec.source,
                destination = gradleEvidenceFile,
                cancelled = { isStopped },
                onProgress = { message -> update(jobId, AuditStage.GRADLE_MODULES, 92, if (language == "en") "Reading Gradle and module evidence" else message) },
            )
            ensureActive()
            update(jobId, AuditStage.ARTIFACTS, 93, tr(language, "Автопоиск DEX, native и runtime-артефактов", "Automatically discovering DEX, native, and runtime artifacts"))
            val artifactResult = ArtifactBundleExporter.export(
                context = applicationContext,
                source = spec.source,
                destination = repository.outputFile(jobId, AuditJobRepository.ARTIFACT_BUNDLE),
                cancelled = { isStopped },
                onProgress = { count, name ->
                    update(jobId, AuditStage.ARTIFACTS, (93 + count / 24).coerceAtMost(97), if (language == "en") "Artifact: $name" else name)
                },
            )
            val realDump = writeRealManagedDump(
                jobId = jobId,
                source = spec.source,
                destination = managedDumpFile,
                packageDestination = repository.outputFile(jobId, AuditJobRepository.IL2CPP_DUMP_PACKAGE),
                offsetsDestination = offsetsFile,
                readableOffsetsDestination = readableOffsetsFile,
                languageCode = language,
            )
            customerFile.writeText(CustomerReportExporter.export(report, gradleEvidence, language, realDump), Charsets.UTF_8)
            customerFile.appendText(
                if (language == "en") {
                    "\n\n## Real IL2CPP dump\n\n" + if (realDump?.complete == true) {
                        "- Status: COMPLETE\n- Engine: ${realDump.engine}\n- Metadata: v${realDump.metadataVersion}\n" +
                            "- Successful ABIs: ${realDump.successfulAbis.joinToString()}\n- Failed ABIs: ${realDump.failedAbis.joinToString().ifBlank { "none" }}\n" +
                            "- CodeRegistration (primary ABI): ${realDump.codeRegistration}\n- MetadataRegistration (primary ABI): ${realDump.metadataRegistration}\n" +
                            "- Confirmed gameplay surfaces: ${realDump.gameplaySurfaceCount}\n- Application/monetization surfaces: ${realDump.applicationSurfaceCount}\n"
                    } else {
                        "- Status: NOT_AVAILABLE\n- Reason: ${realDump?.error ?: "matching global-metadata.dat/libil2cpp.so pair not found"}\n" +
                            "- No offsets were created or guessed.\n"
                    }
                } else {
                    "\n\n## Настоящий IL2CPP dump\n\n" + if (realDump?.complete == true) {
                        "- Статус: COMPLETE\n- Движок: ${realDump.engine}\n- Metadata: v${realDump.metadataVersion}\n" +
                            "- Успешные ABI: ${realDump.successfulAbis.joinToString()}\n- Неуспешные ABI: ${realDump.failedAbis.joinToString().ifBlank { "нет" }}\n" +
                            "- CodeRegistration (основной ABI): ${realDump.codeRegistration}\n- MetadataRegistration (основной ABI): ${realDump.metadataRegistration}\n" +
                            "- Игровые поверхности: ${realDump.gameplaySurfaceCount}\n- Приложение/монетизация: ${realDump.applicationSurfaceCount}\n"
                    } else {
                        "- Статус: NOT_AVAILABLE\n- Причина: ${realDump?.error ?: "не найдена совместимая пара global-metadata.dat/libil2cpp.so"}\n" +
                            "- Офсеты не создавались и не угадывались.\n"
                    }
                },
                Charsets.UTF_8,
            )

            ensureActive()
            update(jobId, AuditStage.SIGNING, 98, tr(language, "Подпись целостности пакета доказательств", "Signing evidence package integrity"))
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
                packageEntryNames = (signedInputs +
                    repository.outputFile(jobId, AuditJobRepository.EVIDENCE_MANIFEST) +
                    repository.outputFile(jobId, AuditJobRepository.EVIDENCE_SIGNATURE))
                    .associate { it.name to AuditOutputNames.localized(it.name, language) },
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
                il2cppDetected = report.il2cpp?.detected == true || realDump?.pairLocated == true,
                il2cppMetadataVersion = realDump?.metadataVersion?.toInt() ?: report.il2cpp?.metadata?.metadataVersion,
                il2cppDetectionSource = when {
                    realDump?.complete == true -> "REAL_DUMP_COMPLETE"
                    realDump?.pairLocated == true -> "INPUT_PAIR_LOCATED"
                    report.il2cpp?.detected == true -> "STATIC_SCANNER"
                    else -> "NOT_DETECTED"
                },
                il2cppDumpStatus = realDump?.status,
                il2cppDumpError = realDump?.error,
                il2cppSuccessfulAbis = realDump?.successfulAbis.orEmpty(),
                confirmedGameplaySurfaces = realDump?.gameplaySurfaceCount ?: 0,
                confirmedApplicationSurfaces = realDump?.applicationSurfaceCount ?: 0,
                exportedArtifactCount = artifactResult.includedEntries,
                outputFiles = AuditJobRepository.OUTPUT_FILES.map { repository.outputFile(jobId, it) }.filter(File::isFile).map(File::getName).sorted(),
                languageCode = language,
            )
            repository.writeSummary(summary)
            update(jobId, AuditStage.COMPLETE, 100, tr(language, "Готово: пакет доказательств и отчёт сформированы", "Complete: evidence package and report generated"))
            Result.success(workDataOf(KEY_JOB_ID to jobId))
        } catch (cancelled: CancellationException) {
            val message = tr(jobLanguage, "Анализ отменён", "Analysis cancelled")
            persistTerminal(jobId, AuditStage.CANCELLED, message, null)
            Result.failure(errorData(message))
        } catch (error: Throwable) {
            val message = sanitizeError(error)
            persistTerminal(jobId, AuditStage.FAILED, tr(jobLanguage, "Не удалось завершить анализ", "Unable to complete analysis"), message)
            Result.failure(errorData(message))
        }
    }

    override fun onStopped() {
        val jobId = inputData.getString(KEY_JOB_ID)
        if (jobId != null) persistTerminal(jobId, AuditStage.CANCELLED, tr(jobLanguage, "Анализ остановлен", "Analysis stopped"), null)
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
            .setContentTitle(tr(jobLanguage, "UniRevLab: анализ приложения", "UniRevLab: application analysis"))
            .setContentText(message.take(MAX_MESSAGE_LENGTH))
            .setProgress(100, progress.coerceIn(0, 100), false)
            .setOnlyAlertOnce(true)
            .setOngoing(progress < 100)
            .addAction(0, tr(jobLanguage, "Остановить", "Stop"), cancel)
            .setSubText(jobId.take(8))
            .build()
        return if (Build.VERSION.SDK_INT >= 29) {
            ForegroundInfo(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            ForegroundInfo(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel(languageCode: String) {
        if (Build.VERSION.SDK_INT >= 26) {
            notifications.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    tr(languageCode, "Автоматический аудит", "Automatic audit"),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = tr(languageCode, "Ход фонового анализа приложения", "Background application analysis progress")
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
        source: AuditSourceSpec,
        destination: File,
        packageDestination: File,
        offsetsDestination: File,
        readableOffsetsDestination: File,
        languageCode: String,
    ): RealIl2CppDumpEngine.Result? {
        val outputDirectory = File(destination.parentFile, ".real-il2cpp-$id")
        var located: Il2CppInputLocator.Result? = null
        try {
            located = Il2CppInputLocator.locate(
                context = applicationContext,
                source = source,
                workingDirectory = requireNotNull(destination.parentFile),
                token = id.toString(),
                cancelled = { isStopped },
            )
            val metadata = located.metadataFile
            val libraries = located.libraries
            val result = if (metadata == null || libraries.isEmpty()) {
                val missing = buildList {
                    if (metadata == null) add("global-metadata.dat")
                    if (libraries.isEmpty()) add("libil2cpp.so")
                }.joinToString(" + ")
                val details = located.diagnostics.joinToString("; ").take(500)
                RealIl2CppDumpEngine.notAvailable(
                    tr(languageCode, "Не найдено напрямую во входном APK/APKS: $missing", "Not found directly in the input APK/APKS: $missing") +
                        details.takeIf(String::isNotBlank)?.let { ". $it" }.orEmpty()
                )
            } else {
                update(
                    jobId,
                    AuditStage.IL2CPP,
                    97,
                    tr(languageCode, "Настоящий IL2CPP dump для ABI: ${libraries.joinToString { it.abi }}", "Real IL2CPP dump for ABIs: ${libraries.joinToString { it.abi }}"),
                )
                RealIl2CppDumpEngine.dumpMultiple(metadata, libraries, outputDirectory)
            }
            if (result?.complete == true) {
                requireNotNull(result.dumpCsFile).copyTo(destination, overwrite = true)
                requireNotNull(result.packageFile).copyTo(packageDestination, overwrite = true)
            }
            ConfirmedDumpOutputExporter.write(result, outputDirectory, offsetsDestination, readableOffsetsDestination, languageCode)
            return result
        } finally {
            located?.cleanup()
            outputDirectory.deleteRecursively()
            File(outputDirectory.parentFile, "${outputDirectory.name}-real-il2cpp-dump.zip").delete()
        }
    }

    private fun tr(languageCode: String, russian: String, english: String): String =
        if (languageCode == "en") english else russian

    private fun englishStageMessage(stage: String, current: Int?, total: Int?): String {
        val base = when (stage.lowercase()) {
            "archive" -> "Reading APK/archive structure and signatures"
            "manifest" -> "Parsing manifest and resources"
            "dex", "reachability" -> "Indexing DEX calls and trust surfaces"
            "native" -> "Analyzing native ELF and JNI"
            "il2cpp", "runtime" -> "Locating IL2CPP and runtime metadata"
            "supply_chain" -> "Building component and dependency inventory"
            "report", "findings", "saving", "complete" -> "Preparing findings and report evidence"
            else -> "Preparing analysis input"
        }
        return if (current != null && total != null && total > 0) "$base · $current/$total" else base
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
