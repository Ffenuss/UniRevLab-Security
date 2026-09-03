package org.unirevlab.security.data

import android.content.Context
import org.unirevlab.security.model.AuditJobSpec
import org.unirevlab.security.model.AuditJobSummary
import org.unirevlab.security.model.AuditProfile
import org.unirevlab.security.model.AuditSourceSpec
import org.unirevlab.security.model.AuditStage
import org.unirevlab.security.model.AuditWorkflowJson
import org.unirevlab.security.model.PersistedAuditState
import java.io.File
import java.util.UUID

class AuditJobRepository(context: Context) {
    private val appContext = context.applicationContext
    private val root = File(appContext.filesDir, JOBS_DIRECTORY)
    private val preferences = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    init {
        require(root.isDirectory || root.mkdirs()) { "Не удалось создать каталог заданий" }
    }

    fun saveProfile(profile: AuditProfile) {
        require(profile.isValid) { "Профиль аудита заполнен не полностью" }
        preferences.edit().putString(KEY_PROFILE, AuditWorkflowJson.encodeProfile(profile)).apply()
    }

    fun loadProfile(): AuditProfile? = preferences.getString(KEY_PROFILE, null)?.let { raw ->
        runCatching { AuditWorkflowJson.decodeProfile(raw) }.getOrNull()
    }

    fun createJob(profile: AuditProfile, source: AuditSourceSpec): AuditJobSpec {
        require(profile.isValid) { "Сначала заполните профиль аудита" }
        validateSource(source)
        val spec = AuditJobSpec(
            jobId = UUID.randomUUID().toString(),
            createdAtEpochMs = System.currentTimeMillis(),
            scope = profile.createScope(),
            source = source,
        )
        val dir = jobDirectory(spec.jobId)
        require(dir.isDirectory || dir.mkdirs()) { "Не удалось создать каталог задания" }
        atomicWrite(specFile(spec.jobId), AuditWorkflowJson.encodeSpec(spec))
        writeState(
            PersistedAuditState(
                jobId = spec.jobId,
                stage = AuditStage.QUEUED,
                progress = 0,
                message = AuditStage.QUEUED.title,
                updatedAtEpochMs = System.currentTimeMillis(),
            )
        )
        preferences.edit().putString(KEY_CURRENT_JOB_ID, spec.jobId).apply()
        return spec
    }

    fun rememberWork(jobId: String, workId: UUID) {
        validatedJobId(jobId)
        preferences.edit()
            .putString(KEY_CURRENT_JOB_ID, jobId)
            .putString(KEY_CURRENT_WORK_ID, workId.toString())
            .apply()
    }

    fun currentJobId(): String? = preferences.getString(KEY_CURRENT_JOB_ID, null)
        ?.takeIf { runCatching { validatedJobId(it) }.isSuccess }

    fun currentWorkId(): UUID? = preferences.getString(KEY_CURRENT_WORK_ID, null)?.let { raw ->
        runCatching { UUID.fromString(raw) }.getOrNull()
    }

    fun loadSpec(jobId: String): AuditJobSpec =
        AuditWorkflowJson.decodeSpec(specFile(jobId).readText(Charsets.UTF_8))

    fun writeSummary(summary: AuditJobSummary) {
        atomicWrite(summaryFile(summary.jobId), AuditWorkflowJson.encodeSummary(summary))
    }

    fun loadSummary(jobId: String): AuditJobSummary? = summaryFile(jobId).takeIf(File::isFile)?.let { file ->
        runCatching { AuditWorkflowJson.decodeSummary(file.readText(Charsets.UTF_8)) }.getOrNull()
    }

    fun writeState(state: PersistedAuditState) {
        atomicWrite(stateFile(state.jobId), AuditWorkflowJson.encodeState(state))
    }

    fun loadState(jobId: String): PersistedAuditState? = stateFile(jobId).takeIf(File::isFile)?.let { file ->
        runCatching { AuditWorkflowJson.decodeState(file.readText(Charsets.UTF_8)) }.getOrNull()
    }

    fun jobDirectory(jobId: String): File = File(root, validatedJobId(jobId))

    fun outputFile(jobId: String, fileName: String): File {
        require(fileName in OUTPUT_FILES) { "Неизвестный выходной файл" }
        return File(jobDirectory(jobId), fileName)
    }

    private fun specFile(jobId: String) = File(jobDirectory(jobId), SPEC_FILE)
    private fun summaryFile(jobId: String) = File(jobDirectory(jobId), SUMMARY_FILE)
    private fun stateFile(jobId: String) = File(jobDirectory(jobId), STATE_FILE)

    private fun validateSource(source: AuditSourceSpec) {
        require(source.displayName.isNotBlank()) { "Не указано имя цели" }
        when (source.kind) {
            org.unirevlab.security.model.AuditSourceKind.FILE_URI ->
                require(!source.uri.isNullOrBlank()) { "Не указан URI файла" }
            org.unirevlab.security.model.AuditSourceKind.INSTALLED_APP -> {
                require(!source.packageName.isNullOrBlank()) { "Не указан package name" }
                require(!source.baseApkPath.isNullOrBlank()) { "Не указан путь base APK" }
            }
        }
    }

    private fun validatedJobId(jobId: String): String {
        require(JOB_ID.matches(jobId)) { "Некорректный идентификатор задания" }
        return jobId
    }

    private fun atomicWrite(destination: File, content: String) {
        require(destination.parentFile?.isDirectory == true || destination.parentFile?.mkdirs() == true) {
            "Не удалось создать каталог результата"
        }
        val temporary = File(destination.parentFile, ".${destination.name}.tmp")
        temporary.writeText(content, Charsets.UTF_8)
        if (!temporary.renameTo(destination)) {
            destination.outputStream().use { output -> temporary.inputStream().use { it.copyTo(output) } }
            check(temporary.delete()) { "Не удалось завершить атомарную запись" }
        }
    }

    companion object {
        const val REPORT_JSON = "full-report.json"
        const val CUSTOMER_REPORT = "customer-report.md"
        const val OFFSET_EVIDENCE = "offset-evidence.json"
        const val IL2CPP_DUMP = "il2cpp-dump.cs"
        const val GRADLE_MODULE_EVIDENCE = "gradle-module-evidence.json"
        const val VERIFICATION_PLAN = "verification-plan.json"
        const val ARTIFACT_BUNDLE = "analysis-artifacts.zip"
        const val EVIDENCE_MANIFEST = "evidence-manifest.json"
        const val EVIDENCE_SIGNATURE = "evidence-signature.json"
        const val SIGNED_EVIDENCE_PACKAGE = "signed-evidence-package.zip"

        val OUTPUT_FILES = setOf(
            REPORT_JSON,
            CUSTOMER_REPORT,
            OFFSET_EVIDENCE,
            IL2CPP_DUMP,
            GRADLE_MODULE_EVIDENCE,
            VERIFICATION_PLAN,
            ARTIFACT_BUNDLE,
            EVIDENCE_MANIFEST,
            EVIDENCE_SIGNATURE,
            SIGNED_EVIDENCE_PACKAGE,
        )

        private const val JOBS_DIRECTORY = "audit-jobs"
        private const val PREFERENCES = "audit_jobs"
        private const val KEY_PROFILE = "last_profile"
        private const val KEY_CURRENT_JOB_ID = "current_job_id"
        private const val KEY_CURRENT_WORK_ID = "current_work_id"
        private const val SPEC_FILE = "job-spec.json"
        private const val SUMMARY_FILE = "job-summary.json"
        private const val STATE_FILE = "job-state.json"
        private val JOB_ID = Regex("[0-9a-fA-F-]{36}")
    }
}
