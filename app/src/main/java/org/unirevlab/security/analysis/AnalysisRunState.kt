package org.unirevlab.security.analysis

import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.StaticAnalysisReport

enum class AnalysisStage(val title: String) {
    PREPARING("Подготовка"),
    HASHING("Чтение и SHA-256"),
    CACHE("Проверка кэша"),
    ARCHIVE("Индекс APK/ZIP"),
    MANIFEST("Manifest и resources"),
    DEX("DEX анализ"),
    REACHABILITY("Связность Manifest → DEX"),
    NATIVE("Native / ELF анализ"),
    IL2CPP("IL2CPP"),
    RUNTIME("Runtime профили"),
    SUPPLY_CHAIN("Supply-chain / SBOM"),
    FINDINGS("Формирование findings"),
    SAVING("Сохранение результата"),
    COMPLETE("Готово"),
}

data class AnalysisProgress(
    val stage: AnalysisStage,
    val percent: Int,
    val detail: String,
    val completedUnits: Int? = null,
    val totalUnits: Int? = null,
    val startedAtEpochMs: Long,
    val updatedAtEpochMs: Long = System.currentTimeMillis(),
    val fractionComplete: Double = percent / 100.0,
    val estimatedFinishAtEpochMs: Long? = null,
) {
    init {
        require(percent in 0..100)
        require(fractionComplete.isFinite() && fractionComplete in 0.0..1.0)
    }
}

sealed interface AnalysisRunState {
    data object Idle : AnalysisRunState

    data class Running(
        val runId: Long,
        val targetLabel: String,
        val assessmentScope: AssessmentScope,
        val progress: AnalysisProgress,
    ) : AnalysisRunState

    data class Cancelling(
        val runId: Long,
        val targetLabel: String,
        val assessmentScope: AssessmentScope,
        val progress: AnalysisProgress,
    ) : AnalysisRunState

    data class Completed(
        val runId: Long,
        val targetLabel: String,
        val report: StaticAnalysisReport,
        val finishedAtEpochMs: Long = System.currentTimeMillis(),
        /** Null only when the complete report snapshot was durably stored before completion. */
        val historyPersistError: String? = null,
    ) : AnalysisRunState

    data class Cancelled(
        val runId: Long,
        val targetLabel: String,
        val message: String = "Анализ отменён",
        val finishedAtEpochMs: Long = System.currentTimeMillis(),
    ) : AnalysisRunState

    data class Failed(
        val runId: Long,
        val targetLabel: String,
        val message: String,
        val finishedAtEpochMs: Long = System.currentTimeMillis(),
    ) : AnalysisRunState

    data class Interrupted(
        val targetLabel: String?,
        val message: String,
        val previousPercent: Int? = null,
        val previousStage: String? = null,
    ) : AnalysisRunState
}
