package org.unirevlab.security.analysis

import android.content.Context

/** Small crash/restart marker. It intentionally stores only status text, never report evidence. */
internal class AnalysisRunStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    data class Snapshot(
        val status: String,
        val targetLabel: String?,
        val percent: Int?,
        val stage: String?,
        val detail: String?,
        val startedAtEpochMs: Long?,
        val updatedAtEpochMs: Long?,
    )

    fun load(): Snapshot? {
        val status = prefs.getString(KEY_STATUS, null) ?: return null
        return Snapshot(
            status = status,
            targetLabel = prefs.getString(KEY_TARGET, null),
            percent = prefs.takeIf { it.contains(KEY_PERCENT) }?.getInt(KEY_PERCENT, 0),
            stage = prefs.getString(KEY_STAGE, null),
            detail = prefs.getString(KEY_DETAIL, null),
            startedAtEpochMs = prefs.takeIf { it.contains(KEY_STARTED) }?.getLong(KEY_STARTED, 0L),
            updatedAtEpochMs = prefs.takeIf { it.contains(KEY_UPDATED) }?.getLong(KEY_UPDATED, 0L),
        )
    }

    fun writeRunning(targetLabel: String, progress: AnalysisProgress, cancelling: Boolean = false) {
        prefs.edit()
            .putString(KEY_STATUS, if (cancelling) STATUS_CANCELLING else STATUS_RUNNING)
            .putString(KEY_TARGET, targetLabel)
            .putInt(KEY_PERCENT, progress.percent)
            .putString(KEY_STAGE, progress.stage.title)
            .putString(KEY_DETAIL, progress.detail)
            .putLong(KEY_STARTED, progress.startedAtEpochMs)
            .putLong(KEY_UPDATED, progress.updatedAtEpochMs)
            .apply()
    }

    fun writeTerminal(status: String, targetLabel: String?, detail: String? = null) {
        prefs.edit()
            .putString(KEY_STATUS, status)
            .putString(KEY_TARGET, targetLabel)
            .putString(KEY_DETAIL, detail)
            .putLong(KEY_UPDATED, System.currentTimeMillis())
            .apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        const val STATUS_RUNNING = "RUNNING"
        const val STATUS_CANCELLING = "CANCELLING"
        const val STATUS_COMPLETED = "COMPLETED"
        const val STATUS_CANCELLED = "CANCELLED"
        const val STATUS_FAILED = "FAILED"
        const val STATUS_INTERRUPTED = "INTERRUPTED"

        private const val PREFS = "analysis-run-state-v1"
        private const val KEY_STATUS = "status"
        private const val KEY_TARGET = "target"
        private const val KEY_PERCENT = "percent"
        private const val KEY_STAGE = "stage"
        private const val KEY_DETAIL = "detail"
        private const val KEY_STARTED = "started"
        private const val KEY_UPDATED = "updated"
    }
}
