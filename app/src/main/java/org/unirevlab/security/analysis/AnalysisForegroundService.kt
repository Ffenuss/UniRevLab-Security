package org.unirevlab.security.analysis

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.unirevlab.security.MainActivity

/** Keeps a user-started long local analysis alive while the display is off. */
class AnalysisForegroundService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var stateJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        AnalysisManager.initialize(applicationContext)
        createNotificationChannel()
        stateJob = serviceScope.launch {
            var lastNotificationAtMs = 0L
            var lastNotificationStage: AnalysisStage? = null
            AnalysisManager.state.collect { state ->
                when (state) {
                    is AnalysisRunState.Running,
                    is AnalysisRunState.Cancelling -> {
                        val progress = when (state) {
                            is AnalysisRunState.Running -> state.progress
                            is AnalysisRunState.Cancelling -> state.progress
                            else -> null
                        }
                        val now = SystemClock.elapsedRealtime()
                        val stageChanged = progress?.stage != lastNotificationStage
                        if (stageChanged || state is AnalysisRunState.Cancelling || now - lastNotificationAtMs >= 1_000L) {
                            notificationManager().notify(NOTIFICATION_ID, buildNotification(state))
                            lastNotificationAtMs = now
                            lastNotificationStage = progress?.stage
                        }
                    }
                    is AnalysisRunState.Completed,
                    is AnalysisRunState.Cancelled,
                    is AnalysisRunState.Failed,
                    is AnalysisRunState.Interrupted,
                    AnalysisRunState.Idle -> if (!AnalysisManager.isRunningInProcess()) stopSelf()
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CANCEL -> {
                AnalysisManager.cancel()
                return START_NOT_STICKY
            }
            ACTION_STOP -> {
                releaseWakeLock()
                stopSelf()
                return START_NOT_STICKY
            }
        }

        val state = AnalysisManager.state.value
        if (state !is AnalysisRunState.Running && state !is AnalysisRunState.Cancelling) {
            stopSelf()
            return START_NOT_STICKY
        }
        acquireWakeLock()
        startForeground(NOTIFICATION_ID, buildNotification(state))
        return START_STICKY
    }

    override fun onDestroy() {
        stateJob?.cancel()
        releaseWakeLock()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun acquireWakeLock() {
        val pm = getSystemService(PowerManager::class.java)
        val lock = wakeLock ?: pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:analysis").also {
            it.setReferenceCounted(false)
            wakeLock = it
        }
        if (!lock.isHeld) lock.acquire(TimeUnit.DAYS.toMillis(1))
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun buildNotification(state: AnalysisRunState): Notification {
        val progress = when (state) {
            is AnalysisRunState.Running -> state.progress
            is AnalysisRunState.Cancelling -> state.progress
            else -> null
        }
        val target = when (state) {
            is AnalysisRunState.Running -> state.targetLabel
            is AnalysisRunState.Cancelling -> state.targetLabel
            else -> "UniRevLab"
        }
        val cancelling = state is AnalysisRunState.Cancelling
        val openIntent = PendingIntent.getActivity(
            this,
            100,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val cancelIntent = PendingIntent.getService(
            this,
            101,
            Intent(this, AnalysisForegroundService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(if (cancelling) "UniRevLab: отмена анализа" else "UniRevLab: анализ ${progress?.percent ?: 0}%")
            .setContentText(progress?.let { "${it.stage.title}: ${it.detail}" } ?: target)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$target\n${progress?.stage?.title ?: "Анализ"}: ${progress?.detail ?: "Выполняется"}"))
            .setOnlyAlertOnce(true)
            .setOngoing(!cancelling)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openIntent)
            .setProgress(100, progress?.percent ?: 0, false)
            .apply {
                if (!cancelling) addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отменить", cancelIntent)
            }
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Анализ приложений",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Прогресс длительного локального статического анализа"
                setShowBadge(false)
            }
            notificationManager().createNotificationChannel(channel)
        }
    }

    private fun notificationManager(): NotificationManager = getSystemService(NotificationManager::class.java)

    companion object {
        private const val CHANNEL_ID = "analysis_progress_v1"
        private const val NOTIFICATION_ID = 2201
        private const val ACTION_CANCEL = "org.unirevlab.security.action.CANCEL_ANALYSIS"
        private const val ACTION_STOP = "org.unirevlab.security.action.STOP_ANALYSIS_SERVICE"

        fun start(context: Context) {
            val intent = Intent(context, AnalysisForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent) else context.startService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AnalysisForegroundService::class.java))
        }
    }
}
