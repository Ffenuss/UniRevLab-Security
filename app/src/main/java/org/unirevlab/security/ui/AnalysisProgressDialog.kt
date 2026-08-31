package org.unirevlab.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.unirevlab.security.analysis.AnalysisRunState

@Composable
fun AnalysisProgressDialog(
    state: AnalysisRunState,
    onCancel: () -> Unit,
    onCloseTerminal: () -> Unit,
) {
    when (state) {
        is AnalysisRunState.Running -> ActiveAnalysisDialog(
            target = state.targetLabel,
            progress = state.progress,
            cancelling = false,
            onCancel = onCancel,
        )
        is AnalysisRunState.Cancelling -> ActiveAnalysisDialog(
            target = state.targetLabel,
            progress = state.progress,
            cancelling = true,
            onCancel = onCancel,
        )
        is AnalysisRunState.Cancelled -> TerminalAnalysisDialog(
            title = "Анализ отменён",
            message = "${state.targetLabel}: активные DEX/native задачи остановлены. Можно запускать новый анализ.",
            onClose = onCloseTerminal,
        )
        is AnalysisRunState.Interrupted -> TerminalAnalysisDialog(
            title = "Предыдущий анализ был прерван",
            message = state.message,
            onClose = onCloseTerminal,
        )
        is AnalysisRunState.Failed -> TerminalAnalysisDialog(
            title = "Анализ завершился ошибкой",
            message = "${state.targetLabel}: ${state.message}",
            onClose = onCloseTerminal,
        )
        else -> Unit
    }
}

@Composable
private fun ActiveAnalysisDialog(
    target: String,
    progress: org.unirevlab.security.analysis.AnalysisProgress,
    cancelling: Boolean,
    onCancel: () -> Unit,
) {
    val now by produceState(
        initialValue = System.currentTimeMillis(),
        key1 = progress.startedAtEpochMs,
    ) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1_000)
        }
    }
    val elapsedMs = (now - progress.startedAtEpochMs).coerceAtLeast(0L)
    val unchangedMs = (now - progress.updatedAtEpochMs).coerceAtLeast(0L)
    val remainingMs = progress.estimatedFinishAtEpochMs
        ?.minus(now)
        ?.takeIf { it > 0L && unchangedMs < 180_000L }
    val percentLabel = formatProgressPercent(progress.fractionComplete)

    AlertDialog(
        onDismissRequest = { /* Analysis state must remain visible while work is active. */ },
        title = {
            Text(
                if (cancelling) "Останавливаем анализ" else "Анализ выполняется — $percentLabel",
                fontWeight = FontWeight.SemiBold,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(target, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(progress.stage.title, fontWeight = FontWeight.Medium)
                    Text(percentLabel, fontWeight = FontWeight.Bold)
                }
                LinearProgressIndicator(
                    progress = { progress.fractionComplete.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(progress.detail)
                progress.totalUnits?.takeIf { it > 0 }?.let { total ->
                    val completed = progress.completedUnits?.coerceIn(0, total) ?: 0
                    Text("Объекты текущего этапа: $completed / $total", style = MaterialTheme.typography.bodySmall)
                }
                Text(
                    buildString {
                        append("Прошло: ${formatDuration(elapsedMs)}")
                        if (remainingMs != null) {
                            append(" · Осталось примерно: ${formatDuration(remainingMs)}")
                        } else if (!cancelling) {
                            append(" · Осталось: оценка уточняется")
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (!cancelling && unchangedMs >= 30_000L) {
                    Text(
                        "Подэтап не сменился ${formatDuration(unchangedMs)}. Для большого DEX/ELF это допустимо; " +
                            "сессия всё ещё активна, а внутренние счётчики обновятся на ближайшей контрольной точке.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    if (cancelling) {
                        "Запрос на отмену принят. Прерываем активные DEX/native worker-задачи и освобождаем временные файлы."
                    } else {
                        "Экран можно заблокировать или выключить — анализ продолжится в foreground-режиме. " +
                            "Полное выключение или перезагрузка телефона прервёт текущую сессию; после запуска приложение сообщит об этом явно."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onCancel, enabled = !cancelling) {
                Text(if (cancelling) "Остановка…" else "Отменить анализ")
            }
        },
    )
}

@Composable
private fun TerminalAnalysisDialog(
    title: String,
    message: String,
    onClose: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(title, fontWeight = FontWeight.SemiBold) },
        text = { Text(message) },
        confirmButton = {
            TextButton(onClick = onClose) { Text("Закрыть") }
        },
    )
}

private fun formatProgressPercent(fraction: Double): String {
    val value = (fraction.coerceIn(0.0, 1.0) * 1000.0).toInt() / 10.0
    return if (value % 1.0 == 0.0) "${value.toInt()}%" else "${value}%"
}

private fun formatDuration(durationMs: Long): String {
    val totalSeconds = (durationMs / 1_000L).coerceAtLeast(0L)
    val hours = totalSeconds / 3_600L
    val minutes = (totalSeconds % 3_600L) / 60L
    val seconds = totalSeconds % 60L
    return when {
        hours > 0 -> "${hours}ч ${minutes}м"
        minutes > 0 -> "${minutes}м ${seconds}с"
        else -> "${seconds}с"
    }
}
