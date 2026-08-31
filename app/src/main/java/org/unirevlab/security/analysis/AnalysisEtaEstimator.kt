package org.unirevlab.security.analysis

import java.util.ArrayDeque

/**
 * Estimates a finish timestamp from observed monotonic progress rather than from elapsed/percent.
 *
 * The important property for the UI is that between real progress checkpoints the estimated finish
 * timestamp stays fixed, so the displayed remaining time counts down instead of increasing every
 * second while an integer percentage is unchanged.
 */
internal class AnalysisEtaEstimator(
    private val windowMs: Long = 180_000L,
    private val minSpanMs: Long = 10_000L,
    private val minFractionDelta: Double = 0.001,
) {
    private data class Sample(val timestampMs: Long, val fraction: Double)

    private val samples = ArrayDeque<Sample>()
    private var lastFraction = -1.0
    private var estimatedFinishAtMs: Long? = null

    @Synchronized
    fun observe(fraction: Double, timestampMs: Long): Long? {
        if (!fraction.isFinite()) return estimatedFinishAtMs
        val normalized = fraction.coerceIn(0.0, 1.0)
        if (normalized >= 1.0) {
            lastFraction = 1.0
            estimatedFinishAtMs = timestampMs
            return timestampMs
        }
        if (lastFraction >= 0.0 && normalized + EPSILON < lastFraction) return estimatedFinishAtMs
        if (lastFraction >= 0.0 && normalized <= lastFraction + EPSILON) return estimatedFinishAtMs

        lastFraction = normalized
        samples.addLast(Sample(timestampMs, normalized))
        while (samples.size > 2 && timestampMs - samples.first.timestampMs > windowMs) {
            samples.removeFirst()
        }

        if (samples.size < 2) return estimatedFinishAtMs
        val first = samples.first
        val spanMs = timestampMs - first.timestampMs
        val advanced = normalized - first.fraction
        if (spanMs < minSpanMs || advanced < minFractionDelta) return estimatedFinishAtMs

        val ratePerMs = advanced / spanMs.toDouble()
        if (ratePerMs <= 0.0 || !ratePerMs.isFinite()) return estimatedFinishAtMs
        val remainingMs = ((1.0 - normalized) / ratePerMs).toLong()
        if (remainingMs <= 0L || remainingMs > MAX_ETA_MS) return estimatedFinishAtMs

        val rawFinish = timestampMs + remainingMs
        estimatedFinishAtMs = estimatedFinishAtMs?.let { previous ->
            previous + ((rawFinish - previous) * SMOOTHING).toLong()
        } ?: rawFinish
        return estimatedFinishAtMs
    }

    companion object {
        private const val EPSILON = 0.0000001
        private const val SMOOTHING = 0.25
        private const val MAX_ETA_MS = 12L * 60L * 60L * 1_000L
    }
}
