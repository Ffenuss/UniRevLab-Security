package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AnalysisEtaEstimatorTest {
    @Test
    fun finishTimestampStaysFixedWhenProgressDoesNotAdvance() {
        val estimator = AnalysisEtaEstimator()
        assertNull(estimator.observe(0.10, 0L))
        val finishAt = estimator.observe(0.20, 20_000L)
        assertEquals(180_000L, finishAt)
        assertEquals(finishAt, estimator.observe(0.20, 30_000L))

        val remainingAt20s = requireNotNull(finishAt) - 20_000L
        val remainingAt30s = requireNotNull(estimator.observe(0.20, 30_000L)) - 30_000L
        assertEquals(10_000L, remainingAt20s - remainingAt30s)
    }
}
