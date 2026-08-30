package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedDistinctCollectorTest {
    @Test
    fun matchesDistinctByThenTakeOrder() {
        val input = listOf("a1", "b1", "a2", "c1", "d1", "b2")
        val expected = input.distinctBy { it.first() }.take(3)
        val collector = BoundedDistinctCollector<String, Char>(3) { it.first() }
        collector.addAll(input)
        assertEquals(expected, collector.toList())
        assertTrue(collector.overflowed)
    }

    @Test
    fun duplicateBeyondLimitDoesNotCountAsOverflow() {
        val collector = BoundedDistinctCollector<String, String>(2) { it }
        collector.addAll(listOf("a", "b", "a", "b"))
        assertEquals(listOf("a", "b"), collector.toList())
        assertFalse(collector.overflowed)
    }
}
