package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary

class DexCallGraphTest {
    private val a = DexMethodReference("classes.dex", 1, "Lapp/Entry;", "onCreate", "()V")
    private val b = DexMethodReference("classes.dex", 2, "Lapp/Router;", "route", "()V")
    private val c = DexMethodReference("classes.dex", 3, "Lapp/PremiumGate;", "isPremium", "()Z")
    private val d = DexMethodReference("classes.dex", 4, "Lapp/Other;", "noise", "()V")

    @Test
    fun shortestPathUsesExistingXrefs() {
        val dex = fixture()
        val path = DexCallGraph.shortestPath(
            dex,
            DexCallGraph.MethodKey("classes.dex", 1),
            DexCallGraph.MethodKey("classes.dex", 3),
        )
        assertNotNull(path)
        assertEquals(listOf(a.methodIndex, b.methodIndex, c.methodIndex), path!!.nodes.map { it.key.methodIndex })
        assertEquals(2, path.edges.size)
        assertEquals(12, path.edges.first().instructionOffsetCodeUnits)
    }

    @Test
    fun maxDepthPreventsOverclaimingReachability() {
        val dex = fixture()
        val path = DexCallGraph.shortestPath(
            dex,
            DexCallGraph.MethodKey("classes.dex", 1),
            DexCallGraph.MethodKey("classes.dex", 3),
            maxDepth = 1,
        )
        assertNull(path)
    }

    @Test
    fun reachableSliceIsBoundedAndExportsDot() {
        val dex = fixture()
        val slice = DexCallGraph.reachableSlice(
            dex,
            roots = setOf(DexCallGraph.MethodKey("classes.dex", 1)),
            maxDepth = 1,
            maxNodes = 10,
        )
        assertFalse(slice.truncated)
        assertEquals(setOf(1, 2, 4), slice.nodes.map { it.key.methodIndex }.toSet())
        assertEquals(2, slice.edges.size)
        val dot = DexCallGraph.toDot(slice)
        assertTrue(dot.contains("Lapp/Entry;->onCreate()V"))
        assertTrue(dot.contains("+12"))
    }

    private fun fixture(): DexSummary {
        val methods = listOf(a, b, c, d)
        val calls = listOf(
            call(a, b, 12),
            call(b, c, 8),
            call(a, d, 20),
        )
        return DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 0,
            stringsScanned = 0,
            methodsDeclared = methods.size.toLong(),
            methodsIndexed = methods.size.toLong(),
            methods = methods,
            callXrefs = calls,
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )
    }

    private fun call(from: DexMethodReference, to: DexMethodReference, offset: Int) = DexMethodCallXref(
        dexEntry = from.dexEntry,
        callerMethodIndex = from.methodIndex,
        callerClass = from.declaringClass,
        callerName = from.name,
        calleeMethodIndex = to.methodIndex,
        calleeClass = to.declaringClass,
        calleeName = to.name,
        calleePrototype = to.prototype,
        instructionOffsetCodeUnits = offset,
    )
}
