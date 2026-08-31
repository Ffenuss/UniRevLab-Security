#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text:
        print(f"already patched: {rel}")
        return
    if old not in text:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing block:\n{old[:500]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


# 1) Exact fractional progress + finish-time ETA carried with each progress checkpoint.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisRunState.kt",
    '''    val startedAtEpochMs: Long,\n    val updatedAtEpochMs: Long = System.currentTimeMillis(),\n) {\n    init {\n        require(percent in 0..100)\n    }\n}\n''',
    '''    val startedAtEpochMs: Long,\n    val updatedAtEpochMs: Long = System.currentTimeMillis(),\n    val fractionComplete: Double = percent / 100.0,\n    val estimatedFinishAtEpochMs: Long? = null,\n) {\n    init {\n        require(percent in 0..100)\n        require(fractionComplete.isFinite() && fractionComplete in 0.0..1.0)\n    }\n}\n''',
)

eta_file = "app/src/main/java/org/unirevlab/security/analysis/AnalysisEtaEstimator.kt"
eta_source = '''package org.unirevlab.security.analysis\n\nimport java.util.ArrayDeque\n\n/**\n * Estimates a finish timestamp from observed monotonic progress rather than from elapsed/percent.\n *\n * The important property for the UI is that between real progress checkpoints the estimated finish\n * timestamp stays fixed, so the displayed remaining time counts down instead of increasing every\n * second while an integer percentage is unchanged.\n */\ninternal class AnalysisEtaEstimator(\n    private val windowMs: Long = 180_000L,\n    private val minSpanMs: Long = 10_000L,\n    private val minFractionDelta: Double = 0.001,\n) {\n    private data class Sample(val timestampMs: Long, val fraction: Double)\n\n    private val samples = ArrayDeque<Sample>()\n    private var lastFraction = -1.0\n    private var estimatedFinishAtMs: Long? = null\n\n    @Synchronized\n    fun observe(fraction: Double, timestampMs: Long): Long? {\n        if (!fraction.isFinite()) return estimatedFinishAtMs\n        val normalized = fraction.coerceIn(0.0, 1.0)\n        if (normalized >= 1.0) {\n            lastFraction = 1.0\n            estimatedFinishAtMs = timestampMs\n            return timestampMs\n        }\n        if (lastFraction >= 0.0 && normalized + EPSILON < lastFraction) return estimatedFinishAtMs\n        if (lastFraction >= 0.0 && normalized <= lastFraction + EPSILON) return estimatedFinishAtMs\n\n        lastFraction = normalized\n        samples.addLast(Sample(timestampMs, normalized))\n        while (samples.size > 2 && timestampMs - samples.first.timestampMs > windowMs) {\n            samples.removeFirst()\n        }\n\n        if (samples.size < 2) return estimatedFinishAtMs\n        val first = samples.first\n        val spanMs = timestampMs - first.timestampMs\n        val advanced = normalized - first.fraction\n        if (spanMs < minSpanMs || advanced < minFractionDelta) return estimatedFinishAtMs\n\n        val ratePerMs = advanced / spanMs.toDouble()\n        if (ratePerMs <= 0.0 || !ratePerMs.isFinite()) return estimatedFinishAtMs\n        val remainingMs = ((1.0 - normalized) / ratePerMs).toLong()\n        if (remainingMs <= 0L || remainingMs > MAX_ETA_MS) return estimatedFinishAtMs\n\n        val rawFinish = timestampMs + remainingMs\n        estimatedFinishAtMs = estimatedFinishAtMs?.let { previous ->\n            previous + ((rawFinish - previous) * SMOOTHING).toLong()\n        } ?: rawFinish\n        return estimatedFinishAtMs\n    }\n\n    companion object {\n        private const val EPSILON = 0.0000001\n        private const val SMOOTHING = 0.25\n        private const val MAX_ETA_MS = 12L * 60L * 60L * 1_000L\n    }\n}\n'''
if not (ROOT / eta_file).exists():
    write(eta_file, eta_source)
    print(f"created: {eta_file}")
elif read(eta_file) != eta_source:
    raise SystemExit(f"patch state mismatch: {eta_file}")
else:
    print(f"already patched: {eta_file}")

eta_test_file = "app/src/test/java/org/unirevlab/security/analysis/AnalysisEtaEstimatorTest.kt"
eta_test_source = '''package org.unirevlab.security.analysis\n\nimport org.junit.Assert.assertEquals\nimport org.junit.Assert.assertNull\nimport org.junit.Test\n\nclass AnalysisEtaEstimatorTest {\n    @Test\n    fun finishTimestampStaysFixedWhenProgressDoesNotAdvance() {\n        val estimator = AnalysisEtaEstimator()\n        assertNull(estimator.observe(0.10, 0L))\n        val finishAt = estimator.observe(0.20, 20_000L)\n        assertEquals(180_000L, finishAt)\n        assertEquals(finishAt, estimator.observe(0.20, 30_000L))\n\n        val remainingAt20s = requireNotNull(finishAt) - 20_000L\n        val remainingAt30s = requireNotNull(estimator.observe(0.20, 30_000L)) - 30_000L\n        assertEquals(10_000L, remainingAt20s - remainingAt30s)\n    }\n}\n'''
if not (ROOT / eta_test_file).exists():
    write(eta_test_file, eta_test_source)
    print(f"created: {eta_test_file}")
elif read(eta_test_file) != eta_test_source:
    raise SystemExit(f"patch state mismatch: {eta_test_file}")
else:
    print(f"already patched: {eta_test_file}")

# 2) ProgressReporter: throttle UI callbacks, retain exact fractional progress, and calculate ETA only
#    from observed advancement. This removes the mathematically broken elapsed/percent ETA.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''        private var lastPercent: Int = -1\n        private var lastStage: AnalysisStage? = null\n        private var lastDetail: String? = null\n        private var lastCallbackAtMs: Long = 0L\n''',
    '''        private val etaEstimator = AnalysisEtaEstimator()\n        private var lastPercent: Int = -1\n        private var lastFraction: Double = -1.0\n        private var lastStage: AnalysisStage? = null\n        private var lastDetail: String? = null\n        private var lastCallbackAtMs: Long = 0L\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''            detail: String,\n            completedUnits: Int? = null,\n            totalUnits: Int? = null,\n        ) {\n            checkCancelled()\n            val normalized = percent.coerceIn(0, 100)\n            if (normalized < lastPercent) return\n            val now = System.currentTimeMillis()\n            val sameCheckpoint = normalized == lastPercent && stage == lastStage && detail == lastDetail\n            if (sameCheckpoint && normalized != 0 && normalized != 100 && now - lastCallbackAtMs < 250L) return\n            lastPercent = normalized\n            lastStage = stage\n            lastDetail = detail\n            lastCallbackAtMs = now\n            callback?.invoke(\n                AnalysisProgress(\n                    stage = stage,\n                    percent = normalized,\n                    detail = detail,\n                    completedUnits = completedUnits,\n                    totalUnits = totalUnits,\n                    startedAtEpochMs = startedAtEpochMs,\n                )\n            )\n        }\n''',
    '''            detail: String,\n            completedUnits: Int? = null,\n            totalUnits: Int? = null,\n            fractionComplete: Double? = null,\n        ) {\n            checkCancelled()\n            val normalized = percent.coerceIn(0, 100)\n            val normalizedFraction = (fractionComplete ?: normalized / 100.0).coerceIn(0.0, 1.0)\n            if (normalized < lastPercent || (lastFraction >= 0.0 && normalizedFraction + 0.0000001 < lastFraction)) return\n            val now = System.currentTimeMillis()\n            val importantCheckpoint = normalized != lastPercent || stage != lastStage || normalized == 0 || normalized == 100\n            if (!importantCheckpoint && now - lastCallbackAtMs < 500L) return\n            lastPercent = normalized\n            lastFraction = maxOf(lastFraction, normalizedFraction)\n            lastStage = stage\n            lastDetail = detail\n            lastCallbackAtMs = now\n            val finishAt = etaEstimator.observe(lastFraction, now)\n            callback?.invoke(\n                AnalysisProgress(\n                    stage = stage,\n                    percent = normalized,\n                    detail = detail,\n                    completedUnits = completedUnits,\n                    totalUnits = totalUnits,\n                    startedAtEpochMs = startedAtEpochMs,\n                    updatedAtEpochMs = now,\n                    fractionComplete = lastFraction,\n                    estimatedFinishAtEpochMs = finishAt,\n                )\n            )\n        }\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''            val fraction = if (total <= 0L) 1.0 else (completed.toDouble() / total.toDouble()).coerceIn(0.0, 1.0)\n            val percent = fromPercent + ((toPercent - fromPercent) * fraction).toInt()\n            emit(stage, percent, detail, completedUnits, totalUnits)\n''',
    '''            val fraction = if (total <= 0L) 1.0 else (completed.toDouble() / total.toDouble()).coerceIn(0.0, 1.0)\n            val precisePercent = fromPercent.toDouble() + (toPercent - fromPercent).toDouble() * fraction\n            emit(\n                stage, precisePercent.toInt(), detail, completedUnits, totalUnits,\n                fractionComplete = precisePercent / 100.0,\n            )\n''',
)

# 3) Compact keys for the large report-level xref collectors. List<Any> allocated an array plus boxed
#    integers for every retained key (hundreds of thousands of objects on large multidex apps).
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''    private data class PreparedDexEntry(val reportedEntry: String, val file: File, val sha256: String, val ordinal: Int)\n    private data class DexTaskResult(val prepared: PreparedDexEntry, val bundle: DexScanBundle?, val failed: Boolean)\n''',
    '''    private data class PreparedDexEntry(val reportedEntry: String, val file: File, val sha256: String, val ordinal: Int)\n    private data class DexTaskResult(val prepared: PreparedDexEntry, val bundle: DexScanBundle?, val failed: Boolean)\n    private data class DexCallKey(val entry: String, val caller: Int, val callee: Int, val offset: Int)\n    private data class DexStringKey(val entry: String, val caller: Int, val stringIndex: Int, val offset: Int)\n    private data class DexTypeKey(val entry: String, val caller: Int, val typeIndex: Int, val kind: String, val offset: Int)\n    private data class DexFieldKey(val entry: String, val caller: Int, val fieldIndex: Int, val kind: String, val offset: Int)\n    private data class DexBlockKey(val entry: String, val method: Int, val start: Int)\n    private data class DexConstantKey(val entry: String, val method: Int, val register: Int, val offset: Int)\n    private data class DexInvokeKey(val entry: String, val caller: Int, val callee: Int, val offset: Int)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''        val callXrefs = BoundedDistinctCollector<DexMethodCallXref, List<Any>>(MAX_REPORTED_CALL_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }\n        val stringXrefs = BoundedDistinctCollector<DexStringXref, List<Any>>(MAX_REPORTED_STRING_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.stringIndex, it.instructionOffsetCodeUnits) }\n        val typeXrefs = BoundedDistinctCollector<DexTypeXref, List<Any>>(MAX_REPORTED_TYPE_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.typeIndex, it.kind, it.instructionOffsetCodeUnits) }\n        val fieldXrefs = BoundedDistinctCollector<DexFieldXref, List<Any>>(MAX_REPORTED_FIELD_XREFS) { listOf(it.dexEntry, it.callerMethodIndex, it.fieldIndex, it.kind, it.instructionOffsetCodeUnits) }\n        val basicBlocks = BoundedDistinctCollector<DexBasicBlock, List<Any>>(MAX_REPORTED_BASIC_BLOCKS) { listOf(it.dexEntry, it.methodIndex, it.startCodeUnit) }\n        val constants = BoundedDistinctCollector<DexConstantReference, List<Any>>(MAX_REPORTED_CONSTANTS) { listOf(it.dexEntry, it.methodIndex, it.register, it.instructionOffsetCodeUnits) }\n        val invokeObservations = BoundedDistinctCollector<DexInvokeObservation, List<Any>>(MAX_REPORTED_INVOKE_OBSERVATIONS) { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }\n\n        try {\n''',
    '''        val callXrefs = BoundedDistinctCollector<DexMethodCallXref, DexCallKey>(MAX_REPORTED_CALL_XREFS) { DexCallKey(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }\n        val stringXrefs = BoundedDistinctCollector<DexStringXref, DexStringKey>(MAX_REPORTED_STRING_XREFS) { DexStringKey(it.dexEntry, it.callerMethodIndex, it.stringIndex, it.instructionOffsetCodeUnits) }\n        val typeXrefs = BoundedDistinctCollector<DexTypeXref, DexTypeKey>(MAX_REPORTED_TYPE_XREFS) { DexTypeKey(it.dexEntry, it.callerMethodIndex, it.typeIndex, it.kind, it.instructionOffsetCodeUnits) }\n        val fieldXrefs = BoundedDistinctCollector<DexFieldXref, DexFieldKey>(MAX_REPORTED_FIELD_XREFS) { DexFieldKey(it.dexEntry, it.callerMethodIndex, it.fieldIndex, it.kind, it.instructionOffsetCodeUnits) }\n        val basicBlocks = BoundedDistinctCollector<DexBasicBlock, DexBlockKey>(MAX_REPORTED_BASIC_BLOCKS) { DexBlockKey(it.dexEntry, it.methodIndex, it.startCodeUnit) }\n        val constants = BoundedDistinctCollector<DexConstantReference, DexConstantKey>(MAX_REPORTED_CONSTANTS) { DexConstantKey(it.dexEntry, it.methodIndex, it.register, it.instructionOffsetCodeUnits) }\n        val invokeObservations = BoundedDistinctCollector<DexInvokeObservation, DexInvokeKey>(MAX_REPORTED_INVOKE_OBSERVATIONS) { DexInvokeKey(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) }\n\n        val dexProgressFractions = DoubleArray(overallTotal.coerceAtLeast(1)) { index -> if (index < overallBase) 1.0 else 0.0 }\n        val dexProgressLock = Any()\n        fun updateDexProgress(ordinal: Int, localFraction: Double): Pair<Double, Int> = synchronized(dexProgressLock) {\n            val slot = (ordinal - 1).coerceIn(0, dexProgressFractions.lastIndex)\n            dexProgressFractions[slot] = maxOf(dexProgressFractions[slot], localFraction.coerceIn(0.0, 1.0))\n            val overallFraction = dexProgressFractions.sum() / dexProgressFractions.size.toDouble()\n            val completed = dexProgressFractions.count { it >= 0.999999 }\n            overallFraction to completed\n        }\n\n        try {\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''                                        val completedBefore = (item.ordinal - 1).coerceAtLeast(0)\n                                        val globalFraction = (completedBefore.toDouble() + localPercent.coerceIn(0, 100) / 100.0) / overallTotal.coerceAtLeast(1).toDouble()\n                                        val globalPercent = 25 + (globalFraction.coerceIn(0.0, 1.0) * 33.0).toInt()\n                                        progress?.emit(\n                                            AnalysisStage.DEX,\n                                            globalPercent,\n                                            "${item.reportedEntry}: $detail",\n                                            completedBefore.coerceAtMost(overallTotal),\n                                            overallTotal,\n                                        )\n''',
    '''                                        val (globalFraction, completedDex) = updateDexProgress(\n                                            item.ordinal, localPercent.coerceIn(0, 100) / 100.0,\n                                        )\n                                        val precisePercent = 25.0 + globalFraction.coerceIn(0.0, 1.0) * 33.0\n                                        progress?.emit(\n                                            AnalysisStage.DEX,\n                                            precisePercent.toInt(),\n                                            "${item.reportedEntry}: $detail",\n                                            completedDex,\n                                            overallTotal,\n                                            fractionComplete = precisePercent / 100.0,\n                                        )\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''                                progress?.emit(\n                                    AnalysisStage.DEX,\n                                    25 + (((task.prepared.ordinal.toDouble() / overallTotal.coerceAtLeast(1).toDouble()).coerceIn(0.0, 1.0)) * 33.0).toInt(),\n                                    "DEX готов: ${task.prepared.reportedEntry}",\n                                    task.prepared.ordinal.coerceAtMost(overallTotal),\n                                    overallTotal,\n                                )\n''',
    '''                                val (globalFraction, completedDex) = updateDexProgress(task.prepared.ordinal, 1.0)\n                                val precisePercent = 25.0 + globalFraction.coerceIn(0.0, 1.0) * 33.0\n                                progress?.emit(\n                                    AnalysisStage.DEX,\n                                    precisePercent.toInt(),\n                                    "DEX готов: ${task.prepared.reportedEntry}",\n                                    completedDex,\n                                    overallTotal,\n                                    fractionComplete = precisePercent / 100.0,\n                                )\n''',
)

# 4) The biggest WPS-class crash candidate: terminal distinctBy() duplicated all large xref/CFG lists
#    and built additional HashSets right after the UI said "Bytecode xrefs/CFG готовы". Every event
#    already has a unique method/instruction position in a valid DEX, and all lists are bounded while
#    decoding, so returning them directly removes the transient OOM spike without reducing coverage.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''                codeMethods = codeMethods.distinctBy { Triple(it.dexEntry, it.methodIndex, it.codeOffset) },\n                callXrefs = calls.distinctBy { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) },\n                stringXrefs = strings.distinctBy { listOf(it.dexEntry, it.callerMethodIndex, it.stringIndex, it.instructionOffsetCodeUnits) },\n                typeXrefs = types.distinctBy { listOf(it.dexEntry, it.callerMethodIndex, it.typeIndex, it.kind, it.instructionOffsetCodeUnits) },\n                fieldXrefs = fields.distinctBy { listOf(it.dexEntry, it.callerMethodIndex, it.fieldIndex, it.kind, it.instructionOffsetCodeUnits) },\n                basicBlocks = blocks.distinctBy { listOf(it.dexEntry, it.methodIndex, it.startCodeUnit, it.endCodeUnitExclusive) },\n                constants = constants.distinctBy { listOf(it.dexEntry, it.methodIndex, it.register, it.instructionOffsetCodeUnits) },\n                invokeObservations = observations.distinctBy { listOf(it.dexEntry, it.callerMethodIndex, it.calleeMethodIndex, it.instructionOffsetCodeUnits) },\n''',
    '''                // Decoder visits each valid method/instruction position once. Avoid terminal\n                // distinctBy copies here: on very large DEX files they temporarily doubled the\n                // xref/CFG graph and its key sets, which could kill the Android process.\n                codeMethods = codeMethods,\n                callXrefs = calls,\n                stringXrefs = strings,\n                typeXrefs = types,\n                fieldXrefs = fields,\n                basicBlocks = blocks,\n                constants = constants,\n                invokeObservations = observations,\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    '''                nativeMethods = nativeMethods.distinctBy { Triple(it.dexEntry, it.methodIndex, it.declaringClass) },\n                httpUrls = httpUrls.distinctBy { Triple(it.dexEntry, it.stringIndex, it.value) },\n                httpsUrls = httpsUrls.distinctBy { Triple(it.dexEntry, it.stringIndex, it.value) },\n                secretCandidates = secrets.distinctBy { Triple(it.kind, it.dexEntry, it.stringIndex) },\n''',
    '''                // These collections are produced from a single monotonic DEX traversal; avoid\n                // end-of-scan copies so large files do not create a second transient object graph.\n                nativeMethods = nativeMethods,\n                httpUrls = httpUrls,\n                httpsUrls = httpsUrls,\n                secretCandidates = secrets,\n''',
)

# 5) Reduce progress infrastructure overhead added in v0.22.1. UI state remains responsive, while
#    SharedPreferences recovery checkpoints are persisted at most every 2 seconds or on stage change.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''    @Volatile private var store: AnalysisRunStore? = null\n    @Volatile private var activeJob: Job? = null\n''',
    '''    @Volatile private var store: AnalysisRunStore? = null\n    @Volatile private var activeJob: Job? = null\n    private var lastPersistAtMs: Long = 0L\n    private var lastPersistStage: AnalysisStage? = null\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''                    stale.percent?.let { append(" ($it%)") }\n                    append(". Запустите анализ снова. Уже сохранённые content-cache результаты будут переиспользованы автоматически.")\n''',
    '''                    stale.percent?.let { append(" ($it%)") }\n                    stale.detail?.takeIf { it.isNotBlank() }?.let { append(". Последняя операция: $it") }\n                    append(". Запустите анализ снова; доступные кэшированные результаты будут переиспользованы автоматически.")\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''            mutableState.value = cancelling\n            store?.writeRunning(cancelling.targetLabel, cancelling.progress, cancelling = true)\n''',
    '''            mutableState.value = cancelling\n            persistRunning(cancelling.targetLabel, cancelling.progress, cancelling = true, force = true)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''            mutableState.value = AnalysisRunState.Running(runId, targetLabel, assessmentScope, initialProgress)\n            store?.writeRunning(targetLabel, initialProgress)\n''',
    '''            mutableState.value = AnalysisRunState.Running(runId, targetLabel, assessmentScope, initialProgress)\n            persistRunning(targetLabel, initialProgress, force = true)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''                    mutableState.value = current.copy(progress = normalized)\n                    store?.writeRunning(targetLabel, normalized)\n''',
    '''                    mutableState.value = current.copy(progress = normalized)\n                    persistRunning(targetLabel, normalized)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''                    mutableState.value = current.copy(progress = cancellationProgress)\n                    store?.writeRunning(targetLabel, cancellationProgress, cancelling = true)\n''',
    '''                    mutableState.value = current.copy(progress = cancellationProgress)\n                    persistRunning(targetLabel, cancellationProgress, cancelling = true)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisManager.kt",
    '''    private fun currentRunId(): Long? = when (val current = mutableState.value) {\n''',
    '''    private fun persistRunning(\n        targetLabel: String,\n        progress: AnalysisProgress,\n        cancelling: Boolean = false,\n        force: Boolean = false,\n    ) {\n        val now = System.currentTimeMillis()\n        val stageChanged = progress.stage != lastPersistStage\n        if (!force && !stageChanged && now - lastPersistAtMs < 2_000L) return\n        store?.writeRunning(targetLabel, progress, cancelling)\n        lastPersistAtMs = now\n        lastPersistStage = progress.stage\n    }\n\n    private fun currentRunId(): Long? = when (val current = mutableState.value) {\n''',
)

# Foreground notification Binder updates are capped to roughly once/sec while progress continues.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisForegroundService.kt",
    '''import android.os.PowerManager\n''',
    '''import android.os.PowerManager\nimport android.os.SystemClock\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisForegroundService.kt",
    '''import kotlinx.coroutines.flow.collectLatest\n''',
    '''import kotlinx.coroutines.flow.collect\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisForegroundService.kt",
    '''        stateJob = serviceScope.launch {\n            AnalysisManager.state.collectLatest { state ->\n                when (state) {\n                    is AnalysisRunState.Running,\n                    is AnalysisRunState.Cancelling -> notificationManager().notify(NOTIFICATION_ID, buildNotification(state))\n                    is AnalysisRunState.Completed,\n''',
    '''        stateJob = serviceScope.launch {\n            var lastNotificationAtMs = 0L\n            var lastNotificationStage: AnalysisStage? = null\n            AnalysisManager.state.collect { state ->\n                when (state) {\n                    is AnalysisRunState.Running,\n                    is AnalysisRunState.Cancelling -> {\n                        val progress = when (state) {\n                            is AnalysisRunState.Running -> state.progress\n                            is AnalysisRunState.Cancelling -> state.progress\n                            else -> null\n                        }\n                        val now = SystemClock.elapsedRealtime()\n                        val stageChanged = progress?.stage != lastNotificationStage\n                        if (stageChanged || state is AnalysisRunState.Cancelling || now - lastNotificationAtMs >= 1_000L) {\n                            notificationManager().notify(NOTIFICATION_ID, buildNotification(state))\n                            lastNotificationAtMs = now\n                            lastNotificationStage = progress?.stage\n                        }\n                    }\n                    is AnalysisRunState.Completed,\n''',
)

# 6) UI: precise progress bar/label and countdown from a fixed estimated finish timestamp.
replace_once(
    "app/src/main/java/org/unirevlab/security/ui/AnalysisProgressDialog.kt",
    '''    val elapsedMs = (now - progress.startedAtEpochMs).coerceAtLeast(0L)\n    val remainingMs = estimateRemainingMs(elapsedMs, progress.percent)\n    val unchangedMs = (now - progress.updatedAtEpochMs).coerceAtLeast(0L)\n''',
    '''    val elapsedMs = (now - progress.startedAtEpochMs).coerceAtLeast(0L)\n    val unchangedMs = (now - progress.updatedAtEpochMs).coerceAtLeast(0L)\n    val remainingMs = progress.estimatedFinishAtEpochMs\n        ?.minus(now)\n        ?.takeIf { it > 0L && unchangedMs < 180_000L }\n    val percentLabel = formatProgressPercent(progress.fractionComplete)\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/ui/AnalysisProgressDialog.kt",
    '''                if (cancelling) "Останавливаем анализ" else "Анализ выполняется — ${progress.percent}%",\n''',
    '''                if (cancelling) "Останавливаем анализ" else "Анализ выполняется — $percentLabel",\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/ui/AnalysisProgressDialog.kt",
    '''                    Text("${progress.percent}%", fontWeight = FontWeight.Bold)\n                }\n                LinearProgressIndicator(\n                    progress = { progress.percent / 100f },\n''',
    '''                    Text(percentLabel, fontWeight = FontWeight.Bold)\n                }\n                LinearProgressIndicator(\n                    progress = { progress.fractionComplete.toFloat() },\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/ui/AnalysisProgressDialog.kt",
    '''                        append("Прошло: ${formatDuration(elapsedMs)}")\n                        remainingMs?.let { append(" · Осталось примерно: ${formatDuration(it)}") }\n''',
    '''                        append("Прошло: ${formatDuration(elapsedMs)}")\n                        if (remainingMs != null) {\n                            append(" · Осталось примерно: ${formatDuration(remainingMs)}")\n                        } else if (!cancelling) {\n                            append(" · Осталось: оценка уточняется")\n                        }\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/ui/AnalysisProgressDialog.kt",
    '''private fun estimateRemainingMs(elapsedMs: Long, percent: Int): Long? {\n    if (percent !in 3..99 || elapsedMs < 2_000L) return null\n    return ((elapsedMs.toDouble() * (100 - percent).toDouble()) / percent.toDouble())\n        .toLong()\n        .coerceAtLeast(0L)\n}\n\nprivate fun formatDuration(durationMs: Long): String {\n''',
    '''private fun formatProgressPercent(fraction: Double): String {\n    val value = (fraction.coerceIn(0.0, 1.0) * 1000.0).toInt() / 10.0\n    return if (value % 1.0 == 0.0) "${value.toInt()}%" else "${value}%"\n}\n\nprivate fun formatDuration(durationMs: Long): String {\n''',
)

# 7) Give this specialized local analyzer access to Android's larger heap class and bump engine/app
#    version so stale final-result caches cannot mask the scanner changes.
replace_once(
    "app/src/main/AndroidManifest.xml",
    '''        android:label="@string/app_name"\n        android:networkSecurityConfig="@xml/network_security_config"\n''',
    '''        android:label="@string/app_name"\n        android:largeHeap="true"\n        android:networkSecurityConfig="@xml/network_security_config"\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''        const val ENGINE_VERSION = "0.22.0-dev-performance-ux"\n''',
    '''        const val ENGINE_VERSION = "0.22.2-dev-dex-stability-eta"\n''',
)
replace_once(
    "app/build.gradle.kts",
    '''        versionCode = 19\n        versionName = "0.22.1-dev-analysis-progress-cancel"\n''',
    '''        versionCode = 20\n        versionName = "0.22.2-dev-dex-stability-eta"\n''',
)

print("v0.22.2 stability/ETA patch integrated")
