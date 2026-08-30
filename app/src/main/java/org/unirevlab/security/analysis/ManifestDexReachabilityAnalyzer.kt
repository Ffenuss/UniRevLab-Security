package org.unirevlab.security.analysis

import org.unirevlab.security.model.ComponentDexReachability
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.ManifestDexReachabilitySummary
import org.unirevlab.security.model.ManifestSummary
import java.util.ArrayDeque

/**
 * Conservative manifest-to-DEX graph correlation for defensive review.
 *
 * It never claims runtime reachability. Roots are only lifecycle/API methods declared directly on
 * manifest components. Traversal follows bounded static DEX invoke xrefs and reports evidence that
 * a method is reachable in the decoded call graph, not that Android will execute that path.
 */
object ManifestDexReachabilityAnalyzer {
    data class Limits(
        val maxDepth: Int = 12,
        val maxReachableMethodsPerComponent: Int = 10_000,
        val maxComponents: Int = 2_000,
    )

    fun analyze(manifest: ManifestSummary?, dex: DexSummary?, limits: Limits = Limits()): ManifestDexReachabilitySummary? {
        if (manifest == null || dex == null) return null
        val methodsByClass = dex.methods.groupBy { it.declaringClass }
        val outgoing = dex.callXrefs.groupBy { it.callerMethodIndex }
        val deepLinked = manifest.deepLinks.map { normalizeComponentName(manifest.packageName, it.componentName) }.toSet()
        val providerNames = manifest.providers.map { normalizeComponentName(manifest.packageName, it.name) }.toSet()
        val results = mutableListOf<ComponentDexReachability>()
        var globalTruncated = manifest.components.size > limits.maxComponents

        for (component in manifest.components.take(limits.maxComponents)) {
            val fqcn = normalizeComponentName(manifest.packageName, component.name)
            val descriptor = toDescriptor(fqcn)
            val classMethods = methodsByClass[descriptor].orEmpty()
            val roots = classMethods.filter { it.name in lifecycleRoots(component.kind) }.map { it.methodIndex }.distinct().sorted()
            val externallyAddressable = component.exported || fqcn in deepLinked || fqcn in providerNames
            val queue = ArrayDeque<Pair<Int, Int>>()
            roots.forEach { queue.add(it to 0) }
            val seen = linkedSetOf<Int>()
            var maxDepthReached = 0
            var truncated = false
            while (queue.isNotEmpty()) {
                val (method, depth) = queue.removeFirst()
                if (!seen.add(method)) continue
                maxDepthReached = maxOf(maxDepthReached, depth)
                if (seen.size >= limits.maxReachableMethodsPerComponent) { truncated = true; break }
                if (depth >= limits.maxDepth) {
                    if (outgoing[method].orEmpty().isNotEmpty()) truncated = true
                    continue
                }
                for (xref in outgoing[method].orEmpty()) {
                    if (xref.calleeMethodIndex !in seen) queue.add(xref.calleeMethodIndex to (depth + 1))
                }
            }
            globalTruncated = globalTruncated || truncated
            results += ComponentDexReachability(
                componentKind = component.kind,
                componentName = fqcn,
                classDescriptor = descriptor,
                exported = component.exported,
                externallyAddressable = externallyAddressable,
                classPresent = classMethods.isNotEmpty() || dex.classes.any { it.descriptor == descriptor },
                entryMethodIndexes = roots,
                reachableMethodIndexes = seen.toList().sorted(),
                reachableMethodCount = seen.size,
                maxDepthReached = maxDepthReached,
                truncated = truncated,
            )
        }
        return ManifestDexReachabilitySummary(
            components = results.sortedWith(compareBy({ it.componentKind }, { it.componentName })),
            externallyAddressableComponents = results.count { it.externallyAddressable },
            reachableMethods = results.flatMap { it.reachableMethodIndexes }.distinct().size,
            truncated = globalTruncated,
        )
    }

    private fun normalizeComponentName(pkg: String, raw: String): String = when {
        raw.startsWith('.') -> pkg + raw
        '.' !in raw -> "$pkg.$raw"
        else -> raw
    }

    private fun toDescriptor(name: String): String = "L" + name.replace('.', '/') + ";"

    private fun lifecycleRoots(kind: String): Set<String> = when (kind.lowercase()) {
        "activity", "activity-alias" -> setOf("onCreate", "onStart", "onResume", "onNewIntent", "onActivityResult")
        "service" -> setOf("onCreate", "onStartCommand", "onBind", "onRebind", "onHandleIntent")
        "receiver" -> setOf("onReceive")
        "provider" -> setOf("onCreate", "query", "insert", "update", "delete", "openFile", "call", "getType")
        else -> emptySet()
    }
}
