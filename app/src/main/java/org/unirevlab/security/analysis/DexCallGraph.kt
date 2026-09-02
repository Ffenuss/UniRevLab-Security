package org.unirevlab.security.analysis

import java.util.ArrayDeque
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary

/**
 * Bounded call-graph helpers built from the DEX xrefs already produced by [DexCodeScanner].
 *
 * This layer never parses or executes target code. It only navigates normalized xrefs, which keeps
 * graph queries cheap enough for the on-device RE browser and makes every path reproducible from the
 * stored analysis report.
 */
object DexCallGraph {
    data class MethodKey(val dexEntry: String, val methodIndex: Int)

    data class MethodNode(
        val key: MethodKey,
        val classDescriptor: String,
        val name: String,
        val prototype: String,
    ) {
        val signature: String get() = "$classDescriptor->$name$prototype"
    }

    data class Edge(
        val from: MethodKey,
        val to: MethodKey,
        val instructionOffsetCodeUnits: Int,
    )

    data class Path(
        val nodes: List<MethodNode>,
        val edges: List<Edge>,
        val truncated: Boolean = false,
    )

    data class Slice(
        val nodes: List<MethodNode>,
        val edges: List<Edge>,
        val truncated: Boolean,
    )

    private data class Index(
        val nodes: Map<MethodKey, MethodNode>,
        val outgoing: Map<MethodKey, List<Edge>>,
        val incoming: Map<MethodKey, List<Edge>>,
    )

    fun nodeFor(method: DexMethodReference): MethodNode = MethodNode(
        key = MethodKey(method.dexEntry, method.methodIndex),
        classDescriptor = method.declaringClass,
        name = method.name,
        prototype = method.prototype,
    )

    fun findMethods(dex: DexSummary, query: String, limit: Int = 100): List<MethodNode> {
        val q = query.trim().lowercase()
        if (q.length < 2 || limit <= 0) return emptyList()
        return dex.methods.asSequence()
            .map(::nodeFor)
            .filter { node ->
                node.signature.lowercase().contains(q) || node.key.dexEntry.lowercase().contains(q)
            }
            .take(limit)
            .toList()
    }

    fun shortestPath(
        dex: DexSummary,
        start: MethodKey,
        target: MethodKey,
        maxDepth: Int = 16,
        maxVisited: Int = 50_000,
    ): Path? = shortestPath(
        dex = dex,
        starts = setOf(start),
        target = { it == target },
        maxDepth = maxDepth,
        maxVisited = maxVisited,
    )

    fun shortestPath(
        dex: DexSummary,
        starts: Set<MethodKey>,
        target: (MethodKey) -> Boolean,
        maxDepth: Int = 16,
        maxVisited: Int = 50_000,
    ): Path? {
        if (starts.isEmpty() || maxDepth < 0 || maxVisited <= 0) return null
        val index = buildIndex(dex)
        val queue = ArrayDeque<MethodKey>()
        val depth = HashMap<MethodKey, Int>()
        val previous = HashMap<MethodKey, Edge>()

        starts.asSequence().filter { it in index.nodes }.forEach { key ->
            if (depth.putIfAbsent(key, 0) == null) queue.addLast(key)
        }
        if (queue.isEmpty()) return null

        var visited = 0
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val currentDepth = depth.getValue(current)
            visited++
            if (target(current)) return reconstruct(index, current, previous, truncated = false)
            if (visited >= maxVisited) return null
            if (currentDepth >= maxDepth) continue

            for (edge in index.outgoing[current].orEmpty()) {
                if (edge.to !in index.nodes || edge.to in depth) continue
                depth[edge.to] = currentDepth + 1
                previous[edge.to] = edge
                queue.addLast(edge.to)
            }
        }
        return null
    }

    fun reachableSlice(
        dex: DexSummary,
        roots: Set<MethodKey>,
        maxDepth: Int = 3,
        maxNodes: Int = 1_000,
        includeIncoming: Boolean = false,
    ): Slice {
        if (roots.isEmpty() || maxDepth < 0 || maxNodes <= 0) return Slice(emptyList(), emptyList(), false)
        val index = buildIndex(dex)
        val queue = ArrayDeque<MethodKey>()
        val depth = HashMap<MethodKey, Int>()
        roots.asSequence().filter { it in index.nodes }.forEach { key ->
            if (depth.putIfAbsent(key, 0) == null) queue.addLast(key)
        }

        val selectedEdges = LinkedHashSet<Edge>()
        var truncated = false
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val currentDepth = depth.getValue(current)
            if (currentDepth >= maxDepth) continue
            val candidates = if (includeIncoming) {
                index.outgoing[current].orEmpty() + index.incoming[current].orEmpty()
            } else {
                index.outgoing[current].orEmpty()
            }
            for (edge in candidates) {
                val neighbor = if (edge.from == current) edge.to else edge.from
                if (neighbor !in index.nodes) continue
                selectedEdges += edge
                if (neighbor !in depth) {
                    if (depth.size >= maxNodes) {
                        truncated = true
                        continue
                    }
                    depth[neighbor] = currentDepth + 1
                    queue.addLast(neighbor)
                }
            }
        }

        val nodes = depth.keys.mapNotNull(index.nodes::get)
            .sortedWith(compareBy({ it.key.dexEntry }, { it.classDescriptor }, { it.name }, { it.prototype }))
        val nodeKeys = nodes.mapTo(HashSet()) { it.key }
        val edges = selectedEdges.filter { it.from in nodeKeys && it.to in nodeKeys }
            .sortedWith(compareBy({ it.from.dexEntry }, { it.from.methodIndex }, { it.instructionOffsetCodeUnits }, { it.to.methodIndex }))
        return Slice(nodes, edges, truncated)
    }

    fun toDot(slice: Slice): String = buildString {
        appendLine("digraph dex_call_graph {")
        appendLine("  rankdir=LR;")
        slice.nodes.forEach { node ->
            append("  \"").append(dotId(node.key)).append("\" [label=\"")
                .append(escapeDot(node.signature)).append("\"];\n")
        }
        slice.edges.forEach { edge ->
            append("  \"").append(dotId(edge.from)).append("\" -> \"")
                .append(dotId(edge.to)).append("\" [label=\"+")
                .append(edge.instructionOffsetCodeUnits).append("\"];\n")
        }
        appendLine("}")
    }

    private fun buildIndex(dex: DexSummary): Index {
        val nodes = LinkedHashMap<MethodKey, MethodNode>(dex.methods.size * 2)
        dex.methods.forEach { method -> nodes[nodeFor(method).key] = nodeFor(method) }

        // Some reports can contain xrefs to method_ids that were not retained in the structural index.
        // Preserve those endpoints with xref-derived metadata instead of silently dropping graph edges.
        fun ensureXrefNode(xref: DexMethodCallXref, caller: Boolean): MethodKey {
            val key = MethodKey(xref.dexEntry, if (caller) xref.callerMethodIndex else xref.calleeMethodIndex)
            if (key !in nodes) {
                nodes[key] = if (caller) {
                    MethodNode(key, xref.callerClass, xref.callerName, "")
                } else {
                    MethodNode(key, xref.calleeClass, xref.calleeName, xref.calleePrototype)
                }
            }
            return key
        }

        val outgoing = HashMap<MethodKey, MutableList<Edge>>()
        val incoming = HashMap<MethodKey, MutableList<Edge>>()
        dex.callXrefs.forEach { xref ->
            val from = ensureXrefNode(xref, caller = true)
            val to = ensureXrefNode(xref, caller = false)
            val edge = Edge(from, to, xref.instructionOffsetCodeUnits)
            outgoing.getOrPut(from) { mutableListOf() }.add(edge)
            incoming.getOrPut(to) { mutableListOf() }.add(edge)
        }
        return Index(nodes, outgoing, incoming)
    }

    private fun reconstruct(
        index: Index,
        end: MethodKey,
        previous: Map<MethodKey, Edge>,
        truncated: Boolean,
    ): Path {
        val reversedEdges = mutableListOf<Edge>()
        var cursor = end
        while (true) {
            val edge = previous[cursor] ?: break
            reversedEdges += edge
            cursor = edge.from
        }
        reversedEdges.reverse()
        val keys = buildList {
            if (reversedEdges.isEmpty()) add(end)
            else {
                add(reversedEdges.first().from)
                reversedEdges.forEach { add(it.to) }
            }
        }
        return Path(
            nodes = keys.mapNotNull(index.nodes::get),
            edges = reversedEdges,
            truncated = truncated,
        )
    }

    private fun dotId(key: MethodKey): String = "${key.dexEntry}:${key.methodIndex}"

    private fun escapeDot(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
}
