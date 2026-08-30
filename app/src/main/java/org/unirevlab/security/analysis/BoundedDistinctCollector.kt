package org.unirevlab.security.analysis

/**
 * First-seen, bounded distinct collector used on hot merge paths.
 *
 * It is deliberately equivalent to `values.distinctBy(key).take(limit)` while avoiding the
 * temporary full distinct list. `overflowed` is raised as soon as an additional unique value is
 * observed, so callers preserve the existing truncation semantics.
 */
internal class BoundedDistinctCollector<T, K>(
    private val limit: Int,
    private val keyOf: (T) -> K,
) {
    private val seen = HashSet<K>(minOf(limit.coerceAtLeast(16), 4096))
    private val values = ArrayList<T>(minOf(limit.coerceAtLeast(0), 4096))

    var overflowed: Boolean = false
        private set

    fun add(value: T) {
        val key = keyOf(value)
        if (!seen.add(key)) return
        if (values.size < limit) {
            values += value
        } else {
            overflowed = true
        }
    }

    fun addAll(items: Iterable<T>) {
        for (item in items) add(item)
    }

    fun toList(): List<T> = values.toList()
}

/** Equivalent to `values.take(limit)` while avoiding materializing a full flattened list. */
internal class BoundedCollector<T>(private val limit: Int) {
    private val values = ArrayList<T>(minOf(limit.coerceAtLeast(0), 4096))
    var overflowed: Boolean = false
        private set

    fun add(value: T) {
        if (values.size < limit) values += value else overflowed = true
    }

    fun addAll(items: Iterable<T>) {
        for (item in items) add(item)
    }

    fun toList(): List<T> = values.toList()
}
