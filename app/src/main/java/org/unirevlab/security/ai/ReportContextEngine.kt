package org.unirevlab.security.ai

import java.io.File
import java.io.InputStreamReader
import java.util.PriorityQueue
import java.util.Locale

data class ReportContext(
    val text: String,
    val reportBytes: Long,
    val scannedChunks: Int,
    val includedChunks: Int,
    val completeFileIncluded: Boolean,
)

/**
 * Reads the complete report as a stream. Small reports are supplied verbatim. For reports that
 * exceed the chosen model's context window, every chunk is still inspected locally and the most
 * relevant evidence is selected without loading the full artifact into memory.
 */
object ReportContextEngine {
    fun build(file: File, query: String, modelContextLength: Int): ReportContext {
        require(file.isFile && file.canRead()) { "Полный отчёт недоступен" }
        require(file.length() in 1..MAX_REPORT_BYTES) { "Размер отчёта не поддерживается" }

        val contextChars = ((modelContextLength.takeIf { it > 0 } ?: DEFAULT_CONTEXT_TOKENS).toLong() * CHARS_PER_TOKEN)
            .coerceIn(MIN_CONTEXT_CHARS.toLong(), MAX_CONTEXT_CHARS.toLong())
            .toInt()
        val directLimit = minOf(contextChars, MAX_DIRECT_REPORT_CHARS)
        if (file.length() <= directLimit.toLong()) {
            val text = file.readText(Charsets.UTF_8)
            return ReportContext(
                text = wrapComplete(text),
                reportBytes = file.length(),
                scannedChunks = 1,
                includedChunks = 1,
                completeFileIncluded = true,
            )
        }

        val terms = queryTerms(query)
        val queryPattern = terms.takeIf { it.isNotEmpty() }?.joinToString("|") { Regex.escape(it) }?.let(::Regex)
        val perChunkChars = (contextChars / MAX_SELECTED_CHUNKS).coerceIn(8_000, CHUNK_CHARS)
        val selected = PriorityQueue<ScoredChunk>(compareBy<ScoredChunk> { it.score }.thenByDescending { it.index })
        var firstChunk: ScoredChunk? = null
        var chunks = 0
        InputStreamReader(file.inputStream().buffered(BUFFER_BYTES), Charsets.UTF_8).use { reader ->
            val buffer = CharArray(CHUNK_CHARS)
            while (true) {
                val read = reader.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                val raw = String(buffer, 0, read)
                val normalized = raw.lowercase(Locale.ROOT)
                val scored = score(normalized, queryPattern)
                val candidate = ScoredChunk(
                    index = chunks,
                    score = scored.score,
                    text = excerpt(raw, scored.firstMatch, perChunkChars),
                )
                if (chunks == 0) firstChunk = candidate.copy(score = Int.MAX_VALUE)
                selected.add(candidate)
                if (selected.size > MAX_SELECTED_CHUNKS) selected.poll()
                chunks++
            }
        }

        val ordered = selected.toList()
            .sortedWith(compareByDescending<ScoredChunk> { it.score }.thenBy { it.index })
            .plus(listOfNotNull(firstChunk))
            .distinctBy { it.index }
        val assembled = buildString(contextChars + 2_000) {
            appendLine("<full-report-access mode=\"stream-selected\" total-bytes=\"${file.length()}\" scanned-chunks=\"$chunks\">")
            appendLine("Все части файла были просмотрены локальным поиском. Ниже приведены наиболее релевантные исходные фрагменты полного отчёта.")
            for (chunk in ordered) {
                if (length >= contextChars) break
                appendLine("\n--- report chunk ${chunk.index + 1}/$chunks; relevance=${chunk.score} ---")
                val remaining = contextChars - length
                if (remaining <= 0) break
                append(chunk.text.take(remaining))
            }
            appendLine("\n</full-report-access>")
        }
        return ReportContext(
            text = assembled,
            reportBytes = file.length(),
            scannedChunks = chunks,
            includedChunks = ordered.size,
            completeFileIncluded = false,
        )
    }

    private fun wrapComplete(text: String): String = buildString(text.length + 160) {
        appendLine("<full-report-access mode=\"verbatim-complete\">")
        append(text)
        appendLine("\n</full-report-access>")
    }

    private fun queryTerms(query: String): Set<String> = TOKEN.findAll(query.lowercase(Locale.ROOT))
        .map { it.value }
        .filter { it.length >= 3 && it !in STOP_WORDS }
        .take(MAX_QUERY_TERMS)
        .toSet()

    private fun score(normalized: String, queryPattern: Regex?): ScoredText {
        var score = 0
        var firstMatch: Int? = null
        queryPattern?.findAll(normalized)?.take(MAX_QUERY_MATCHES_PER_CHUNK)?.forEach { match ->
            score += 12
            if (firstMatch == null) firstMatch = match.range.first
        }
        PRIORITY_MARKERS.forEach { (marker, weight) ->
            val index = normalized.indexOf(marker)
            if (index >= 0) {
                score += weight
                if (firstMatch == null || index < firstMatch!!) firstMatch = index
            }
        }
        return ScoredText(score, firstMatch)
    }

    private fun excerpt(text: String, firstMatch: Int?, maxChars: Int): String {
        if (text.length <= maxChars) return text
        val match = firstMatch ?: 0
        val start = (match - maxChars / 3).coerceIn(0, text.length - maxChars)
        val end = (start + maxChars).coerceAtMost(text.length)
        return buildString(maxChars + 80) {
            if (start > 0) appendLine("… [начало блока опущено]")
            append(text, start, end)
            if (end < text.length) appendLine("\n… [конец блока опущен]")
        }
    }

    private data class ScoredChunk(val index: Int, val score: Int, val text: String)
    private data class ScoredText(val score: Int, val firstMatch: Int?)

    private val TOKEN = Regex("[\\p{L}\\p{N}_./:-]+")
    private val STOP_WORDS = setOf(
        "что", "как", "где", "для", "это", "этот", "эта", "эти", "при", "или", "про", "весь", "все",
        "the", "and", "for", "with", "this", "that", "from", "report", "отчёт", "отчет", "покажи", "найди",
    )
    private val PRIORITY_MARKERS = listOf(
        "\"severity\": \"critical\"" to 40,
        "\"severity\": \"high\"" to 28,
        "\"confidence\": \"confirmed\"" to 18,
        "\"modificationsurfaceprioritization\"" to 18,
        "\"findings\"" to 12,
        "\"il2cpp\"" to 8,
        "\"remediation\"" to 8,
    )

    private const val DEFAULT_CONTEXT_TOKENS = 128_000
    private const val CHARS_PER_TOKEN = 2
    private const val MIN_CONTEXT_CHARS = 64_000
    private const val MAX_CONTEXT_CHARS = 600_000
    private const val MAX_DIRECT_REPORT_CHARS = 600_000
    private const val CHUNK_CHARS = 32_000
    private const val BUFFER_BYTES = 64 * 1024
    private const val MAX_SELECTED_CHUNKS = 16
    private const val MAX_QUERY_TERMS = 24
    private const val MAX_QUERY_MATCHES_PER_CHUNK = 96
    private const val MAX_REPORT_BYTES = 1_073_741_824L
}
