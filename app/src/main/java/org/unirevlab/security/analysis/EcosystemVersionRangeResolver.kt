package org.unirevlab.security.analysis

/**
 * Conservative ecosystem-aware version-range resolver.
 *
 * This intentionally implements a strict, deterministic subset instead of pretending that Maven,
 * npm and NuGet share a version grammar. Unsupported expressions return null (unknown), never true.
 */
object EcosystemVersionRangeResolver {
    data class Evaluation(
        val matches: Boolean,
        val normalizedVersion: String,
        val normalizedExpression: String,
        val resolver: String,
    )

    fun supports(ecosystem: String): Boolean = normalizeEcosystem(ecosystem) in setOf("MAVEN", "NPM", "NUGET")

    /** Returns null when either the version or range is outside the supported safe subset. */
    fun evaluate(ecosystem: String, version: String, expression: String): Evaluation? {
        val kind = normalizeEcosystem(ecosystem)
        if (kind !in setOf("MAVEN", "NPM", "NUGET")) return null
        val raw = expression.trim()
        if (raw.isBlank() || raw.length > 512) return null
        if (listOf("||", "^", "~", "*", " x", " X", "[", "]", "(", ")").any(raw::contains)) return null
        val parsedVersion = parse(kind, version) ?: return null
        val clauses = splitClauses(raw) ?: return null
        if (clauses.isEmpty() || clauses.size > 8) return null
        var all = true
        for (clause in clauses) {
            val match = CLAUSE.matchEntire(clause) ?: return null
            val op = match.groupValues[1].ifBlank { "=" }
            val rhsText = match.groupValues[2]
            val rhs = parse(kind, rhsText) ?: return null
            val cmp = compare(parsedVersion, rhs)
            val satisfied = when (op) {
                "=" , "==" -> cmp == 0
                ">" -> cmp > 0
                ">=" -> cmp >= 0
                "<" -> cmp < 0
                "<=" -> cmp <= 0
                else -> return null
            }
            if (!satisfied) { all = false; break }
        }
        return Evaluation(
            matches = all,
            normalizedVersion = parsedVersion.render(),
            normalizedExpression = clauses.joinToString(", "),
            resolver = when (kind) {
                "MAVEN" -> "MAVEN_SAFE_1"
                "NPM" -> "NPM_SEMVER_SAFE_1"
                else -> "NUGET_SEMVER_SAFE_1"
            },
        )
    }

    /** Validates a range without requiring a target component version. */
    fun isSupportedExpression(ecosystem: String, expression: String): Boolean {
        val kind = normalizeEcosystem(ecosystem)
        if (kind !in setOf("MAVEN", "NPM", "NUGET")) return false
        val raw = expression.trim()
        if (raw.isBlank() || raw.length > 512) return false
        if (listOf("||", "^", "~", "*", " x", " X", "[", "]", "(", ")").any(raw::contains)) return false
        val clauses = splitClauses(raw) ?: return false
        return clauses.isNotEmpty() && clauses.size <= 8 && clauses.all { clause ->
            val m = CLAUSE.matchEntire(clause) ?: return@all false
            parse(kind, m.groupValues[2]) != null
        }
    }

    private val CLAUSE = Regex("^(>=|<=|==|=|>|<)?\\s*([0-9A-Za-z][0-9A-Za-z.+_-]{0,127})$")

    private fun splitClauses(raw: String): List<String>? {
        val comma = raw.split(',').map(String::trim).filter(String::isNotBlank)
        if (comma.size > 1) return comma
        // GitHub/npm ranges may use whitespace between comparator clauses.
        val tokens = raw.trim().split(Regex("\\s+")).filter(String::isNotBlank)
        if (tokens.size <= 2) return listOf(raw.trim())
        val clauses = mutableListOf<String>()
        var i = 0
        while (i < tokens.size) {
            val token = tokens[i]
            if (token in setOf(">", ">=", "<", "<=", "=", "==")) {
                if (i + 1 >= tokens.size) return null
                clauses += token + tokens[i + 1]
                i += 2
            } else if (token.matches(Regex("^(>=|<=|==|=|>|<).+"))) {
                clauses += token
                i++
            } else {
                // A bare version is only valid as a single equality expression.
                if (tokens.size != 1) return null
                clauses += token
                i++
            }
        }
        return clauses
    }

    private data class ParsedVersion(
        val numeric: List<Int>,
        val pre: List<PrePart>,
        val qualifierRank: Int? = null,
        val qualifierNumber: Int = 0,
        val kind: String,
    ) {
        fun render(): String {
            val base = numeric.joinToString(".")
            return when {
                kind == "MAVEN" && qualifierRank != null -> base + when (qualifierRank) {
                    0 -> "-snapshot"
                    1 -> "-alpha$qualifierNumber"
                    2 -> "-beta$qualifierNumber"
                    3 -> "-rc$qualifierNumber"
                    else -> ""
                }
                pre.isNotEmpty() -> base + "-" + pre.joinToString(".") { it.text }
                else -> base
            }
        }
    }

    private data class PrePart(val numeric: Int?, val text: String)

    private fun parse(kind: String, rawVersion: String): ParsedVersion? {
        val raw = rawVersion.trim().removePrefix("v")
        if (raw.isBlank() || raw.length > 128) return null
        return if (kind == "MAVEN") parseMaven(raw) else parseSemver(raw, kind)
    }

    private fun parseSemver(raw: String, kind: String): ParsedVersion? {
        val m = SEMVER.matchEntire(raw) ?: return null
        val nums = listOf(m.groupValues[1], m.groupValues[2], m.groupValues[3]).map {
            if (it.length > 1 && it.startsWith('0')) return null
            it.toIntOrNull() ?: return null
        }
        val preRaw = m.groupValues[4]
        val pre = if (preRaw.isBlank()) emptyList() else preRaw.split('.').map { part ->
            if (part.isBlank()) return null
            val n = part.toIntOrNull()
            if (n != null && part.length > 1 && part.startsWith('0')) return null
            PrePart(n, part.lowercase())
        }
        return ParsedVersion(nums, pre, kind = kind)
    }

    private fun parseMaven(raw: String): ParsedVersion? {
        val m = MAVEN.matchEntire(raw) ?: return null
        val nums = m.groupValues[1].split('.').map { it.toIntOrNull() ?: return null }.toMutableList()
        while (nums.size < 4) nums += 0
        while (nums.size > 1 && nums.last() == 0) nums.removeAt(nums.lastIndex)
        val qualifier = m.groupValues[2].lowercase()
        val qNum = m.groupValues[3].toIntOrNull() ?: 0
        val rank = when (qualifier) {
            "" -> 4
            "snapshot" -> 0
            "alpha", "a" -> 1
            "beta", "b" -> 2
            "rc", "cr" -> 3
            else -> return null
        }
        return ParsedVersion(nums, emptyList(), qualifierRank = rank, qualifierNumber = qNum, kind = "MAVEN")
    }

    private fun compare(a: ParsedVersion, b: ParsedVersion): Int {
        val width = maxOf(a.numeric.size, b.numeric.size)
        for (i in 0 until width) {
            val av = a.numeric.getOrElse(i) { 0 }
            val bv = b.numeric.getOrElse(i) { 0 }
            if (av != bv) return av.compareTo(bv)
        }
        if (a.kind == "MAVEN" || b.kind == "MAVEN") {
            val ar = a.qualifierRank ?: 4
            val br = b.qualifierRank ?: 4
            if (ar != br) return ar.compareTo(br)
            return a.qualifierNumber.compareTo(b.qualifierNumber)
        }
        if (a.pre.isEmpty() && b.pre.isNotEmpty()) return 1
        if (a.pre.isNotEmpty() && b.pre.isEmpty()) return -1
        val widthPre = maxOf(a.pre.size, b.pre.size)
        for (i in 0 until widthPre) {
            val ap = a.pre.getOrNull(i) ?: return -1
            val bp = b.pre.getOrNull(i) ?: return 1
            val cmp = when {
                ap.numeric != null && bp.numeric != null -> ap.numeric.compareTo(bp.numeric)
                ap.numeric != null -> -1
                bp.numeric != null -> 1
                else -> ap.text.compareTo(bp.text)
            }
            if (cmp != 0) return cmp
        }
        return 0
    }

    private fun normalizeEcosystem(value: String): String = when (value.trim().uppercase()) {
        "MAVEN" -> "MAVEN"
        "NPM" -> "NPM"
        "NUGET" -> "NUGET"
        else -> value.trim().uppercase()
    }

    private val SEMVER = Regex("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z.-]+)?$")
    private val MAVEN = Regex("^(\\d+(?:\\.\\d+){0,3})(?:-(snapshot|alpha|a|beta|b|rc|cr)(\\d*))?$", RegexOption.IGNORE_CASE)
}
