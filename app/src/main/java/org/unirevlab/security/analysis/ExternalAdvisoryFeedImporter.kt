package org.unirevlab.security.analysis

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.unirevlab.security.model.AdvisoryFeedProvenance

/**
 * Bounded offline adapters for upstream advisory JSON.
 *
 * Exact affected versions are normalized directly. v0.21 also preserves only those Maven/npm/NuGet
 * ranges that fit the conservative ecosystem resolver; unsupported range grammar is counted as
 * skipped evidence rather than guessed.
 */
object ExternalAdvisoryFeedImporter {
    const val ADAPTER_VERSION = "1.1"

    data class Limits(
        val maxBytes: Int = 32 * 1024 * 1024,
        val maxSourceAdvisories: Int = 25_000,
        val maxNormalizedAdvisories: Int = 20_000,
        val maxAffectedVersions: Int = 2_000,
    )

    fun parse(input: InputStream, limits: Limits = Limits()): VulnerabilityAdvisoryCorrelator.Feed {
        val bytes = readBounded(input, limits.maxBytes)
        val text = bytes.toString(Charsets.UTF_8).trim()
        require(text.isNotBlank()) { "Advisory input is empty" }
        val token = JSONTokener(text).nextValue()
        if (token is JSONObject && token.optString("schemaVersion") == "1.0" && token.has("advisories")) {
            return AdvisoryFeedJsonParser.parse(ByteArrayInputStream(bytes))
        }
        val sha = sha256(bytes)
        return when (token) {
            is JSONObject -> when {
                token.has("vulnerabilities") && (token.optString("format").startsWith("NVD", true) || token.optString("version") == "2.0") -> parseNvd(token, sha, limits)
                token.has("ghsa_id") -> parseGithub(JSONArray().put(token), sha, limits)
                token.has("id") && token.has("affected") -> parseOsv(JSONArray().put(token), sha, limits, token.optString("modified"))
                token.optJSONArray("vulns") != null -> parseOsv(token.getJSONArray("vulns"), sha, limits, token.optString("modified"))
                else -> error("Unsupported advisory JSON format")
            }
            is JSONArray -> {
                require(token.length() <= limits.maxSourceAdvisories) { "Advisory source exceeds bounded item limit" }
                val first = token.optJSONObject(0)
                when {
                    first == null -> error("Advisory array is empty or invalid")
                    first.has("ghsa_id") -> parseGithub(token, sha, limits)
                    first.has("id") && first.has("affected") -> parseOsv(token, sha, limits, null)
                    else -> error("Unsupported advisory array format")
                }
            }
            else -> error("Unsupported advisory JSON root")
        }
    }

    private fun parseOsv(
        source: JSONArray,
        sha: String,
        limits: Limits,
        bundleModified: String?,
    ): VulnerabilityAdvisoryCorrelator.Feed {
        require(source.length() <= limits.maxSourceAdvisories) { "OSV input exceeds bounded advisory limit" }
        val out = mutableListOf<VulnerabilityAdvisoryCorrelator.Advisory>()
        var skipped = 0
        val timestamps = mutableListOf<String>()
        for (i in 0 until source.length()) {
            val vuln = source.optJSONObject(i)
            if (vuln == null) { skipped++; continue }
            val id = vuln.optString("id").trim().take(160)
            if (id.isBlank()) { skipped++; continue }
            vuln.optString("modified").trim().takeIf { it.isNotBlank() }?.let(timestamps::add)
            val aliases = strings(vuln.optJSONArray("aliases"), 32, 160)
            val summary = (vuln.optString("summary").ifBlank { vuln.optString("details") }).trim().take(1_000)
            val topSeverity = osvSeverity(vuln)
            val affected = vuln.optJSONArray("affected")
            var acceptedForSource = 0
            if (affected != null) {
                for (j in 0 until affected.length()) {
                    if (out.size >= limits.maxNormalizedAdvisories) break
                    val item = affected.optJSONObject(j) ?: continue
                    val pkg = item.optJSONObject("package") ?: continue
                    val ecosystemRaw = pkg.optString("ecosystem")
                    val component = componentId(ecosystemRaw, pkg.optString("name")) ?: continue
                    val versions = strings(item.optJSONArray("versions"), limits.maxAffectedVersions, 256)
                        .filter { it.isNotBlank() }.toSet()
                    val ranges = parseOsvRanges(item.optJSONArray("ranges"), ecosystemRaw)
                    if (versions.isEmpty() && ranges.isEmpty()) continue
                    out += VulnerabilityAdvisoryCorrelator.Advisory(
                        id = id,
                        aliases = aliases,
                        componentId = component,
                        affectedVersions = versions,
                        affectedRanges = ranges,
                        severity = normalizeSeverity(osvSeverity(item).takeUnless { it == "MEDIUM" } ?: topSeverity),
                        summary = summary.ifBlank { "OSV advisory $id" },
                        source = "OSV",
                    )
                    acceptedForSource++
                }
            }
            if (acceptedForSource == 0) skipped++
        }
        val generatedAt = (timestamps + listOfNotNull(bundleModified?.takeIf { it.isNotBlank() })).maxOrNull() ?: "UNSPECIFIED"
        return feed("OSV", sha, generatedAt, out, skipped)
    }

    private fun parseGithub(source: JSONArray, sha: String, limits: Limits): VulnerabilityAdvisoryCorrelator.Feed {
        require(source.length() <= limits.maxSourceAdvisories) { "GitHub advisory input exceeds bounded item limit" }
        val out = mutableListOf<VulnerabilityAdvisoryCorrelator.Advisory>()
        val timestamps = mutableListOf<String>()
        var skipped = 0
        val exact = Regex("^(?:==?|=)?\\s*([0-9A-Za-z][0-9A-Za-z._+\\-:]*)$")
        for (i in 0 until source.length()) {
            val item = source.optJSONObject(i)
            if (item == null) { skipped++; continue }
            val id = item.optString("ghsa_id").trim().take(160)
            if (id.isBlank()) { skipped++; continue }
            listOf("updated_at", "published_at").map { item.optString(it).trim() }.filter { it.isNotBlank() }.forEach(timestamps::add)
            val aliases = buildList {
                item.optString("cve_id").trim().takeIf { it.isNotBlank() }?.let(::add)
            }
            val vulnerabilities = item.optJSONArray("vulnerabilities")
            var acceptedForSource = 0
            if (vulnerabilities != null) {
                for (j in 0 until vulnerabilities.length()) {
                    if (out.size >= limits.maxNormalizedAdvisories) break
                    val affected = vulnerabilities.optJSONObject(j) ?: continue
                    val pkg = affected.optJSONObject("package") ?: continue
                    val ecosystemRaw = pkg.optString("ecosystem")
                    val component = componentId(ecosystemRaw, pkg.optString("name")) ?: continue
                    val range = affected.optString("vulnerable_version_range").trim()
                    val match = exact.matchEntire(range)
                    val versions = match?.groupValues?.getOrNull(1)?.takeIf { it.isNotBlank() }?.let { setOf(it.take(256)) }.orEmpty()
                    val normalizedEcosystem = rangeEcosystem(ecosystemRaw)
                    val ranges = if (versions.isEmpty() && normalizedEcosystem != null && EcosystemVersionRangeResolver.isSupportedExpression(normalizedEcosystem, range)) {
                        listOf(VulnerabilityAdvisoryCorrelator.VersionRange(normalizedEcosystem, range.take(512), "github:vulnerable_version_range"))
                    } else emptyList()
                    if (versions.isEmpty() && ranges.isEmpty()) continue
                    out += VulnerabilityAdvisoryCorrelator.Advisory(
                        id = id,
                        aliases = aliases,
                        componentId = component,
                        affectedVersions = versions,
                        affectedRanges = ranges,
                        severity = normalizeSeverity(item.optString("severity")),
                        summary = item.optString("summary").trim().take(1_000).ifBlank { "GitHub advisory $id" },
                        source = "GitHub Advisory Database",
                    )
                    acceptedForSource++
                }
            }
            if (acceptedForSource == 0) skipped++
        }
        return feed("GITHUB_GLOBAL_ADVISORY", sha, timestamps.maxOrNull() ?: "UNSPECIFIED", out, skipped)
    }

    private fun parseNvd(root: JSONObject, sha: String, limits: Limits): VulnerabilityAdvisoryCorrelator.Feed {
        val source = root.optJSONArray("vulnerabilities") ?: error("NVD vulnerabilities array is missing")
        require(source.length() <= limits.maxSourceAdvisories) { "NVD input exceeds bounded advisory limit" }
        val out = mutableListOf<VulnerabilityAdvisoryCorrelator.Advisory>()
        var skipped = 0
        for (i in 0 until source.length()) {
            val wrapper = source.optJSONObject(i)
            if (wrapper == null) { skipped++; continue }
            val cve = wrapper.optJSONObject("cve")
            if (cve == null) { skipped++; continue }
            val id = cve.optString("id").trim().take(160)
            if (id.isBlank()) { skipped++; continue }
            val summary = nvdEnglishDescription(cve).take(1_000).ifBlank { "NVD advisory $id" }
            val severity = nvdSeverity(cve)
            val exactMatches = mutableMapOf<String, MutableSet<String>>()
            collectNvdExactCpes(cve.optJSONArray("configurations"), exactMatches, limits.maxAffectedVersions)
            var acceptedForSource = 0
            for ((component, versions) in exactMatches.toSortedMap()) {
                if (out.size >= limits.maxNormalizedAdvisories) break
                if (versions.isEmpty()) continue
                out += VulnerabilityAdvisoryCorrelator.Advisory(
                    id = id,
                    aliases = emptyList(),
                    componentId = component,
                    affectedVersions = versions,
                    severity = severity,
                    summary = summary,
                    source = "NVD 2.0",
                )
                acceptedForSource++
            }
            if (acceptedForSource == 0) skipped++
        }
        val generatedAt = root.optString("timestamp").trim().ifBlank { "UNSPECIFIED" }
        return feed("NVD_CVE_2_0", sha, generatedAt, out, skipped)
    }

    private fun collectNvdExactCpes(configurations: JSONArray?, out: MutableMap<String, MutableSet<String>>, maxVersions: Int) {
        if (configurations == null) return
        var nodeBudget = 50_000
        fun walk(node: JSONObject) {
            if (--nodeBudget < 0) return
            val matches = node.optJSONArray("cpeMatch")
            if (matches != null) for (i in 0 until matches.length()) {
                val match = matches.optJSONObject(i) ?: continue
                if (!match.optBoolean("vulnerable", false)) continue
                if (listOf("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding").any(match::has)) continue
                val parts = parseCpe23(match.optString("criteria")) ?: continue
                val version = parts[5]
                if (version.isBlank() || version == "*" || version == "-") continue
                val component = "cpe:${parts[3].lowercase()}:${parts[4].lowercase()}"
                val versions = out.getOrPut(component) { linkedSetOf() }
                if (versions.size < maxVersions) versions += unescapeCpe(version).take(256)
            }
            val children = node.optJSONArray("nodes")
            if (children != null) for (i in 0 until children.length()) children.optJSONObject(i)?.let(::walk)
        }
        for (i in 0 until configurations.length()) configurations.optJSONObject(i)?.let(::walk)
    }

    private fun parseCpe23(criteria: String): List<String>? {
        if (!criteria.startsWith("cpe:2.3:")) return null
        val parts = mutableListOf<String>()
        val current = StringBuilder()
        var escaped = false
        for (c in criteria) {
            if (escaped) { current.append('\\').append(c); escaped = false }
            else if (c == '\\') escaped = true
            else if (c == ':') { parts += current.toString(); current.setLength(0) }
            else current.append(c)
        }
        if (escaped) current.append('\\')
        parts += current.toString()
        return parts.takeIf { it.size >= 6 && it[0] == "cpe" && it[1] == "2.3" }
    }

    private fun unescapeCpe(value: String): String = value.replace(Regex("\\\\(.)"), "$1")

    private fun nvdEnglishDescription(cve: JSONObject): String {
        val descriptions = cve.optJSONArray("descriptions") ?: return ""
        for (i in 0 until descriptions.length()) {
            val item = descriptions.optJSONObject(i) ?: continue
            if (item.optString("lang").equals("en", true)) return item.optString("value").trim()
        }
        return descriptions.optJSONObject(0)?.optString("value")?.trim().orEmpty()
    }

    private fun nvdSeverity(cve: JSONObject): String {
        val metrics = cve.optJSONObject("metrics") ?: return "MEDIUM"
        for (key in listOf("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")) {
            val array = metrics.optJSONArray(key) ?: continue
            for (i in 0 until array.length()) {
                val metric = array.optJSONObject(i) ?: continue
                val direct = metric.optString("baseSeverity").trim()
                if (direct.isNotBlank()) return normalizeSeverity(direct)
                val cvss = metric.optJSONObject("cvssData") ?: continue
                val nested = cvss.optString("baseSeverity").trim()
                if (nested.isNotBlank()) return normalizeSeverity(nested)
            }
        }
        return "MEDIUM"
    }

    private fun osvSeverity(value: JSONObject): String {
        val db = value.optJSONObject("database_specific")
        val direct = db?.optString("severity")?.trim().orEmpty()
        return normalizeSeverity(direct)
    }


    private fun parseOsvRanges(source: JSONArray?, ecosystemRaw: String): List<VulnerabilityAdvisoryCorrelator.VersionRange> {
        if (source == null) return emptyList()
        val ecosystem = rangeEcosystem(ecosystemRaw) ?: return emptyList()
        val out = mutableListOf<VulnerabilityAdvisoryCorrelator.VersionRange>()
        for (i in 0 until minOf(source.length(), 64)) {
            val range = source.optJSONObject(i) ?: continue
            val type = range.optString("type").uppercase()
            if (type !in setOf("ECOSYSTEM", "SEMVER")) continue
            val events = range.optJSONArray("events") ?: continue
            var introduced: String? = null
            for (j in 0 until minOf(events.length(), 128)) {
                val event = events.optJSONObject(j) ?: continue
                val intro = event.optString("introduced").trim().takeIf { it.isNotBlank() }
                if (intro != null) {
                    introduced = intro.takeUnless { it == "0" }
                    continue
                }
                val fixed = event.optString("fixed").trim().takeIf { it.isNotBlank() }
                val last = event.optString("last_affected").trim().takeIf { it.isNotBlank() }
                val limit = event.optString("limit").trim().takeIf { it.isNotBlank() }
                val end = fixed ?: last ?: limit ?: continue
                val endOp = if (last != null) "<=" else "<"
                val expression = buildList {
                    introduced?.let { add(">= $it") }
                    add("$endOp $end")
                }.joinToString(", ")
                if (EcosystemVersionRangeResolver.isSupportedExpression(ecosystem, expression)) {
                    out += VulnerabilityAdvisoryCorrelator.VersionRange(ecosystem, expression, "osv:$type")
                }
                introduced = null
            }
            introduced?.let { start ->
                val expression = ">= $start"
                if (EcosystemVersionRangeResolver.isSupportedExpression(ecosystem, expression)) {
                    out += VulnerabilityAdvisoryCorrelator.VersionRange(ecosystem, expression, "osv:$type")
                }
            }
        }
        return out.distinctBy { Pair(it.ecosystem, it.expression) }.take(64)
    }

    private fun rangeEcosystem(ecosystemRaw: String): String? = when (ecosystemRaw.trim().substringBefore(':').uppercase()) {
        "MAVEN" -> "MAVEN"
        "NPM" -> "NPM"
        "NUGET" -> "NUGET"
        else -> null
    }

    private fun componentId(ecosystemRaw: String, nameRaw: String): String? {
        val ecosystem = ecosystemRaw.trim().substringBefore(':').lowercase()
        val name = nameRaw.trim()
        if (name.isBlank()) return null
        return when (ecosystem) {
            "maven" -> "maven:$name"
            "npm" -> "npm:$name"
            "pypi", "pip" -> "pypi:${name.lowercase()}"
            "nuget" -> "nuget:${name.lowercase()}"
            "pub" -> "pub:$name"
            "go" -> "go:$name"
            "crates.io", "rust" -> "cargo:$name"
            "packagist", "composer" -> "composer:$name"
            "rubygems" -> "rubygems:$name"
            else -> null
        }
    }

    private fun normalizeSeverity(value: String): String = when (value.trim().uppercase()) {
        "CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFORMATIONAL" -> when (value.trim().uppercase()) {
            "MODERATE" -> "MEDIUM"
            else -> value.trim().uppercase()
        }
        else -> "MEDIUM"
    }

    private fun strings(array: JSONArray?, max: Int, maxLength: Int): List<String> {
        if (array == null) return emptyList()
        return List(minOf(array.length(), max)) { array.optString(it).trim().take(maxLength) }.filter { it.isNotBlank() }
    }

    private fun feed(
        format: String,
        sha: String,
        generatedAt: String,
        advisories: List<VulnerabilityAdvisoryCorrelator.Advisory>,
        skipped: Int,
    ): VulnerabilityAdvisoryCorrelator.Feed {
        val bounded = advisories.distinctBy { listOf(it.id, it.componentId, it.affectedVersions.sorted().joinToString("|"), it.affectedRanges.joinToString("|") { r -> "${r.ecosystem}:${r.expression}" }) }
        return VulnerabilityAdvisoryCorrelator.Feed(
            provenance = AdvisoryFeedProvenance(
                schemaVersion = "1.0",
                feedId = "${format.lowercase()}:${sha.take(16)}",
                source = format,
                generatedAt = generatedAt.take(128).ifBlank { "UNSPECIFIED" },
                sha256 = sha,
                advisoryCount = bounded.size,
                format = format,
                adapterVersion = ADAPTER_VERSION,
                skippedAdvisoryCount = skipped,
            ),
            advisories = bounded,
        )
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= maxBytes) { "Advisory input exceeds $maxBytes byte import limit" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
