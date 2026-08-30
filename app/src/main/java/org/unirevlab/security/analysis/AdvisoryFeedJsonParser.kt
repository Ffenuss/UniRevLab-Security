package org.unirevlab.security.analysis

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import org.json.JSONObject
import org.unirevlab.security.model.AdvisoryFeedProvenance

/** Bounded parser for UniRevLab normalized offline advisory feed schema 1.0. */
object AdvisoryFeedJsonParser {
    data class Limits(
        val maxBytes: Int = 16 * 1024 * 1024,
        val maxAdvisories: Int = 20_000,
        val maxAffectedVersions: Int = 2_000,
    )

    fun parse(input: InputStream, limits: Limits = Limits()): VulnerabilityAdvisoryCorrelator.Feed {
        val bytes = readBounded(input, limits.maxBytes)
        val root = JSONObject(bytes.toString(Charsets.UTF_8))
        require(root.getString("schemaVersion") == "1.0") { "Unsupported advisory feed schema" }
        val advisories = root.getJSONArray("advisories")
        require(advisories.length() <= limits.maxAdvisories) { "Advisory feed exceeds bounded item limit" }
        val source = root.getString("source").trim().take(512)
        val feedId = root.getString("feedId").trim().take(256)
        val generatedAt = root.getString("generatedAt").trim().take(128)
        require(source.isNotBlank() && feedId.isNotBlank() && generatedAt.isNotBlank())
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val parsed = List(advisories.length()) { index ->
            val item = advisories.getJSONObject(index)
            val versions = item.getJSONArray("affectedVersions")
            require(versions.length() in 1..limits.maxAffectedVersions)
            val aliases = item.optJSONArray("aliases")
            VulnerabilityAdvisoryCorrelator.Advisory(
                id = item.getString("id").trim().take(160),
                aliases = if (aliases == null) emptyList() else List(aliases.length().coerceAtMost(32)) { aliases.getString(it).trim().take(160) },
                componentId = item.getString("componentId").trim().take(512),
                affectedVersions = List(versions.length()) { versions.getString(it).trim().take(256) }.filter { it.isNotBlank() }.toSet(),
                severity = item.optString("severity", "MEDIUM").trim().take(32),
                summary = item.getString("summary").trim().take(1_000),
                source = item.optString("source", source).trim().take(512),
            ).also { require(it.id.isNotBlank() && it.componentId.isNotBlank() && it.affectedVersions.isNotEmpty()) }
        }
        return VulnerabilityAdvisoryCorrelator.Feed(
            provenance = AdvisoryFeedProvenance("1.0", feedId, source, generatedAt, sha, parsed.size),
            advisories = parsed,
        )
    }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= maxBytes) { "Advisory feed exceeds $maxBytes byte import limit" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
