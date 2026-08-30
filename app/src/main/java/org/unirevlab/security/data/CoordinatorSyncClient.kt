package org.unirevlab.security.data

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import org.json.JSONObject
import org.unirevlab.security.analysis.GhidraResultIntegrator
import org.unirevlab.security.analysis.GhidraResultJsonParser
import org.unirevlab.security.model.StaticAnalysisReport

/** Small dependency-free client for a self-hosted UniRevLab coordinator sync endpoint. */
object CoordinatorSyncClient {
    data class Receipt(
        val report: StaticAnalysisReport,
        val coordinatorUrl: String,
        val pulledGhidraLibraries: Int,
        val historyItems: Int,
        val generatedAt: String,
        val auditTailHash: String? = null,
    )

    data class Limits(
        val maxResponseBytes: Int = 64 * 1024 * 1024,
        val connectTimeoutMs: Int = 10_000,
        val readTimeoutMs: Int = 30_000,
    )

    fun sync(baseUrl: String, report: StaticAnalysisReport, apiKey: String? = null, limits: Limits = Limits()): Receipt {
        val root = normalizeBaseUrl(baseUrl)
        val token = apiKey?.trim()?.takeIf { it.isNotBlank() }
        if (!isLabRoot(root)) require(token != null) { "Coordinator API key is required for non-lab hosts" }
        token?.let { require(it.length in 16..512 && !it.contains('\n') && !it.contains('\r')) { "Coordinator API key is invalid" } }
        val scope = report.assessment
        require(scope.confirmsAuthority) { "Assessment authority confirmation is required" }
        val request = JSONObject()
            .put("project_name", scope.projectName)
            .put("organization", scope.organization)
            .put("purpose", scope.purpose)
            .put("artifact_sha256", report.artifact.sha256)
            .put("modes", org.json.JSONArray(buildList {
                if (scope.staticAnalysis) add("static")
                if (scope.reverseEngineering) add("reverse")
                if (scope.dynamicAnalysis) add("dynamic")
                if (scope.networkTesting) add("network")
            }))
            .put("authority_confirmed", true)
            .put("created_at_epoch_ms", scope.createdAtEpochMs)
        requestJson("PUT", "$root/v1/assessments/${scope.assessmentId}", request.toString(), token, limits)

        val syncText = requestJson("GET", "$root/v1/assessments/${scope.assessmentId}/sync", null, token, limits)
        val sync = JSONObject(syncText)
        val syncSchema = sync.getString("syncSchemaVersion")
        require(syncSchema in setOf("1.0", "1.1")) { "Unsupported coordinator sync schema" }
        val assessment = sync.getJSONObject("assessment")
        require(assessment.getString("id") == scope.assessmentId) { "Coordinator assessment identity mismatch" }
        val remoteHash = assessment.getJSONObject("request").getString("artifact_sha256").lowercase()
        require(remoteHash == report.artifact.sha256.lowercase()) { "Coordinator artifact hash mismatch" }

        val ghidra = sync.getJSONArray("ghidraResults")
        val imported = if (ghidra.length() == 0) emptyList() else {
            GhidraResultJsonParser.parse(ByteArrayInputStream(ghidra.toString().toByteArray(Charsets.UTF_8)))
        }
        val updated = if (imported.isEmpty()) report else GhidraResultIntegrator.attach(report, imported)
        val history = sync.getJSONArray("ghidraHistory")
        return Receipt(
            report = updated,
            coordinatorUrl = root,
            pulledGhidraLibraries = imported.size,
            historyItems = history.length(),
            generatedAt = sync.getString("generatedAt"),
            auditTailHash = sync.optString("auditTailHash").takeIf { it.matches(Regex("[0-9a-f]{64}")) },
        )
    }

    internal fun normalizeBaseUrl(value: String): String {
        val raw = value.trim().trimEnd('/')
        require(raw.length in 8..2048) { "Coordinator URL is invalid" }
        val uri = URI(raw)
        require(uri.userInfo == null && uri.query == null && uri.fragment == null) { "Coordinator URL must not contain credentials, query, or fragment" }
        require(uri.path.isNullOrBlank() || uri.path == "/") { "Coordinator URL must point to the server root" }
        require(uri.scheme.equals("https", true) || uri.scheme.equals("http", true)) { "Coordinator URL must use http(s)" }
        val host = uri.host ?: error("Coordinator URL host is missing")
        if (uri.scheme.equals("http", true)) {
            require(isLabCleartextHost(host)) { "Plain HTTP is allowed only for localhost/Android-emulator host; use HTTPS for LAN/remote coordinators" }
        }
        return raw
    }

    private fun isLabRoot(root: String): Boolean {
        val uri = URI(root)
        return uri.scheme.equals("http", true) && isLabCleartextHost(uri.host ?: return false)
    }

    private fun isLabCleartextHost(host: String): Boolean {
        if (host.equals("localhost", true) || host == "10.0.2.2" || host == "::1" || host == "[::1]") return true
        val octets = host.split('.')
        return octets.size == 4 && octets.firstOrNull() == "127" && octets.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) && (part.toIntOrNull() ?: -1) in 0..255
        }
    }


    private fun requestJson(method: String, url: String, body: String?, apiKey: String?, limits: Limits): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = limits.connectTimeoutMs
            connection.readTimeout = limits.readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "UniRevLab-Android/${org.unirevlab.security.analysis.LocalArtifactInspector.ENGINE_VERSION}")
            apiKey?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                body.toByteArray(Charsets.UTF_8).also { bytes ->
                    require(bytes.size <= 1024 * 1024) { "Coordinator request body too large" }
                    connection.setFixedLengthStreamingMode(bytes.size)
                    connection.outputStream.use { it.write(bytes) }
                }
            }
            val status = connection.responseCode
            require(status !in 300..399) { "Coordinator redirects are not followed" }
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.use { readBounded(it, limits.maxResponseBytes) }?.toString(Charsets.UTF_8).orEmpty()
            require(status in 200..299) { "Coordinator HTTP $status${text.take(500).let { if (it.isBlank()) "" else ": $it" }}" }
            return text
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= maxBytes) { "Coordinator response exceeds bounded limit" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
