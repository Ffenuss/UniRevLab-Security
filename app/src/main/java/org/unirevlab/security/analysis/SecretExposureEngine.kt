package org.unirevlab.security.analysis

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.Locale
import java.util.zip.ZipFile

/**
 * Secret Exposure Proof for an explicitly authorized Patch Lab target.
 *
 * The scanner returns metadata only. Full secret material is kept in a process-local vault and is
 * available only through [reveal] after the UI has obtained target-specific authorization.
 * Nothing in this type is serialized into the normal deterministic report.
 */
object SecretExposureEngine {
    data class ExposureHit(
        val id: String,
        val kind: String,
        val entryName: String,
        val offset: Long,
        val confidence: String,
        val exposure: String,
        val storage: String,
        val redactedPreview: String,
        val valueSha256: String,
        val recoveredSha256: String?,
        val recoverySteps: List<String>,
        val roundTripVerified: Boolean,
        val structurallyValid: Boolean,
        val editableTextEntry: Boolean,
        val remediation: List<String>,
    )

    data class ExposureReport(
        val artifactSha256: String,
        val entriesScanned: Int,
        val bytesScanned: Long,
        val hits: List<ExposureHit>,
        val truncated: Boolean,
    )

    data class RevealResult(
        val rawValue: String,
        val recoveredValue: String?,
        val recoverySteps: List<String>,
    )

    private data class VaultRecord(
        val artifactSha256: String,
        val rawValue: String,
        val recoveredValue: String?,
        val recoverySteps: List<String>,
    )

    private data class Recovery(
        val storage: String,
        val recovered: String?,
        val steps: List<String>,
        val roundTrip: Boolean,
    )

    private val vault = Collections.synchronizedMap(mutableMapOf<String, VaultRecord>())

    fun scan(workspace: PatchLabEngine.Workspace): ExposureReport = scanApk(workspace.originalApk, workspace.artifactSha256)

    fun reveal(hitId: String, artifactSha256: String, authorizationConfirmed: Boolean): RevealResult {
        require(authorizationConfirmed) { "Полный просмотр не подтверждён для этой цели" }
        val record = synchronized(vault) { vault[hitId] }
            ?: error("Secret material больше не находится во временном vault; запустите Secret Exposure Proof повторно")
        require(record.artifactSha256.equals(artifactSha256, ignoreCase = true)) {
            "Secret material относится к другому APK"
        }
        return RevealResult(record.rawValue, record.recoveredValue, record.recoverySteps)
    }

    fun forgetArtifact(artifactSha256: String) {
        synchronized(vault) {
            val iterator = vault.entries.iterator()
            while (iterator.hasNext()) {
                if (iterator.next().value.artifactSha256.equals(artifactSha256, ignoreCase = true)) iterator.remove()
            }
        }
    }

    internal fun scanApk(apk: File, artifactSha256: String): ExposureReport {
        require(apk.isFile && apk.length() > 0L) { "Исходный APK недоступен" }
        forgetArtifact(artifactSha256)
        val hits = mutableListOf<ExposureHit>()
        val dedupe = mutableSetOf<String>()
        var entriesScanned = 0
        var bytesScanned = 0L
        var truncated = false

        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                if (bytesScanned >= MAX_TOTAL_SCAN_BYTES) {
                    truncated = true
                    break
                }
                entriesScanned++
                zip.getInputStream(entry).use { input ->
                    val allowance = MAX_TOTAL_SCAN_BYTES - bytesScanned
                    val scanned = scanStream(
                        artifactSha256 = artifactSha256,
                        entryName = entry.name,
                        entrySize = entry.size,
                        input = input,
                        maxBytes = allowance,
                        hits = hits,
                        dedupe = dedupe,
                    )
                    bytesScanned += scanned
                    if (entry.size > 0 && scanned < entry.size) truncated = true
                }
            }
        }
        return ExposureReport(
            artifactSha256 = artifactSha256,
            entriesScanned = entriesScanned,
            bytesScanned = bytesScanned,
            hits = hits.sortedWith(compareByDescending<ExposureHit> { confidenceRank(it.confidence) }.thenBy { it.entryName }.thenBy { it.offset }),
            truncated = truncated || hits.size >= MAX_FINDINGS,
        )
    }

    private fun scanStream(
        artifactSha256: String,
        entryName: String,
        entrySize: Long,
        input: InputStream,
        maxBytes: Long,
        hits: MutableList<ExposureHit>,
        dedupe: MutableSet<String>,
    ): Long {
        val buffer = ByteArray(CHUNK_BYTES)
        var carry = ByteArray(0)
        var total = 0L
        while (total < maxBytes) {
            val requested = minOf(buffer.size.toLong(), maxBytes - total).toInt()
            if (requested <= 0) break
            val read = input.read(buffer, 0, requested)
            if (read < 0) break
            if (read == 0) continue
            val combined = ByteArray(carry.size + read)
            carry.copyInto(combined)
            buffer.copyInto(combined, carry.size, 0, read)
            val baseOffset = total - carry.size
            scanWindow(artifactSha256, entryName, entrySize, combined, baseOffset, hits, dedupe)
            total += read
            val keep = minOf(OVERLAP_BYTES, combined.size)
            carry = combined.copyOfRange(combined.size - keep, combined.size)
        }
        return total
    }

    private fun scanWindow(
        artifactSha256: String,
        entryName: String,
        entrySize: Long,
        bytes: ByteArray,
        baseOffset: Long,
        hits: MutableList<ExposureHit>,
        dedupe: MutableSet<String>,
    ) {
        if (hits.size >= MAX_FINDINGS) return
        // ISO-8859-1 keeps a 1:1 byte-to-char mapping, so offsets remain meaningful even for DEX/.so.
        val text = bytes.toString(Charsets.ISO_8859_1)

        PRIVATE_KEY_BLOCK.findAll(text).forEach { match ->
            if (hits.size >= MAX_FINDINGS) return@forEach
            val raw = match.value
            val body = match.groupValues.getOrNull(1).orEmpty().filterNot(Char::isWhitespace)
            val decoded = runCatching { Base64.getDecoder().decode(body) }.getOrNull()
            val valid = decoded != null && looksLikeDerSequence(decoded)
            if (!valid) return@forEach
            addHit(
                artifactSha256, entryName, entrySize, baseOffset + match.range.first,
                kind = "PRIVATE_KEY_MATERIAL", rawValue = raw, confidence = "HIGH",
                exposure = "STRUCTURALLY_VALID", storage = "PEM",
                recoveredValue = null,
                recoverySteps = listOf("PEM body Base64 decoded", "DER SEQUENCE structure validated"),
                roundTrip = true, structurallyValid = true, hits = hits, dedupe = dedupe,
            )
        }

        DIRECT_PATTERNS.forEach { pattern ->
            pattern.regex.findAll(text).forEach { match ->
                if (hits.size >= MAX_FINDINGS) return@forEach
                val raw = match.value
                if (isPlaceholder(raw)) return@forEach
                addHit(
                    artifactSha256, entryName, entrySize, baseOffset + match.range.first,
                    kind = pattern.kind, rawValue = raw, confidence = pattern.confidence,
                    exposure = "PLAINTEXT_EXPOSED", storage = pattern.storage,
                    recoveredValue = null, recoverySteps = emptyList(), roundTrip = false,
                    structurallyValid = pattern.structured, hits = hits, dedupe = dedupe,
                )
            }
        }

        GENERIC_ASSIGNMENT.findAll(text).forEach { match ->
            if (hits.size >= MAX_FINDINGS) return@forEach
            val label = match.groupValues.getOrNull(1).orEmpty().lowercase(Locale.ROOT)
            val raw = trimValue(match.groupValues.getOrNull(2).orEmpty())
            if (raw.length < 8 || isPlaceholder(raw) || lowInformation(raw)) return@forEach
            val recovery = recover(raw)
            val kind = genericKind(label)
            val confidence = when {
                recovery.recovered != null && recovery.roundTrip -> "HIGH"
                raw.length >= 20 -> "MEDIUM"
                else -> "LOW"
            }
            addHit(
                artifactSha256, entryName, entrySize,
                baseOffset + match.range.first + match.value.indexOf(raw).coerceAtLeast(0),
                kind = kind, rawValue = raw, confidence = confidence,
                exposure = if (recovery.recovered != null) "RECOVERABLE_ENCODING" else "PLAINTEXT_EXPOSED",
                storage = recovery.storage, recoveredValue = recovery.recovered,
                recoverySteps = recovery.steps, roundTrip = recovery.roundTrip,
                structurallyValid = false, hits = hits, dedupe = dedupe,
            )
        }
    }

    private fun addHit(
        artifactSha256: String,
        entryName: String,
        entrySize: Long,
        offset: Long,
        kind: String,
        rawValue: String,
        confidence: String,
        exposure: String,
        storage: String,
        recoveredValue: String?,
        recoverySteps: List<String>,
        roundTrip: Boolean,
        structurallyValid: Boolean,
        hits: MutableList<ExposureHit>,
        dedupe: MutableSet<String>,
    ) {
        val rawSha = sha256(rawValue)
        val effective = recoveredValue ?: rawValue
        val recoveredSha = recoveredValue?.let(::sha256)
        // Prefer the concrete detector that runs first; generic assignment detection must not
        // duplicate the same bytes under a second kind.
        val dedupeKey = "$entryName|$offset|$rawSha"
        if (!dedupe.add(dedupeKey)) return
        val id = sha256("$artifactSha256|$dedupeKey")
        synchronized(vault) {
            vault[id] = VaultRecord(artifactSha256, rawValue, recoveredValue, recoverySteps)
        }
        hits += ExposureHit(
            id = id,
            kind = kind,
            entryName = entryName,
            offset = offset.coerceAtLeast(0L),
            confidence = confidence,
            exposure = exposure,
            storage = storage,
            redactedPreview = redact(effective),
            valueSha256 = rawSha,
            recoveredSha256 = recoveredSha,
            recoverySteps = recoverySteps,
            roundTripVerified = roundTrip,
            structurallyValid = structurallyValid,
            editableTextEntry = entrySize in 0..MAX_EDITABLE_TEXT_BYTES && isTextCandidate(entryName),
            remediation = remediation(kind),
        )
    }

    private fun recover(input: String): Recovery {
        var current = input
        val steps = mutableListOf<String>()
        var storage = "PLAINTEXT"
        var roundTrip = false

        repeat(MAX_RECOVERY_DEPTH) {
            val url = decodeUrl(current)
            if (url != null && url != current) {
                current = url
                steps += "URL percent-decoding succeeded"
                storage = if (storage == "PLAINTEXT") "URL_ENCODED" else "$storage→URL"
                roundTrip = true
                return@repeat
            }
            val hex = decodeHex(current)
            if (hex != null) {
                current = hex
                steps += "Hex decoding succeeded"
                storage = if (storage == "PLAINTEXT") "HEX" else "$storage→HEX"
                roundTrip = true
                return@repeat
            }
            val b64 = decodeBase64(current)
            if (b64 != null) {
                current = b64
                steps += "Base64 decoding succeeded with reversible round-trip"
                storage = if (storage == "PLAINTEXT") "BASE64" else "$storage→BASE64"
                roundTrip = true
                return@repeat
            }
            return@repeat
        }
        return if (steps.isEmpty()) Recovery("PLAINTEXT", null, emptyList(), false)
        else Recovery(storage, current, steps, roundTrip)
    }

    private fun decodeUrl(value: String): String? {
        if (!PERCENT_ESCAPE.containsMatchIn(value)) return null
        return runCatching { URLDecoder.decode(value, Charsets.UTF_8.name()) }
            .getOrNull()?.takeIf { it != value && printableRatio(it.toByteArray(Charsets.UTF_8)) >= 0.75 }
    }

    private fun decodeHex(value: String): String? {
        val compact = value.trim()
        if (compact.length !in 16..2048 || compact.length % 2 != 0 || !HEX.matches(compact)) return null
        val bytes = ByteArray(compact.length / 2)
        for (i in bytes.indices) {
            bytes[i] = compact.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        if (printableRatio(bytes) < 0.75) return null
        val decoded = bytes.toString(Charsets.UTF_8)
        if ('\uFFFD' in decoded || decoded.isBlank()) return null
        val encoded = bytes.joinToString("") { "%02x".format(it) }
        return decoded.takeIf { encoded.equals(compact, ignoreCase = true) }
    }

    private fun decodeBase64(value: String): String? {
        val compact = value.filterNot(Char::isWhitespace)
        if (compact.length !in 16..4096 || !BASE64_TEXT.matches(compact)) return null
        val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
        val decoded = runCatching { Base64.getDecoder().decode(padded) }.getOrNull() ?: return null
        if (decoded.size < 6 || printableRatio(decoded) < 0.75) return null
        val text = decoded.toString(Charsets.UTF_8)
        if ('\uFFFD' in text || text.isBlank()) return null
        val reencoded = Base64.getEncoder().encodeToString(decoded).trimEnd('=')
        return text.takeIf { reencoded == compact.trimEnd('=') }
    }

    private fun looksLikeDerSequence(bytes: ByteArray): Boolean {
        if (bytes.size < 64 || bytes[0].toInt() and 0xff != 0x30 || bytes.size < 2) return false
        val firstLength = bytes[1].toInt() and 0xff
        var header = 2
        val contentLength = if (firstLength < 0x80) {
            firstLength
        } else {
            val count = firstLength and 0x7f
            if (count !in 1..4 || bytes.size < 2 + count) return false
            var value = 0
            repeat(count) { index -> value = (value shl 8) or (bytes[2 + index].toInt() and 0xff) }
            header += count
            value
        }
        return contentLength > 0 && contentLength <= bytes.size - header
    }

    private fun genericKind(label: String): String = when {
        "client" in label && "secret" in label -> "CLIENT_SECRET"
        "api" in label && "key" in label -> "API_KEY"
        "access" in label && "token" in label -> "ACCESS_TOKEN"
        "auth" in label && "token" in label -> "AUTH_TOKEN"
        "session" in label -> "SESSION_TOKEN"
        "password" in label || "passwd" in label -> "PASSWORD_LIKE"
        else -> "SECRET"
    }

    private fun remediation(kind: String): List<String> = when (kind) {
        "PRIVATE_KEY_MATERIAL" -> listOf(
            "Считать private key скомпрометированным и ротировать/отозвать его.",
            "Убрать глобальный private key из APK; операции подписи/расшифрования выполнять на доверенном backend.",
            "Для per-install ключей использовать Android Keystore и не экспортировать private material.",
        )
        "GOOGLE_API_KEY" -> listOf(
            "Проверить Android package + signing-certificate restrictions и список разрешённых Google API.",
            "Не использовать клиентский Google API key как серверный secret или доказательство авторизации.",
            "Ограничить quota и ротировать ключ, если он ранее был unrestricted.",
        )
        "AWS_ACCESS_KEY_ID" -> listOf(
            "Не поставлять долгоживущие cloud credentials в клиенте.",
            "Ротировать связанные credentials и выдавать клиенту только краткоживущие ограниченные server-mediated grants.",
        )
        "CLIENT_SECRET", "API_KEY", "ACCESS_TOKEN", "AUTH_TOKEN", "SESSION_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "STRIPE_SECRET_KEY" -> listOf(
            "Ротировать подтверждённое значение, если оно действующее.",
            "Перенести привилегированную операцию и общий secret на backend/broker.",
            "Клиенту выдавать краткоживущие scoped credentials после серверной аутентификации.",
        )
        else -> listOf(
            "Проверить назначение значения и считать его извлекаемым из клиентского APK.",
            "Не использовать обратимое кодирование/обфускацию как границу безопасности.",
            "Если значение даёт привилегии — ротировать его и перенести доверие на backend.",
        )
    }

    private fun isPlaceholder(value: String): Boolean {
        val lower = value.lowercase(Locale.ROOT)
        return lower.contains("example") || lower.contains("placeholder") || lower.contains("changeme") ||
            lower.contains("your_key") || lower.contains("your-key") || lower.contains("xxxx") ||
            value.all { it == '*' || it == 'x' || it == 'X' || it == '0' }
    }

    private fun lowInformation(value: String): Boolean = value.toSet().size <= 3

    private fun trimValue(value: String): String = value.trim().trimEnd(',', ';', ')', '}', ']')

    private fun redact(value: String): String = when {
        value.contains("PRIVATE KEY-----", ignoreCase = true) -> "PEM private key · length=${value.length}"
        value.length <= 8 -> "<redacted:length=${value.length}>"
        else -> "${value.take(4)}…${value.takeLast(4)} · length=${value.length}"
    }

    private fun printableRatio(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val printable = bytes.count { b ->
            val v = b.toInt() and 0xff
            v == 9 || v == 10 || v == 13 || v in 0x20..0x7e
        }
        return printable.toDouble() / bytes.size
    }

    private fun isTextCandidate(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return TEXT_EXTENSIONS.any { lower.endsWith(it) } || lower.substringAfterLast('/') in setOf("config", "settings")
    }

    private fun confidenceRank(value: String): Int = when (value) { "HIGH" -> 3; "MEDIUM" -> 2; else -> 1 }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private data class DirectPattern(
        val kind: String,
        val regex: Regex,
        val confidence: String = "HIGH",
        val storage: String = "PLAINTEXT",
        val structured: Boolean = false,
    )

    private val DIRECT_PATTERNS = listOf(
        DirectPattern("GOOGLE_API_KEY", Regex("\\bAIza[0-9A-Za-z_-]{35}\\b")),
        DirectPattern("AWS_ACCESS_KEY_ID", Regex("\\bAKIA[0-9A-Z]{16}\\b"), "MEDIUM"),
        DirectPattern("GITHUB_TOKEN", Regex("\\bgh[pousr]_[A-Za-z0-9_]{30,255}\\b")),
        DirectPattern("OPENAI_API_KEY", Regex("\\bsk-(?:proj-)?[A-Za-z0-9_-]{24,255}\\b")),
        DirectPattern("STRIPE_SECRET_KEY", Regex("\\bsk_live_[A-Za-z0-9]{16,255}\\b")),
        DirectPattern("JWT", Regex("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"), "MEDIUM", "JWT", true),
    )

    private val GENERIC_ASSIGNMENT = Regex(
        "(?i)[\\\"']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|session[_-]?token|password|passwd)[\\\"']?\\s*[:=]\\s*[\\\"']?([A-Za-z0-9%+/_=.:~-]{8,4096})",
    )
    private val PRIVATE_KEY_BLOCK = Regex(
        "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\\s+([A-Za-z0-9+/=\\r\\n]{80,16384})\\s+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val PERCENT_ESCAPE = Regex("%[0-9A-Fa-f]{2}")
    private val HEX = Regex("[0-9A-Fa-f]+")
    private val BASE64_TEXT = Regex("[A-Za-z0-9+/]+={0,2}")
    private val TEXT_EXTENSIONS = listOf(
        ".json", ".txt", ".xml", ".yaml", ".yml", ".properties", ".ini", ".cfg", ".conf",
        ".csv", ".toml", ".js", ".html", ".md", ".dart", ".kt", ".java", ".smali",
    )

    private const val CHUNK_BYTES = 256 * 1024
    private const val OVERLAP_BYTES = 64 * 1024
    private const val MAX_FINDINGS = 200
    private const val MAX_RECOVERY_DEPTH = 3
    private const val MAX_EDITABLE_TEXT_BYTES = 4L * 1024L * 1024L
    private const val MAX_TOTAL_SCAN_BYTES = 1024L * 1024L * 1024L
}
