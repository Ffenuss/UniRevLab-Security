package org.unirevlab.security.analysis

import java.io.ByteArrayOutputStream
import java.util.Locale
import java.util.zip.ZipFile

/**
 * Bounded flag discovery across every APK entry name and representative content.
 *
 * This is a defensive locator. It reports candidate trust/state/configuration markers but never
 * mutates them and never generates purchase/license/ad-bypass patches.
 */
object FlagSweepEngine {
    data class FlagDefinition(
        val category: String,
        val terms: List<String>,
    )

    data class FlagMatch(
        val category: String,
        val term: String,
        val entryName: String,
        val source: String,
        val offset: Int?,
        val preview: String,
    )

    data class SweepReport(
        val matches: List<FlagMatch>,
        val entriesVisited: Int,
        val entriesContentScanned: Int,
        val contentBytesScanned: Long,
        val contentEntriesTruncated: Int,
        val budgetTruncated: Boolean,
        val customTerms: List<String>,
    ) {
        val categoryCounts: Map<String, Int>
            get() = matches.groupingBy { it.category }.eachCount()
    }

    fun scan(workspace: PatchLabEngine.Workspace, customTerms: List<String> = emptyList()): SweepReport {
        val normalizedCustom = customTerms.asSequence()
            .map { it.trim().lowercase(Locale.ROOT) }
            .filter { it.length in 2..64 }
            .distinct()
            .take(MAX_CUSTOM_TERMS)
            .toList()
        val definitions = DEFAULT_DEFINITIONS + if (normalizedCustom.isEmpty()) {
            emptyList()
        } else {
            listOf(FlagDefinition("CUSTOM", normalizedCustom))
        }
        val matches = mutableListOf<FlagMatch>()
        var entriesVisited = 0
        var entriesContentScanned = 0
        var contentBytesScanned = 0L
        var contentEntriesTruncated = 0
        var budgetTruncated = false

        ZipFile(workspace.originalApk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                entriesVisited++
                scanText(
                    text = entry.name.lowercase(Locale.ROOT),
                    original = entry.name,
                    entryName = entry.name,
                    source = "ENTRY_NAME",
                    definitions = definitions,
                    matches = matches,
                    offsetBase = null,
                )
                if (matches.size >= MAX_MATCHES) {
                    budgetTruncated = true
                    continue
                }
                if (contentBytesScanned >= MAX_TOTAL_CONTENT_BYTES) {
                    budgetTruncated = true
                    continue
                }
                val remainingBudget = (MAX_TOTAL_CONTENT_BYTES - contentBytesScanned).coerceAtMost(MAX_ENTRY_CONTENT_BYTES.toLong()).toInt()
                if (remainingBudget <= 0) {
                    budgetTruncated = true
                    continue
                }
                val bytes = zip.getInputStream(entry).use { input -> readPrefix(input, remainingBudget) }
                entriesContentScanned++
                contentBytesScanned += bytes.data.size
                if (bytes.truncated) contentEntriesTruncated++
                if (bytes.data.isEmpty()) continue

                val latin = bytes.data.toString(Charsets.ISO_8859_1)
                scanText(
                    text = latin.lowercase(Locale.ROOT),
                    original = latin,
                    entryName = entry.name,
                    source = "CONTENT_ASCII",
                    definitions = definitions,
                    matches = matches,
                    offsetBase = 0,
                )
                // Android binary resources and some assets contain UTF-16 strings. Probe both byte
                // alignments in LE/BE form without trying to parse arbitrary binary formats.
                if (bytes.data.size >= 4 && matches.size < MAX_MATCHES) {
                    scanUtf16Projection(bytes.data, entry.name, definitions, matches)
                }
            }
        }
        val distinct = matches.distinctBy { "${it.category}|${it.term}|${it.entryName}|${it.source}|${it.offset}|${it.preview}" }
            .take(MAX_MATCHES)
        return SweepReport(
            matches = distinct,
            entriesVisited = entriesVisited,
            entriesContentScanned = entriesContentScanned,
            contentBytesScanned = contentBytesScanned,
            contentEntriesTruncated = contentEntriesTruncated,
            budgetTruncated = budgetTruncated || matches.size > MAX_MATCHES,
            customTerms = normalizedCustom,
        )
    }

    private data class Prefix(val data: ByteArray, val truncated: Boolean)

    private fun readPrefix(input: java.io.InputStream, maxBytes: Int): Prefix {
        val out = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
        val buffer = ByteArray(32 * 1024)
        var total = 0
        var truncated = false
        while (total < maxBytes) {
            val want = minOf(buffer.size, maxBytes - total)
            val read = input.read(buffer, 0, want)
            if (read < 0) break
            if (read == 0) continue
            out.write(buffer, 0, read)
            total += read
        }
        if (total >= maxBytes && input.read() >= 0) truncated = true
        return Prefix(out.toByteArray(), truncated)
    }

    private fun scanText(
        text: String,
        original: String,
        entryName: String,
        source: String,
        definitions: List<FlagDefinition>,
        matches: MutableList<FlagMatch>,
        offsetBase: Int?,
    ) {
        for (definition in definitions) {
            for (rawTerm in definition.terms) {
                if (matches.size >= MAX_MATCHES) return
                val term = rawTerm.lowercase(Locale.ROOT)
                var from = 0
                var perTerm = 0
                while (from < text.length && perTerm < MAX_MATCHES_PER_TERM_ENTRY) {
                    val index = text.indexOf(term, from)
                    if (index < 0) break
                    from = index + maxOf(1, term.length)
                    if (requiresTokenBoundary(term) && !hasTokenBoundary(text, index, term.length)) continue
                    matches += FlagMatch(
                        category = definition.category,
                        term = rawTerm,
                        entryName = entryName,
                        source = source,
                        offset = offsetBase?.let { it + index },
                        preview = preview(original, index, term.length),
                    )
                    perTerm++
                    if (matches.size >= MAX_MATCHES) return
                }
            }
        }
    }

    private fun scanUtf16Projection(
        bytes: ByteArray,
        entryName: String,
        definitions: List<FlagDefinition>,
        matches: MutableList<FlagMatch>,
    ) {
        for (littleEndian in listOf(true, false)) {
            for (alignment in 0..1) {
                if (matches.size >= MAX_MATCHES) return
                val builder = StringBuilder(bytes.size / 2)
                var i = alignment
                while (i + 1 < bytes.size) {
                    val low = if (littleEndian) bytes[i].toInt() and 0xff else bytes[i + 1].toInt() and 0xff
                    val high = if (littleEndian) bytes[i + 1].toInt() and 0xff else bytes[i].toInt() and 0xff
                    builder.append(if (high == 0 && low in 0x20..0x7e) low.toChar() else ' ')
                    i += 2
                }
                val projected = builder.toString()
                scanText(
                    text = projected.lowercase(Locale.ROOT),
                    original = projected,
                    entryName = entryName,
                    source = if (littleEndian) "CONTENT_UTF16LE" else "CONTENT_UTF16BE",
                    definitions = definitions,
                    matches = matches,
                    offsetBase = null,
                )
            }
        }
    }

    private fun requiresTokenBoundary(term: String): Boolean = term.length <= 3 || term in BOUNDARY_TERMS

    private fun hasTokenBoundary(text: String, index: Int, length: Int): Boolean {
        val leftOk = index == 0 || !text[index - 1].isLetterOrDigit()
        val end = index + length
        val rightOk = end >= text.length || !text[end].isLetterOrDigit()
        return leftOk && rightOk
    }

    private fun preview(value: String, index: Int, length: Int): String {
        val start = (index - 44).coerceAtLeast(0)
        val end = (index + length + 68).coerceAtMost(value.length)
        return value.substring(start, end)
            .map { if (it.code in 0x20..0x7e) it else ' ' }
            .joinToString("")
            .replace(Regex("\\s+"), " ")
            .trim()
            .take(180)
    }

    val DEFAULT_DEFINITIONS: List<FlagDefinition> = listOf(
        FlagDefinition("ENTITLEMENT", listOf(
            "premium", "isPremium", "premium_enabled", "pro", "isPro", "vip", "paid", "subscription",
            "subscribed", "entitlement", "unlock", "unlocked", "owned", "hasAccess", "accessLevel", "trial",
        )),
        FlagDefinition("BILLING", listOf(
            "billing", "BillingClient", "purchase", "purchases", "inapp", "in_app", "productId", "product_id",
            "sku", "acknowledgePurchase", "queryPurchases", "consumePurchase", "play_billing",
        )),
        FlagDefinition("ADS", listOf(
            "admob", "ad_unit", "adunit", "banner", "interstitial", "rewarded", "advertisement", "remove_ads",
            "removeAds", "no_ads", "noAds", "ad_free", "adfree", "showAds", "adsEnabled",
        )),
        FlagDefinition("LOCAL_STATE", listOf(
            "hp", "health", "lives", "life", "energy", "stamina", "damage", "armor", "speed", "cooldown",
            "score", "rank", "balance", "coins", "coin", "gems", "gem", "currency", "wallet", "credits",
        )),
        FlagDefinition("FEATURE_CONFIG", listOf(
            "feature_flag", "featureFlag", "featureflags", "toggle", "experiment", "variant", "remote_config",
            "remoteConfig", "config", "settings", "enabled", "disabled",
        )),
        FlagDefinition("API_TRUST", listOf(
            "api_key", "apiKey", "client_secret", "clientSecret", "access_token", "accessToken", "auth_token",
            "bearer", "base_url", "baseUrl", "endpoint", "serverUrl",
        )),
        FlagDefinition("INTEGRITY", listOf(
            "integrity", "tamper", "signature", "checksum", "attestation", "playIntegrity", "rootCheck",
            "emulatorCheck", "installerPackage", "certificate",
        )),
    )

    private val BOUNDARY_TERMS = setOf("pro", "vip", "paid", "trial", "sku", "hp", "life", "coin", "gem")
    private const val MAX_CUSTOM_TERMS = 24
    private const val MAX_MATCHES = 800
    private const val MAX_MATCHES_PER_TERM_ENTRY = 3
    private const val MAX_ENTRY_CONTENT_BYTES = 2 * 1024 * 1024
    private const val MAX_TOTAL_CONTENT_BYTES = 96L * 1024L * 1024L
}
