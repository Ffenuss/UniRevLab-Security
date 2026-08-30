package org.unirevlab.security.analysis

import org.unirevlab.security.model.NetworkDomainConfigSummary
import org.unirevlab.security.model.NetworkSecurityConfigSummary
import org.unirevlab.security.model.NetworkTrustAnchorSummary
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile

/** Bounded parser for compiled Android Network Security Config XML resources. */
object NetworkSecurityConfigScanner {
    data class Limits(
        val maxXmlEntries: Int = 512,
        val maxEntryBytes: Int = 2 * 1024 * 1024,
        val maxTotalBytes: Int = 16 * 1024 * 1024,
        val maxConfigs: Int = 32,
        val maxDomainConfigs: Int = 256,
        val maxTrustAnchors: Int = 256,
    )

    fun scan(
        apk: File,
        manifestReference: String?,
        resolvedManifestEntry: String? = null,
        limits: Limits = Limits(),
    ): NetworkSecurityConfigSummary? {
        var parseErrors = 0
        var truncated = false
        var totalBytes = 0
        val configs = mutableListOf<ParsedConfig>()
        runCatching {
            ZipFile(apk).use { zip ->
                val candidates = if (!resolvedManifestEntry.isNullOrBlank()) {
                    listOfNotNull(zip.getEntry(resolvedManifestEntry)).filter { !it.isDirectory }
                } else {
                    zip.entries().asSequence()
                        .filter { !it.isDirectory }
                        .filter { it.name.lowercase(Locale.ROOT).startsWith("res/xml/") && it.name.lowercase(Locale.ROOT).endsWith(".xml") }
                        .take(limits.maxXmlEntries + 1)
                        .toList()
                }
                if (candidates.size > limits.maxXmlEntries) truncated = true
                for (entry in candidates.take(limits.maxXmlEntries)) {
                    if (configs.size >= limits.maxConfigs) { truncated = true; break }
                    if (entry.size < 0 || entry.size > limits.maxEntryBytes) continue
                    if (totalBytes + entry.size > limits.maxTotalBytes) { truncated = true; break }
                    val bytesResult = runCatching {
                        zip.getInputStream(entry).use { input ->
                            val out = ByteArrayOutputStream()
                            val buffer = ByteArray(16 * 1024)
                            var nTotal = 0
                            while (true) {
                                val n = input.read(buffer)
                                if (n <= 0) break
                                nTotal += n
                                require(nTotal <= limits.maxEntryBytes) { "Network config XML exceeds bound" }
                                out.write(buffer, 0, n)
                            }
                            out.toByteArray()
                        }
                    }
                    if (bytesResult.isFailure) { parseErrors++; continue }
                    val bytes = bytesResult.getOrThrow()
                    totalBytes += bytes.size
                    val elements = KotlinAxmlManifestParser.parseElements(bytes)
                    if (elements == null) { parseErrors++; continue }
                    val root = elements.firstOrNull { it.name != "#text" }
                    if (root?.name != "network-security-config") continue
                    configs += parseConfig(entry.name, elements, limits)
                }
            }
        }.onFailure { parseErrors++ }

        if (configs.isEmpty() && manifestReference.isNullOrBlank()) return null
        val domainConfigs = configs.flatMap { it.domainConfigs }
        val trustAnchors = configs.flatMap { it.trustAnchors }
        if (domainConfigs.size > limits.maxDomainConfigs || trustAnchors.size > limits.maxTrustAnchors) truncated = true
        return NetworkSecurityConfigSummary(
            manifestReference = manifestReference,
            resolvedManifestEntry = resolvedManifestEntry,
            configEntries = configs.map { it.entryName }.distinct().sorted(),
            baseCleartextTrafficPermitted = configs.mapNotNull { it.baseCleartext }.firstOrNull(),
            domainConfigs = domainConfigs.take(limits.maxDomainConfigs),
            trustAnchors = trustAnchors.distinct().take(limits.maxTrustAnchors),
            debugOverridesPresent = configs.any { it.debugOverrides },
            pinSetPresent = configs.any { it.pinSet },
            parseErrors = parseErrors,
            truncated = truncated || configs.any { it.truncated },
        )
    }

    private data class MutableDomain(
        val depth: Int,
        val cleartext: Boolean?,
        val domains: MutableList<String> = mutableListOf(),
        var includeSubdomains: Boolean = false,
    )
    private data class ParsedConfig(
        val entryName: String,
        val baseCleartext: Boolean?,
        val domainConfigs: List<NetworkDomainConfigSummary>,
        val trustAnchors: List<NetworkTrustAnchorSummary>,
        val debugOverrides: Boolean,
        val pinSet: Boolean,
        val truncated: Boolean,
    )

    private fun parseConfig(entryName: String, elements: List<KotlinAxmlManifestParser.ParsedElement>, limits: Limits): ParsedConfig {
        var baseCleartext: Boolean? = null
        var debugOverrides = false
        var pinSet = false
        var truncated = false
        val domains = mutableListOf<NetworkDomainConfigSummary>()
        val trust = mutableListOf<NetworkTrustAnchorSummary>()
        val domainStack = mutableListOf<MutableDomain>()
        val elementStack = mutableListOf<KotlinAxmlManifestParser.ParsedElement>()
        var pendingDomainDepth: Int? = null
        var pendingIncludeSubdomains = false

        fun flushDomains(depth: Int) {
            while (domainStack.isNotEmpty() && depth <= domainStack.last().depth) {
                val d = domainStack.removeAt(domainStack.lastIndex)
                domains += NetworkDomainConfigSummary(d.cleartext, d.domains.distinct().sorted(), d.includeSubdomains)
                if (domains.size > limits.maxDomainConfigs) truncated = true
            }
        }

        for (e in elements) {
            if (e.name == "#text") {
                val pd = pendingDomainDepth
                if (pd != null && e.depth > pd) {
                    val text = e.text?.trim().orEmpty()
                    if (text.isNotBlank() && domainStack.isNotEmpty()) {
                        domainStack.last().domains += text
                        domainStack.last().includeSubdomains = domainStack.last().includeSubdomains || pendingIncludeSubdomains
                    }
                    pendingDomainDepth = null
                }
                continue
            }
            while (elementStack.isNotEmpty() && e.depth <= elementStack.last().depth) elementStack.removeAt(elementStack.lastIndex)
            flushDomains(e.depth)
            val inDebug = elementStack.any { it.name == "debug-overrides" } || e.name == "debug-overrides"
            when (e.name) {
                "base-config" -> baseCleartext = e.attr("cleartextTrafficPermitted")?.toBooleanStrictOrNull()
                "domain-config" -> domainStack += MutableDomain(e.depth, e.attr("cleartextTrafficPermitted")?.toBooleanStrictOrNull())
                "domain" -> {
                    pendingDomainDepth = e.depth
                    pendingIncludeSubdomains = e.attr("includeSubdomains")?.equals("true", true) == true
                }
                "certificates" -> {
                    val src = e.attr("src")
                    if (!src.isNullOrBlank()) {
                        trust += NetworkTrustAnchorSummary(
                            source = src,
                            inDebugOverrides = inDebug,
                            overridePins = e.attr("overridePins")?.toBooleanStrictOrNull(),
                        )
                        if (trust.size > limits.maxTrustAnchors) truncated = true
                    }
                }
                "debug-overrides" -> debugOverrides = true
                "pin-set" -> pinSet = true
            }
            elementStack += e
        }
        flushDomains(-1)
        return ParsedConfig(
            entryName = entryName,
            baseCleartext = baseCleartext,
            domainConfigs = domains.take(limits.maxDomainConfigs),
            trustAnchors = trust.take(limits.maxTrustAnchors),
            debugOverrides = debugOverrides,
            pinSet = pinSet,
            truncated = truncated,
        )
    }
}
