package org.unirevlab.security.analysis

import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ProviderDeclaration
import org.unirevlab.security.model.ProviderPathPermissionSummary
import java.nio.charset.CodingErrorAction

/**
 * Bounded pure-Kotlin Android binary XML parser used when the optional Rust/JNI core is absent.
 * It extracts only security-relevant manifest structure and never instantiates target code.
 */
object KotlinAxmlManifestParser {
    data class Limits(
        val maxBytes: Int = 8 * 1024 * 1024,
        val maxChunks: Int = 100_000,
        val maxStrings: Int = 100_000,
        val maxElements: Int = 100_000,
        val maxAttributesPerElement: Int = 4_096,
        val maxStringBytes: Int = 1024 * 1024,
    )

    data class ParsedAttribute(val name: String, val namespace: String?, val value: String)
    data class ParsedElement(
        val depth: Int,
        val name: String,
        val namespace: String?,
        val attributes: List<ParsedAttribute>,
        val text: String? = null,
    ) {
        fun attr(name: String): String? = attributes.firstOrNull { it.name == name }?.value
        fun androidAttr(name: String): String? = attributes.firstOrNull { it.name == name && (it.namespace == null || it.namespace == ANDROID_NS) }?.value
    }

    fun parse(input: ByteArray, limits: Limits = Limits()): AxmlManifestOverlay? =
        parseElements(input, limits)?.let(::toOverlay)

    /** Pure structural helper used by corpus tests and alternate bounded element sources. */
    fun analyzeElements(elements: List<ParsedElement>): AxmlManifestOverlay = toOverlay(elements)

    fun parseElements(input: ByteArray, limits: Limits = Limits()): List<ParsedElement>? = runCatching {
        require(input.size <= limits.maxBytes) { "AXML input exceeds limit" }
        val root = header(input, 0)
        require(root.kind == RES_XML_TYPE && root.headerSize >= 8 && root.size >= root.headerSize) { "Invalid AXML root" }
        val rootEnd = checkedEnd(0, root.size, input.size)
        var pos = root.headerSize
        var pool: StringPool? = null
        var depth = 0
        var chunks = 0
        val elements = ArrayList<ParsedElement>()
        while (pos < rootEnd) {
            require(++chunks <= limits.maxChunks) { "AXML chunk count exceeds limit" }
            val h = header(input, pos)
            require(h.headerSize >= 8 && h.size >= h.headerSize) { "Invalid AXML chunk" }
            val end = checkedEnd(pos, h.size, rootEnd)
            when (h.kind) {
                RES_STRING_POOL_TYPE -> pool = StringPool.parse(input, pos, h, limits)
                RES_XML_START_ELEMENT_TYPE -> {
                    require(elements.size < limits.maxElements) { "AXML element count exceeds limit" }
                    val p = requireNotNull(pool) { "AXML element before string pool" }
                    elements += parseElement(input, pos, h, depth, p, limits)
                    depth++
                }
                RES_XML_END_ELEMENT_TYPE -> depth = (depth - 1).coerceAtLeast(0)
                RES_XML_CDATA_TYPE -> {
                    val p = requireNotNull(pool) { "AXML CDATA before string pool" }
                    val ext = pos + h.headerSize
                    require(ext + 4 <= end) { "Truncated AXML CDATA" }
                    val index = u32(input, ext)
                    if (index != NO_INDEX) elements += ParsedElement(depth, "#text", null, emptyList(), p[index])
                }
            }
            require(end > pos) { "Non-advancing AXML chunk" }
            pos = end
        }
        elements
    }.getOrNull()


    private fun toOverlay(elements: List<ParsedElement>): AxmlManifestOverlay {
        val app = elements.firstOrNull { it.name == "application" }
        fun appAttr(name: String): String? = app?.attributes?.firstOrNull { it.name == name && (it.namespace == null || it.namespace == ANDROID_NS) }?.value

        var component: String? = null
        var componentDepth = -1
        var filter: Filter? = null
        val links = mutableListOf<DeepLinkDeclaration>()
        fun finishFilter() {
            val f = filter ?: return
            if (f.view && f.browsable && f.schemes.isNotEmpty()) {
                links += DeepLinkDeclaration(
                    componentName = f.component,
                    schemes = f.schemes.toSortedSet().toList(),
                    hosts = f.hosts.toSortedSet().toList(),
                    autoVerify = f.autoVerify,
                    browsable = true,
                    viewAction = true,
                    ports = f.ports.toSortedSet().toList(),
                    paths = f.paths.toSortedSet().toList(),
                    pathPrefixes = f.pathPrefixes.toSortedSet().toList(),
                    pathPatterns = f.pathPatterns.toSortedSet().toList(),
                    mimeTypes = f.mimeTypes.toSortedSet().toList(),
                )
            }
            filter = null
        }
        for (e in elements) {
            if (filter != null && e.depth <= filter!!.depth) finishFilter()
            if (component != null && e.depth <= componentDepth && e.name !in COMPONENTS) {
                component = null
                componentDepth = -1
            }
            if (e.name in COMPONENTS) {
                finishFilter()
                component = e.androidAttr("name") ?: "<unnamed-component>"
                componentDepth = e.depth
                continue
            }
            if (e.name == "intent-filter" && component != null && e.depth > componentDepth) {
                finishFilter()
                filter = Filter(component, e.depth, e.androidAttr("autoVerify").equals("true", true))
                continue
            }
            val f = filter ?: continue
            if (e.depth <= f.depth) continue
            when (e.name) {
                "action" -> if (e.androidAttr("name") == ACTION_VIEW) f.view = true
                "category" -> if (e.androidAttr("name") == CATEGORY_BROWSABLE) f.browsable = true
                "data" -> {
                    e.androidAttr("scheme")?.takeIf { it.isNotBlank() }?.let(f.schemes::add)
                    e.androidAttr("host")?.takeIf { it.isNotBlank() }?.let(f.hosts::add)
                    e.androidAttr("port")?.takeIf { it.isNotBlank() }?.let(f.ports::add)
                    e.androidAttr("path")?.takeIf { it.isNotBlank() }?.let(f.paths::add)
                    e.androidAttr("pathPrefix")?.takeIf { it.isNotBlank() }?.let(f.pathPrefixes::add)
                    e.androidAttr("pathPattern")?.takeIf { it.isNotBlank() }?.let(f.pathPatterns::add)
                    e.androidAttr("mimeType")?.takeIf { it.isNotBlank() }?.let(f.mimeTypes::add)
                }
            }
        }
        finishFilter()

        val providers = mutableListOf<ProviderDeclaration>()
        var provider: ProviderBuilder? = null
        fun finishProvider() {
            val p = provider ?: return
            providers += ProviderDeclaration(
                name = p.name,
                authorities = p.authorities.toSortedSet().toList(),
                exported = p.exported,
                grantUriPermissions = p.grantUriPermissions,
                readPermission = p.readPermission,
                writePermission = p.writePermission,
                pathPermissions = p.pathPermissions.distinct().sortedWith(compareBy({ it.path ?: "" }, { it.pathPrefix ?: "" }, { it.pathPattern ?: "" })),
            )
            provider = null
        }
        for (e in elements) {
            if (provider != null && e.depth <= provider!!.depth) finishProvider()
            if (e.name == "provider") {
                finishProvider()
                provider = ProviderBuilder(
                    depth = e.depth,
                    name = e.androidAttr("name") ?: "<unnamed-provider>",
                    authorities = e.androidAttr("authorities").orEmpty().split(';').map { it.trim() }.filter { it.isNotEmpty() }.toMutableList(),
                    exported = e.androidAttr("exported")?.let { it.equals("true", true) },
                    grantUriPermissions = e.androidAttr("grantUriPermissions").equals("true", true),
                    readPermission = e.androidAttr("readPermission") ?: e.androidAttr("permission"),
                    writePermission = e.androidAttr("writePermission") ?: e.androidAttr("permission"),
                )
                continue
            }
            val currentProvider = provider ?: continue
            if (e.depth <= currentProvider.depth) continue
            if (e.name == "path-permission") {
                currentProvider.pathPermissions += ProviderPathPermissionSummary(
                    path = e.androidAttr("path"),
                    pathPrefix = e.androidAttr("pathPrefix"),
                    pathPattern = e.androidAttr("pathPattern"),
                    readPermission = e.androidAttr("readPermission") ?: e.androidAttr("permission"),
                    writePermission = e.androidAttr("writePermission") ?: e.androidAttr("permission"),
                )
            }
        }
        finishProvider()
        return AxmlManifestOverlay(
            fullBackupContentConfigured = appAttr("fullBackupContent")?.let { it.isNotBlank() && !it.equals("false", true) } ?: false,
            dataExtractionRulesConfigured = appAttr("dataExtractionRules")?.isNotBlank() ?: false,
            networkSecurityConfigConfigured = appAttr("networkSecurityConfig")?.isNotBlank() ?: false,
            fullBackupContentReference = appAttr("fullBackupContent"),
            dataExtractionRulesReference = appAttr("dataExtractionRules"),
            networkSecurityConfigReference = appAttr("networkSecurityConfig"),
            deepLinks = links.distinct().sortedWith(compareBy({ it.componentName }, { it.schemes.joinToString() }, { it.hosts.joinToString() })),
            providers = providers.distinct().sortedBy { it.name },
        )
    }

    private fun parseElement(input: ByteArray, chunkOffset: Int, h: Header, depth: Int, pool: StringPool, limits: Limits): ParsedElement {
        val chunkEnd = checkedEnd(chunkOffset, h.size, input.size)
        val ext = chunkOffset + h.headerSize
        require(ext + 20 <= chunkEnd) { "Truncated AXML start-element extension" }
        val ns = u32(input, ext)
        val name = u32(input, ext + 4)
        val attrStart = u16(input, ext + 8)
        val attrSize = u16(input, ext + 10)
        val attrCount = u16(input, ext + 12)
        require(attrCount <= limits.maxAttributesPerElement) { "AXML attribute count exceeds limit" }
        require(attrCount == 0 || attrSize >= 20) { "Invalid AXML attribute size" }
        val attrsBase = ext + attrStart
        require(attrsBase.toLong() + attrSize.toLong() * attrCount <= chunkEnd.toLong()) { "AXML attributes exceed chunk" }
        val attrs = ArrayList<ParsedAttribute>(attrCount)
        repeat(attrCount) { i ->
            val base = attrsBase + i * attrSize
            require(base + 20 <= chunkEnd) { "Truncated AXML attribute" }
            val attrNs = u32(input, base)
            val attrName = u32(input, base + 4)
            val raw = u32(input, base + 8)
            require(u16(input, base + 12) >= 8) { "Invalid AXML typed value" }
            val type = input[base + 15].toInt() and 0xff
            val data = u32(input, base + 16)
            val value = if (raw != NO_INDEX) pool[raw] else typedValue(type, data, pool)
            attrs += ParsedAttribute(pool[attrName], pool.optional(attrNs), value)
        }
        return ParsedElement(depth, pool[name], pool.optional(ns), attrs)
    }

    private fun typedValue(type: Int, data: Int, pool: StringPool): String = when (type) {
        0x00 -> ""
        0x01 -> "@0x%08x".format(data)
        0x02 -> "?0x%08x".format(data)
        0x03 -> pool[data]
        0x04 -> Float.fromBits(data).toString()
        0x10 -> data.toString()
        0x11 -> "0x%08x".format(data)
        0x12 -> if (data == 0) "false" else "true"
        in 0x1c..0x1f -> "#%08x".format(data)
        else -> "0x%08x".format(data)
    }

    private data class Header(val kind: Int, val headerSize: Int, val size: Int)
    private fun header(b: ByteArray, o: Int): Header {
        require(o >= 0 && o + 8 <= b.size) { "Truncated AXML chunk header" }
        return Header(u16(b, o), u16(b, o + 2), u32(b, o + 4))
    }

    private class StringPool(private val values: List<String>) {
        operator fun get(index: Int): String {
            require(index >= 0 && index < values.size) { "AXML string index outside pool" }
            return values[index]
        }
        fun optional(index: Int): String? = if (index == NO_INDEX) null else get(index)

        companion object {
            fun parse(input: ByteArray, chunk: Int, h: Header, limits: Limits): StringPool {
                require(h.headerSize >= 28) { "Invalid AXML string-pool header" }
                val count = u32(input, chunk + 8)
                val flags = u32(input, chunk + 16)
                val stringsStart = u32(input, chunk + 20)
                require(count in 0..limits.maxStrings) { "AXML string count exceeds limit" }
                val offsets = chunk + h.headerSize
                require(offsets.toLong() + 4L * count <= chunk.toLong() + h.size) { "Truncated AXML string offsets" }
                val utf8 = flags and UTF8_FLAG != 0
                val values = ArrayList<String>(count)
                repeat(count) { i ->
                    val rel = u32(input, offsets + i * 4)
                    val start = chunk + stringsStart + rel
                    require(start >= chunk && start < chunk + h.size) { "AXML string offset outside pool" }
                    values += if (utf8) readUtf8(input, start, chunk + h.size, limits.maxStringBytes) else readUtf16(input, start, chunk + h.size, limits.maxStringBytes)
                }
                return StringPool(values)
            }

            private fun readUtf8(b: ByteArray, start: Int, end: Int, max: Int): String {
                var p = start
                val (_, p1) = len8(b, p, end); p = p1
                val (bytes, p2) = len8(b, p, end); p = p2
                require(bytes <= max && p + bytes <= end) { "AXML UTF-8 string exceeds bounds" }
                val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                return decoder.decode(java.nio.ByteBuffer.wrap(b, p, bytes)).toString()
            }
            private fun len8(b: ByteArray, p0: Int, end: Int): Pair<Int, Int> {
                require(p0 < end); val a = b[p0].toInt() and 0xff
                return if (a and 0x80 == 0) a to (p0 + 1) else { require(p0 + 1 < end); (((a and 0x7f) shl 8) or (b[p0 + 1].toInt() and 0xff)) to (p0 + 2) }
            }
            private fun readUtf16(b: ByteArray, start: Int, end: Int, max: Int): String {
                val (units, p) = len16(b, start, end)
                val bytes = units * 2
                require(bytes <= max && p + bytes <= end) { "AXML UTF-16 string exceeds bounds" }
                return b.copyOfRange(p, p + bytes).toString(Charsets.UTF_16LE)
            }
            private fun len16(b: ByteArray, p0: Int, end: Int): Pair<Int, Int> {
                require(p0 + 2 <= end); val a = u16(b, p0)
                return if (a and 0x8000 == 0) a to (p0 + 2) else { require(p0 + 4 <= end); (((a and 0x7fff) shl 16) or u16(b, p0 + 2)) to (p0 + 4) }
            }
        }
    }

    private data class Filter(
        val component: String, val depth: Int, val autoVerify: Boolean,
        var view: Boolean = false, var browsable: Boolean = false,
        val schemes: MutableList<String> = mutableListOf(), val hosts: MutableList<String> = mutableListOf(),
        val ports: MutableList<String> = mutableListOf(), val paths: MutableList<String> = mutableListOf(),
        val pathPrefixes: MutableList<String> = mutableListOf(), val pathPatterns: MutableList<String> = mutableListOf(),
        val mimeTypes: MutableList<String> = mutableListOf(),
    )

    private data class ProviderBuilder(
        val depth: Int, val name: String, val authorities: MutableList<String>, val exported: Boolean?,
        val grantUriPermissions: Boolean, val readPermission: String?, val writePermission: String?,
        val pathPermissions: MutableList<ProviderPathPermissionSummary> = mutableListOf(),
    )

    private fun checkedEnd(offset: Int, size: Int, limit: Int): Int {
        require(offset >= 0 && size >= 0 && offset.toLong() + size <= limit.toLong()) { "AXML chunk outside bounds" }
        return offset + size
    }
    private fun u16(b: ByteArray, o: Int): Int { require(o >= 0 && o + 2 <= b.size); return (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) }
    private fun u32(b: ByteArray, o: Int): Int { require(o >= 0 && o + 4 <= b.size); return (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24) }

    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val RES_XML_CDATA_TYPE = 0x0104
    private const val UTF8_FLAG = 0x00000100
    private const val NO_INDEX = -1
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    private const val ACTION_VIEW = "android.intent.action.VIEW"
    private const val CATEGORY_BROWSABLE = "android.intent.category.BROWSABLE"
    private val COMPONENTS = setOf("activity", "activity-alias")
}
