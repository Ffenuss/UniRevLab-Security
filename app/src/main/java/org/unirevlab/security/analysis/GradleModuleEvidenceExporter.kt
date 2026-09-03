package org.unirevlab.security.analysis

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditSourceSpec
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipInputStream

data class GradleModuleEvidenceResult(
    val modulesDetected: Int,
    val dynamicFeaturesDetected: Int,
    val configurationSplitsDetected: Int,
    val buildFilesDetected: Int,
    val metadataMarkersDetected: Int,
    val truncated: Boolean,
)

/**
 * Recovers bounded build/module evidence left in an APK, APK Set or XAPK.
 *
 * Gradle source modules are normally compiled away. This scanner therefore distinguishes exact
 * embedded build files from module identities reconstructed from split manifests and AGP/Kotlin
 * metadata. Target code is never loaded or executed.
 */
object GradleModuleEvidenceExporter {
    fun export(
        context: Context,
        source: AuditSourceSpec,
        destination: File,
        cancelled: () -> Boolean = { false },
        onProgress: (message: String) -> Unit = {},
    ): GradleModuleEvidenceResult {
        val inputs = sourceInputs(context, source)
        return exportInputs(
            sourceKind = source.kind.name,
            sourceDisplayName = source.displayName,
            inputs = inputs,
            temporaryDirectory = context.cacheDir,
            destination = destination,
            cancelled = cancelled,
            onProgress = onProgress,
        )
    }

    internal fun exportFilesForTesting(
        archives: List<File>,
        destination: File,
    ): GradleModuleEvidenceResult = exportInputs(
        sourceKind = "TEST",
        sourceDisplayName = "test-artifact",
        inputs = archives.map { file -> ArchiveInput(file.name) { FileInputStream(file) } },
        temporaryDirectory = requireNotNull(destination.parentFile),
        destination = destination,
        cancelled = { false },
        onProgress = {},
    )

    private fun exportInputs(
        sourceKind: String,
        sourceDisplayName: String,
        inputs: List<ArchiveInput>,
        temporaryDirectory: File,
        destination: File,
        cancelled: () -> Boolean,
        onProgress: (String) -> Unit,
    ): GradleModuleEvidenceResult {
        require(destination.parentFile?.isDirectory == true || destination.parentFile?.mkdirs() == true) {
            "Не удалось создать каталог Gradle evidence"
        }
        require(temporaryDirectory.isDirectory || temporaryDirectory.mkdirs()) {
            "Не удалось создать временный каталог Gradle evidence"
        }
        val accumulator = Accumulator()
        inputs.forEach { input ->
            ensureActive(cancelled)
            input.open().use { stream ->
                scanArchive(
                    rawInput = stream,
                    sourceLabel = input.label,
                    depth = 0,
                    temporaryDirectory = temporaryDirectory,
                    accumulator = accumulator,
                    cancelled = cancelled,
                    onProgress = onProgress,
                )
            }
        }

        val result = GradleModuleEvidenceResult(
            modulesDetected = accumulator.modules.size,
            dynamicFeaturesDetected = accumulator.modules.count { it.kind == "DYNAMIC_FEATURE" },
            configurationSplitsDetected = accumulator.modules.count { it.kind == "CONFIG_SPLIT" },
            buildFilesDetected = accumulator.markers.count { it.kind == "BUILD_FILE" },
            metadataMarkersDetected = accumulator.markers.size,
            truncated = accumulator.truncated,
        )
        val json = JSONObject()
            .put("schemaVersion", "1.0")
            .put("sourceKind", sourceKind)
            .put("sourceDisplayName", sourceDisplayName)
            .put("method", "Passive bounded inspection of APK/APKS/XAPK ZIP entries and split manifests")
            .put(
                "interpretation",
                "Gradle source modules are normally absent from release APKs. Exact build files and reconstructed module evidence are reported separately.",
            )
            .put("summary", JSONObject()
                .put("modulesDetected", result.modulesDetected)
                .put("dynamicFeaturesDetected", result.dynamicFeaturesDetected)
                .put("configurationSplitsDetected", result.configurationSplitsDetected)
                .put("buildFilesDetected", result.buildFilesDetected)
                .put("metadataMarkersDetected", result.metadataMarkersDetected)
                .put("truncated", result.truncated))
            .put("modules", JSONArray(accumulator.modules.map(ModuleEvidence::toJson)))
            .put("markers", JSONArray(accumulator.markers.map(MarkerEvidence::toJson)))
            .toString(2)
        destination.writeText(json, Charsets.UTF_8)
        return result
    }

    private fun scanArchive(
        rawInput: InputStream,
        sourceLabel: String,
        depth: Int,
        temporaryDirectory: File,
        accumulator: Accumulator,
        cancelled: () -> Boolean,
        onProgress: (String) -> Unit,
    ) {
        if (depth > MAX_NESTED_DEPTH || accumulator.archivesScanned >= MAX_ARCHIVES) {
            accumulator.truncated = true
            return
        }
        accumulator.archivesScanned++
        var manifestEvidence: ModuleEvidence? = null
        ZipInputStream(BufferedInputStream(rawInput)).use { zip ->
            var entriesSeen = 0
            while (true) {
                ensureActive(cancelled)
                val entry = zip.nextEntry ?: break
                entriesSeen++
                if (entriesSeen > MAX_ENTRIES_PER_ARCHIVE) {
                    accumulator.truncated = true
                    break
                }
                if (entry.isDirectory || unsafePath(entry.name)) {
                    zip.closeEntry()
                    continue
                }
                val normalized = entry.name.lowercase(Locale.ROOT)
                when {
                    normalized == "androidmanifest.xml" -> {
                        val bytes = readBounded(zip, MAX_MANIFEST_BYTES, accumulator, cancelled)
                        manifestEvidence = parseModuleManifest(sourceLabel, bytes)
                        onProgress("Gradle/module: manifest ${sourceLabel.takeLast(MAX_PROGRESS_LABEL)}")
                    }
                    isBuildOrMetadataMarker(normalized) -> {
                        if (accumulator.markers.size >= MAX_MARKERS) {
                            accumulator.truncated = true
                        } else {
                            val bytes = if (shouldReadMarker(normalized)) {
                                readBounded(zip, MAX_MARKER_BYTES, accumulator, cancelled)
                            } else {
                                ByteArray(0)
                            }
                            accumulator.markers += markerEvidence(sourceLabel, entry.name, bytes)
                            onProgress("Gradle metadata: ${entry.name.substringAfterLast('/').take(MAX_PROGRESS_LABEL)}")
                        }
                    }
                    normalized.endsWith(".apk") && depth < MAX_NESTED_DEPTH -> {
                        val temporary = File.createTempFile("unirevlab-module-", ".apk", temporaryDirectory)
                        try {
                            val complete = copyBounded(zip, temporary.outputStream(), MAX_NESTED_APK_BYTES, cancelled)
                            if (complete) {
                                temporary.inputStream().use { nested ->
                                    scanArchive(
                                        rawInput = nested,
                                        sourceLabel = "$sourceLabel!/${entry.name}",
                                        depth = depth + 1,
                                        temporaryDirectory = temporaryDirectory,
                                        accumulator = accumulator,
                                        cancelled = cancelled,
                                        onProgress = onProgress,
                                    )
                                }
                            } else {
                                accumulator.truncated = true
                            }
                        } finally {
                            temporary.delete()
                        }
                    }
                }
                zip.closeEntry()
            }
        }

        val inferred = manifestEvidence ?: inferModuleFromArchiveName(sourceLabel)
        if (inferred != null && accumulator.modules.size < MAX_MODULES) {
            accumulator.modules += inferred
        } else if (inferred != null) {
            accumulator.truncated = true
        }
    }

    private fun parseModuleManifest(sourceLabel: String, bytes: ByteArray): ModuleEvidence {
        val parsed = KotlinAxmlManifestParser.parseElements(bytes)
        if (parsed != null) {
            val manifest = parsed.firstOrNull { it.name == "manifest" }
            val split = manifest?.attrAnyNamespace("split")?.takeIf(String::isNotBlank)
            val configForSplit = manifest?.attrAnyNamespace("configForSplit")?.takeIf(String::isNotBlank)
            val isFeature = manifest?.attrAnyNamespace("isFeatureSplit").equals("true", ignoreCase = true)
            val usesSplits = parsed.filter { it.name == "uses-split" }
                .mapNotNull { it.attrAnyNamespace("name")?.takeIf(String::isNotBlank) }
                .distinct().sorted()
            val hasDistributionModule = parsed.any { it.name == "module" && it.namespace.orEmpty().contains("distribution") }
            val delivery = when {
                parsed.any { it.name == "on-demand" } -> "ON_DEMAND"
                parsed.any { it.name == "fast-follow" } -> "FAST_FOLLOW"
                parsed.any { it.name == "install-time" } -> "INSTALL_TIME"
                else -> null
            }
            return ModuleEvidence(
                source = sourceLabel,
                moduleName = split ?: moduleNameFromSource(sourceLabel),
                kind = classifyModule(split, configForSplit, isFeature || hasDistributionModule, sourceLabel),
                confidence = "CONFIRMED",
                splitName = split,
                configForSplit = configForSplit,
                usesSplits = usesSplits,
                delivery = delivery,
                evidence = "AndroidManifest.xml",
            )
        }

        val text = bytes.toString(Charsets.UTF_8).takeIf { it.trimStart().startsWith("<") }
        if (text != null) {
            val split = XML_SPLIT.find(text)?.groupValues?.get(1)?.takeIf(String::isNotBlank)
            val configForSplit = XML_CONFIG_FOR_SPLIT.find(text)?.groupValues?.get(1)?.takeIf(String::isNotBlank)
            val isFeature = XML_FEATURE.find(text)?.groupValues?.get(1).equals("true", ignoreCase = true)
            val hasDistributionModule = text.contains("<dist:module")
            return ModuleEvidence(
                source = sourceLabel,
                moduleName = split ?: moduleNameFromSource(sourceLabel),
                kind = classifyModule(split, configForSplit, isFeature || hasDistributionModule, sourceLabel),
                confidence = "CONFIRMED",
                splitName = split,
                configForSplit = configForSplit,
                usesSplits = XML_USES_SPLIT.findAll(text).map { it.groupValues[1] }.distinct().sorted().toList(),
                delivery = when {
                    text.contains("<dist:on-demand") -> "ON_DEMAND"
                    text.contains("<dist:fast-follow") -> "FAST_FOLLOW"
                    text.contains("<dist:install-time") -> "INSTALL_TIME"
                    else -> null
                },
                evidence = "AndroidManifest.xml",
            )
        }
        return requireNotNull(inferModuleFromArchiveName(sourceLabel))
    }

    private fun inferModuleFromArchiveName(sourceLabel: String): ModuleEvidence? {
        val archiveName = sourceLabel.substringAfterLast("!/").substringAfterLast('/')
        if (!archiveName.endsWith(".apk", ignoreCase = true) && sourceLabel != "selected-file") return null
        val moduleName = moduleNameFromSource(sourceLabel)
        return ModuleEvidence(
            source = sourceLabel,
            moduleName = moduleName,
            kind = classifyModule(moduleName, null, false, sourceLabel),
            confidence = "INFERRED",
            splitName = moduleName.takeUnless { it == "base" || it == "selected-file" },
            configForSplit = null,
            usesSplits = emptyList(),
            delivery = null,
            evidence = "archive filename; manifest could not be decoded",
        )
    }

    private fun classifyModule(split: String?, configForSplit: String?, isFeature: Boolean, sourceLabel: String): String {
        val name = (split ?: sourceLabel).lowercase(Locale.ROOT)
        return when {
            !configForSplit.isNullOrBlank() || name.contains("split_config") || name.contains("config.") || name.contains("config-") -> "CONFIG_SPLIT"
            isFeature -> "DYNAMIC_FEATURE"
            split.isNullOrBlank() && (name.endsWith("base.apk") || name.contains("base-master") || sourceLabel == "selected-file") -> "BASE"
            !split.isNullOrBlank() -> "SPLIT"
            else -> "UNKNOWN"
        }
    }

    private fun markerEvidence(source: String, path: String, bytes: ByteArray): MarkerEvidence {
        val normalized = path.lowercase(Locale.ROOT)
        val kind = when {
            isGradleBuildFile(normalized) -> "BUILD_FILE"
            normalized.endsWith(".kotlin_module") -> "KOTLIN_MODULE"
            normalized.contains("aar-metadata.properties") -> "AAR_METADATA"
            normalized.contains("app-metadata.properties") -> "AGP_APP_METADATA"
            normalized.contains("bundle-metadata/") -> "BUNDLE_METADATA"
            normalized.endsWith(".version") || normalized.contains("_version") -> "DEPENDENCY_VERSION"
            normalized.contains("baseline.prof") -> "BASELINE_PROFILE"
            normalized.contains("splits") -> "SPLIT_METADATA"
            else -> "BUILD_METADATA"
        }
        val properties = if (bytes.isNotEmpty() && (normalized.endsWith(".properties") || normalized.endsWith(".version"))) {
            parseSafeProperties(bytes)
        } else emptyMap()
        return MarkerEvidence(
            source = source,
            path = path,
            kind = kind,
            sizeRead = bytes.size,
            sha256 = bytes.takeIf(ByteArray::isNotEmpty)?.let(::sha256),
            properties = properties,
        )
    }

    private fun parseSafeProperties(bytes: ByteArray): Map<String, String> = buildMap {
        bytes.toString(Charsets.UTF_8).lineSequence().take(MAX_PROPERTY_LINES).forEach { raw ->
            val line = raw.trim()
            if (line.isBlank() || line.startsWith('#') || line.startsWith('!')) return@forEach
            val separator = listOf(line.indexOf('='), line.indexOf(':')).filter { it > 0 }.minOrNull() ?: return@forEach
            val key = line.substring(0, separator).trim().take(MAX_PROPERTY_LENGTH)
            if (key.lowercase(Locale.ROOT) !in SAFE_PROPERTY_KEYS) return@forEach
            put(key, line.substring(separator + 1).trim().take(MAX_PROPERTY_LENGTH))
        }
    }

    private fun isBuildOrMetadataMarker(path: String): Boolean =
        isGradleBuildFile(path) ||
            path.endsWith(".kotlin_module") ||
            path.endsWith(".version") ||
            path.substringAfterLast('/').contains("_version") ||
            path.contains("meta-inf/com/android/build/gradle/") ||
            path.contains("aar-metadata.properties") ||
            path.contains("bundle-metadata/") ||
            path.endsWith("assets/dexopt/baseline.prof") ||
            path.endsWith("assets/dexopt/baseline.profm") ||
            path.matches(Regex("(?:^|/)res/xml/splits[0-9]*\\.xml$"))

    private fun isGradleBuildFile(path: String): Boolean = path.substringAfterLast('/') in GRADLE_BUILD_FILES

    private fun shouldReadMarker(path: String): Boolean =
        path.endsWith(".properties") || path.endsWith(".version") || path.substringAfterLast('/').contains("_version")

    private fun sourceInputs(context: Context, source: AuditSourceSpec): List<ArchiveInput> = when (source.kind) {
        AuditSourceKind.FILE_URI -> {
            val uri = Uri.parse(requireNotNull(source.uri))
            listOf(ArchiveInput("selected-file") {
                requireNotNull(context.contentResolver.openInputStream(uri)) { "Не удалось открыть выбранный архив" }
            })
        }
        AuditSourceKind.INSTALLED_APP -> {
            (listOf(requireNotNull(source.baseApkPath)) + source.splitApkPaths).map { path ->
                val file = File(path)
                ArchiveInput(file.name) {
                    require(file.isFile && file.canRead()) { "APK-модуль недоступен: ${file.name}" }
                    FileInputStream(file)
                }
            }
        }
    }

    private fun readBounded(
        input: InputStream,
        limit: Int,
        accumulator: Accumulator,
        cancelled: () -> Boolean,
    ): ByteArray {
        val output = java.io.ByteArrayOutputStream(minOf(limit, DEFAULT_BUFFER_SIZE))
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var copied = 0
        while (true) {
            ensureActive(cancelled)
            val read = input.read(buffer)
            if (read <= 0) break
            val accepted = minOf(read, limit - copied)
            if (accepted > 0) output.write(buffer, 0, accepted)
            copied += accepted
            if (copied >= limit) {
                accumulator.truncated = true
                drainEntry(input, cancelled)
                break
            }
        }
        return output.toByteArray()
    }

    private fun copyBounded(input: InputStream, output: OutputStream, limit: Long, cancelled: () -> Boolean): Boolean {
        output.buffered().use { destination ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var copied = 0L
            while (true) {
                ensureActive(cancelled)
                val read = input.read(buffer)
                if (read <= 0) return true
                if (copied + read > limit) {
                    drainEntry(input, cancelled)
                    return false
                }
                destination.write(buffer, 0, read)
                copied += read
            }
        }
    }

    private fun drainEntry(input: InputStream, cancelled: () -> Boolean) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            ensureActive(cancelled)
            if (input.read(buffer) <= 0) return
        }
    }

    private fun unsafePath(path: String): Boolean =
        path.isBlank() || path.startsWith('/') || path.startsWith('\\') || path.contains('\\') ||
            path.split('/').any { it == "." || it == ".." }

    private fun moduleNameFromSource(source: String): String = source.substringAfterLast("!/")
        .substringAfterLast('/')
        .removeSuffix(".apk")
        .removeSuffix("-master")
        .ifBlank { "base" }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun KotlinAxmlManifestParser.ParsedElement.attrAnyNamespace(name: String): String? =
        attributes.firstOrNull { it.name == name }?.value

    private fun ensureActive(cancelled: () -> Boolean) {
        if (cancelled()) throw java.util.concurrent.CancellationException("Поиск Gradle-модулей отменён")
    }

    private data class ArchiveInput(val label: String, val open: () -> InputStream)
    private data class Accumulator(
        val modules: MutableList<ModuleEvidence> = mutableListOf(),
        val markers: MutableList<MarkerEvidence> = mutableListOf(),
        var archivesScanned: Int = 0,
        var truncated: Boolean = false,
    )

    private data class ModuleEvidence(
        val source: String,
        val moduleName: String,
        val kind: String,
        val confidence: String,
        val splitName: String?,
        val configForSplit: String?,
        val usesSplits: List<String>,
        val delivery: String?,
        val evidence: String,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("source", source)
            .put("moduleName", moduleName)
            .put("kind", kind)
            .put("confidence", confidence)
            .put("splitName", splitName ?: JSONObject.NULL)
            .put("configForSplit", configForSplit ?: JSONObject.NULL)
            .put("usesSplits", JSONArray(usesSplits))
            .put("delivery", delivery ?: JSONObject.NULL)
            .put("evidence", evidence)
    }

    private data class MarkerEvidence(
        val source: String,
        val path: String,
        val kind: String,
        val sizeRead: Int,
        val sha256: String?,
        val properties: Map<String, String>,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("source", source)
            .put("path", path)
            .put("kind", kind)
            .put("sizeRead", sizeRead)
            .put("sha256", sha256 ?: JSONObject.NULL)
            .put("properties", JSONObject(properties))
    }

    private val GRADLE_BUILD_FILES = setOf(
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.properties",
        "gradle-wrapper.properties",
        "libs.versions.toml",
    )
    private val SAFE_PROPERTY_KEYS = setOf(
        "gradleversion",
        "androidgradlepluginversion",
        "metadataversion",
        "mincompilesdk",
        "mincompilesdkextension",
        "minagpversion",
        "version",
    )
    private val XML_SPLIT = Regex("""(?:^|\s)split\s*=\s*["']([^"']+)["']""")
    private val XML_CONFIG_FOR_SPLIT = Regex("""(?:android:)?configForSplit\s*=\s*["']([^"']+)["']""")
    private val XML_FEATURE = Regex("""(?:android:)?isFeatureSplit\s*=\s*["']([^"']+)["']""")
    private val XML_USES_SPLIT = Regex("""<uses-split[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']""")

    private const val MAX_NESTED_DEPTH = 2
    private const val MAX_ARCHIVES = 128
    private const val MAX_ENTRIES_PER_ARCHIVE = 200_000
    private const val MAX_MODULES = 256
    private const val MAX_MARKERS = 1_000
    private const val MAX_MANIFEST_BYTES = 8 * 1024 * 1024
    private const val MAX_MARKER_BYTES = 1024 * 1024
    private const val MAX_NESTED_APK_BYTES = 512L * 1024L * 1024L
    private const val MAX_PROPERTY_LINES = 200
    private const val MAX_PROPERTY_LENGTH = 256
    private const val MAX_PROGRESS_LABEL = 80
}
