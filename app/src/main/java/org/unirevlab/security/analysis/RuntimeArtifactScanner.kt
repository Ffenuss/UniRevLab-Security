package org.unirevlab.security.analysis

import org.unirevlab.security.model.FlutterRuntimeSummary
import org.unirevlab.security.model.HermesBytecodeSummary
import org.unirevlab.security.model.HermesFunctionSummary
import org.unirevlab.security.model.HermesRuntimeSummary
import org.unirevlab.security.model.ManagedAssemblySummary
import org.unirevlab.security.model.ManagedMetadataStreamSummary
import org.unirevlab.security.model.ManagedMetadataTableSummary
import org.unirevlab.security.model.RuntimeArtifactFingerprint
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.RuntimeArtifactSummary
import org.unirevlab.security.model.RuntimeFileReference
import org.unirevlab.security.model.UnityMonoRuntimeSummary
import org.unirevlab.security.model.UnrealContainerSummary
import org.unirevlab.security.model.UnrealRuntimeSummary
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipFile

/**
 * Passive runtime-specific inventory. Target code and native libraries are never loaded or executed.
 * All ZIP reads are bounded and the result intentionally describes static packaging evidence only.
 */
object RuntimeArtifactScanner {
    data class Limits(
        val maxEntries: Int = 100_000,
        val maxReportedAssets: Int = 160,
        val maxReportedBundles: Int = 64,
        val maxHermesCandidates: Int = 64,
        val maxHermesFunctions: Int = 512,
        val maxAssemblies: Int = 128,
        val maxAssemblyBytes: Long = 64L * 1024L * 1024L,
        val maxTotalAssemblyBytes: Long = 256L * 1024L * 1024L,
        val maxAssemblyNames: Int = 64,
        val maxUnrealContainers: Int = 256,
        val maxObbEntries: Int = 32,
    )

    fun scanApk(
        apk: File,
        native: NativeSummary?,
        limits: Limits = Limits(),
        archiveIndex: ApkArchiveIndex? = null,
    ): RuntimeArtifactSummary? {
        return try {
            ZipFile(apk).use { zip ->
                val reusableIndex = archiveIndex?.takeIf {
                    limits.maxEntries == 100_000 && !it.duplicateRuntimeArtifactNames
                }
                val entries: List<ZipEntry>
                val archiveTruncated: Boolean
                if (reusableIndex != null) {
                    entries = reusableIndex.runtimeArtifactEntries.mapNotNull { zip.getEntry(it.name) }
                    archiveTruncated = reusableIndex.runtimeArtifactTruncated
                } else {
                    val enumerated = mutableListOf<ZipEntry>()
                    val iterator = zip.entries()
                    var truncated = false
                    while (iterator.hasMoreElements()) {
                        if (enumerated.size >= limits.maxEntries) {
                            truncated = true
                            break
                        }
                        val entry = iterator.nextElement()
                        if (!entry.isDirectory) enumerated += entry
                    }
                    entries = enumerated
                    archiveTruncated = truncated
                }

                val groups = classifyEntries(entries)
                val flutter = scanFlutter(zip, groups, native, archiveTruncated, limits)
                val hermes = scanHermes(zip, groups, native, archiveTruncated, limits)
                val unityMono = scanUnityMono(zip, groups, native, archiveTruncated, limits)
                val unreal = scanUnreal(zip, groups, native, archiveTruncated, limits)

                if (flutter == null && hermes == null && unityMono == null && unreal == null) null
                else RuntimeArtifactSummary(flutter, hermes, unityMono, unreal)
            }
        } catch (_: ZipException) {
            null
        } catch (_: java.io.IOException) {
            null
        }
    }

    private data class EntryGroups(
        val flutterAssets: List<ZipEntry>,
        val flutterSnapshots: List<ZipEntry>,
        val flutterKernels: List<ZipEntry>,
        val hermesCandidates: List<ZipEntry>,
        val managedAssemblies: List<ZipEntry>,
        val unrealContainers: List<ZipEntry>,
        val obbEntries: List<ZipEntry>,
        val commandLineEntries: List<ZipEntry>,
    )

    private fun classifyEntries(entries: List<ZipEntry>): EntryGroups {
        val flutterAssets = ArrayList<ZipEntry>()
        val snapshots = ArrayList<ZipEntry>()
        val kernels = ArrayList<ZipEntry>()
        val hermes = ArrayList<ZipEntry>()
        val assemblies = ArrayList<ZipEntry>()
        val unreal = ArrayList<ZipEntry>()
        val obb = ArrayList<ZipEntry>()
        val commandLine = ArrayList<ZipEntry>()
        for (entry in entries) {
            val n = entry.name.lowercase()
            val base = n.substringAfterLast('/')
            if (n.contains("flutter_assets/")) flutterAssets += entry
            if (base == "vm_snapshot_data" || base == "vm_snapshot_instr" || base == "isolate_snapshot_data" || base == "isolate_snapshot_instr") snapshots += entry
            if (base == "kernel_blob.bin" || base.endsWith(".dill")) kernels += entry
            if (n.endsWith(".hbc") || n.endsWith(".hermes") || n.endsWith(".bundle") || n.endsWith("index.android.bundle") || n.endsWith("index.android.bundle.hbc")) hermes += entry
            if (n.endsWith(".dll") && (n.contains("/managed/") || n.startsWith("assemblies/") || n.contains("/assemblies/"))) assemblies += entry
            if (n.endsWith(".pak") || n.endsWith(".utoc") || n.endsWith(".ucas")) unreal += entry
            if (n.endsWith(".obb")) obb += entry
            if (n.endsWith("uecommandline.txt") || n.endsWith("commandline.txt") || n.endsWith("build.version")) commandLine += entry
        }
        return EntryGroups(flutterAssets, snapshots, kernels, hermes, assemblies, unreal, obb, commandLine)
    }

    private fun scanFlutter(
        zip: ZipFile,
        groups: EntryGroups,
        native: NativeSummary?,
        archiveTruncated: Boolean,
        limits: Limits,
    ): FlutterRuntimeSummary? {
        val libs = native?.libraries.orEmpty()
        val flutterLibraries = libs.filter { it.entryName.substringAfterLast('/').equals("libflutter.so", true) }
        val appLibraries = libs.filter { it.entryName.substringAfterLast('/').equals("libapp.so", true) }
        val assets = groups.flutterAssets
        val manifestEntries = assets.asSequence().map { it.name }.filter {
            val n = it.substringAfterLast('/').lowercase()
            n == "assetmanifest.json" || n == "assetmanifest.bin" || n == "fontmanifest.json" || n == "notices.z"
        }.sorted().toList()
        val snapshots = groups.flutterSnapshots.map { it.name }.sorted()
        val kernels = groups.flutterKernels.map { it.name }.sorted()
        val detected = flutterLibraries.isNotEmpty() || appLibraries.isNotEmpty() || assets.isNotEmpty()
        if (!detected) return null
        val signals = listOf(flutterLibraries.isNotEmpty(), appLibraries.isNotEmpty(), assets.isNotEmpty()).count { it }
        val confidence = if (signals >= 2) "HIGH" else "MEDIUM"
        val reported = assets.sortedBy { it.name }.take(limits.maxReportedAssets).map {
            RuntimeFileReference(it.name, safeSize(it))
        }
        val fingerprintEntries = (groups.flutterSnapshots + groups.flutterKernels).sortedBy { it.name }.take(32)
        val fingerprints = fingerprintEntries.mapNotNull { entry ->
            runCatching {
                val probe = zip.getInputStream(entry).use { readBounded(it, minOf(safeSize(entry).coerceAtLeast(0), 16L * 1024L * 1024L)) }
                RuntimeArtifactFingerprint(
                    entryName = entry.name,
                    kind = if (entry.name.substringAfterLast('/').lowercase().contains("snapshot")) "DART_SNAPSHOT" else "DART_KERNEL",
                    sizeBytes = safeSize(entry),
                    sha256 = MessageDigest.getInstance("SHA-256").digest(probe).toHex(),
                )
            }.getOrNull()
        }
        return FlutterRuntimeSummary(
            detected = true,
            confidence = confidence,
            flutterLibraries = flutterLibraries.map { it.entryName }.sorted(),
            appLibraries = appLibraries.map { it.entryName }.sorted(),
            engineBuildIds = flutterLibraries.mapNotNull { it.buildId }.distinct().sorted(),
            assetCount = assets.size,
            representativeAssets = reported,
            manifestEntries = manifestEntries,
            snapshotEntries = snapshots.take(limits.maxReportedAssets),
            kernelBlobEntries = kernels.take(limits.maxReportedAssets),
            aotLikely = appLibraries.isNotEmpty(),
            artifactFingerprints = fingerprints,
            truncated = archiveTruncated || assets.size > reported.size || snapshots.size > limits.maxReportedAssets || kernels.size > limits.maxReportedAssets,
        )
    }

    private fun scanHermes(
        zip: ZipFile,
        groups: EntryGroups,
        native: NativeSummary?,
        archiveTruncated: Boolean,
        limits: Limits,
    ): HermesRuntimeSummary? {
        val hermesLibraries = native?.libraries.orEmpty().filter {
            it.entryName.substringAfterLast('/').lowercase().contains("hermes")
        }.map { it.entryName }.distinct().sorted()
        val bundleCandidates = groups.hermesCandidates.sortedBy { it.name }
        val bytecode = mutableListOf<HermesBytecodeSummary>()
        val plainBundles = mutableListOf<RuntimeFileReference>()
        var truncated = archiveTruncated || bundleCandidates.size > limits.maxHermesCandidates
        for (entry in bundleCandidates.take(limits.maxHermesCandidates)) {
            val probeLimit = HERMES_HEADER_PROBE_BYTES + limits.maxHermesFunctions * HERMES_SMALL_FUNCTION_HEADER_BYTES
            val header = runCatching { zip.getInputStream(entry).use { readAtMost(it, probeLimit) } }.getOrNull()
            if (header == null) continue
            if (header.size >= 8 && u64le(header, 0) == HERMES_MAGIC) {
                bytecode += parseHermesHeader(entry, header, limits.maxHermesFunctions)
            } else if (plainBundles.size < limits.maxReportedBundles) {
                plainBundles += RuntimeFileReference(entry.name, safeSize(entry))
            } else truncated = true
        }
        val detected = hermesLibraries.isNotEmpty() || bytecode.isNotEmpty()
        if (!detected && plainBundles.isEmpty()) return null
        val confidence = when {
            bytecode.isNotEmpty() && hermesLibraries.isNotEmpty() -> "HIGH"
            bytecode.isNotEmpty() || hermesLibraries.isNotEmpty() -> "MEDIUM"
            else -> "LOW"
        }
        return HermesRuntimeSummary(
            detected = detected,
            confidence = confidence,
            hermesLibraries = hermesLibraries,
            bytecodeFiles = bytecode,
            javascriptBundles = plainBundles,
            truncated = truncated,
        )
    }

    private fun parseHermesHeader(entry: ZipEntry, header: ByteArray, maxFunctions: Int): HermesBytecodeSummary {
        if (header.size < HERMES_HEADER_PROBE_BYTES) {
            return HermesBytecodeSummary(
                entryName = entry.name,
                sizeBytes = safeSize(entry),
                magicValid = true,
                bytecodeVersion = null,
                declaredFileLength = null,
                globalCodeIndex = null,
                functionCount = null,
                identifierCount = null,
                stringCount = null,
                sourceHashSha1 = null,
                parseError = "Hermes bytecode header is truncated",
                truncated = true,
            )
        }
        val version = u32le(header, 8).toInt()
        val sourceHash = header.copyOfRange(12, 32).toHex()
        val declaredLength = u32le(header, 32)
        val actual = safeSize(entry)
        val functionCount = u32le(header, 40)
        val stringKindCount = u32le(header, 44)
        val identifierCount = u32le(header, 48)
        val stringCount = u32le(header, 52)
        val overflowStringCount = u32le(header, 56)
        val stringStorageSize = u32le(header, 60)
        val structuredPrefix = checkedHermesPrefix(
            functionCount,
            stringKindCount,
            identifierCount,
            stringCount,
            overflowStringCount,
            stringStorageSize,
        )
        val errors = mutableListOf<String>()
        if (actual >= 0 && declaredLength > actual) errors += "declared Hermes file length exceeds ZIP entry size"
        if (declaredLength < HERMES_HEADER_PROBE_BYTES) errors += "declared Hermes file length is smaller than the fixed header"
        if (structuredPrefix == null) errors += "Hermes table-size arithmetic overflow"
        else if (structuredPrefix > declaredLength) errors += "Hermes fixed table prefix exceeds declared file length"

        val availableHeaders = ((header.size - HERMES_HEADER_PROBE_BYTES).coerceAtLeast(0) / HERMES_SMALL_FUNCTION_HEADER_BYTES)
        val scanCount = minOf(functionCount.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), maxFunctions, availableHeaders)
        val functions = ArrayList<HermesFunctionSummary>(scanCount)
        repeat(scanCount) { index ->
            val base = HERMES_HEADER_PROBE_BYTES + index * HERMES_SMALL_FUNCTION_HEADER_BYTES
            val w1 = u32le(header, base)
            val w2 = u32le(header, base + 4)
            val frame = header[base + 8].toInt() and 0xff
            val flags = header[base + 11].toInt() and 0xff
            val overflowed = (flags and 0x20) != 0
            val offset = w1 and 0x01ffffffL
            val functionName = ((w2 ushr 14) and 0xff).toInt()
            val largeHeaderOffset = if (overflowed) offset or (functionName.toLong() shl 24) else null
            functions += HermesFunctionSummary(
                index = index,
                bytecodeOffset = if (overflowed) null else offset,
                bytecodeSizeBytes = if (overflowed) null else (w2 and 0x3fffL),
                parameterCount = if (overflowed) null else ((w1 ushr 25) and 0x1f).toInt(),
                loopDepth = if (overflowed) null else ((w1 ushr 30) and 0x3).toInt(),
                functionNameId = if (overflowed) null else functionName,
                frameSize = if (overflowed) null else frame,
                strictMode = if (overflowed) null else (flags and 0x04) != 0,
                hasExceptionHandler = if (overflowed) null else (flags and 0x08) != 0,
                hasDebugInfo = if (overflowed) null else (flags and 0x10) != 0,
                overflowed = overflowed,
                largeHeaderOffset = largeHeaderOffset,
            )
        }
        val functionsTruncated = functionCount > scanCount.toLong()
        return HermesBytecodeSummary(
            entryName = entry.name,
            sizeBytes = actual,
            magicValid = true,
            bytecodeVersion = version,
            declaredFileLength = declaredLength,
            globalCodeIndex = u32le(header, 36),
            functionCount = functionCount,
            stringKindCount = stringKindCount,
            identifierCount = identifierCount,
            stringCount = stringCount,
            overflowStringCount = overflowStringCount,
            stringStorageSize = stringStorageSize,
            bigIntCount = u32le(header, 64),
            regExpCount = u32le(header, 72),
            literalValueBufferSize = u32le(header, 80),
            objKeyBufferSize = u32le(header, 84),
            objShapeTableCount = u32le(header, 88),
            segmentId = u32le(header, 96),
            cjsModuleCount = u32le(header, 100),
            functionSourceCount = u32le(header, 104),
            debugInfoOffset = u32le(header, 108),
            staticBuiltins = (header[112].toInt() and 0x01) != 0,
            structuredPrefixBytes = structuredPrefix,
            functionsScanned = scanCount,
            functions = functions,
            sourceHashSha1 = sourceHash,
            parseError = errors.takeIf { it.isNotEmpty() }?.joinToString("; "),
            truncated = functionsTruncated,
        )
    }

    private fun checkedHermesPrefix(
        functionCount: Long,
        stringKindCount: Long,
        identifierCount: Long,
        stringCount: Long,
        overflowStringCount: Long,
        stringStorageSize: Long,
    ): Long? = runCatching {
        fun addMul(base: Long, count: Long, width: Long): Long {
            require(count >= 0 && width >= 0 && (count == 0L || count <= (Long.MAX_VALUE - base) / width))
            return base + count * width
        }
        var size = HERMES_HEADER_PROBE_BYTES.toLong()
        size = addMul(size, functionCount, HERMES_SMALL_FUNCTION_HEADER_BYTES.toLong())
        size = addMul(size, stringKindCount, 4L)
        size = addMul(size, identifierCount, 4L)
        size = addMul(size, stringCount, 4L)
        size = addMul(size, overflowStringCount, 8L)
        require(stringStorageSize <= Long.MAX_VALUE - size)
        size + stringStorageSize
    }.getOrNull()

    private fun scanUnityMono(
        zip: ZipFile,
        groups: EntryGroups,
        native: NativeSummary?,
        archiveTruncated: Boolean,
        limits: Limits,
    ): UnityMonoRuntimeSummary? {
        val libs = native?.libraries.orEmpty()
        val monoLibs = libs.filter {
            val n = it.entryName.substringAfterLast('/').lowercase()
            n.contains("mono") || n.contains("monosgen")
        }.map { it.entryName }.distinct().sorted()
        val unityLibs = libs.filter { it.entryName.substringAfterLast('/').equals("libunity.so", true) }
            .map { it.entryName }.distinct().sorted()
        val assemblyEntries = groups.managedAssemblies.sortedBy { it.name }
        if (monoLibs.isEmpty() && unityLibs.isEmpty() && assemblyEntries.isEmpty()) return null

        val assemblies = mutableListOf<ManagedAssemblySummary>()
        var total = 0L
        var truncated = archiveTruncated || assemblyEntries.size > limits.maxAssemblies
        for (entry in assemblyEntries.take(limits.maxAssemblies)) {
            val size = safeSize(entry)
            if (size < 0 || size > limits.maxAssemblyBytes || total + size > limits.maxTotalAssemblyBytes) {
                truncated = true
                assemblies += ManagedAssemblySummary(entryName = entry.name, sizeBytes = size.coerceAtLeast(0), peValid = false, cliMetadataPresent = false, metadataVersion = null, nameCandidates = emptyList(), parseError = "assembly exceeds bounded parser budget", truncated = true)
                continue
            }
            val bytesResult = runCatching { zip.getInputStream(entry).use { readBounded(it, limits.maxAssemblyBytes) } }
            val bytes = bytesResult.getOrNull()
            if (bytes == null) {
                val error = bytesResult.exceptionOrNull()
                assemblies += ManagedAssemblySummary(entryName = entry.name, sizeBytes = size.coerceAtLeast(0), peValid = false, cliMetadataPresent = false, metadataVersion = null, nameCandidates = emptyList(), parseError = error?.message?.take(200), truncated = false)
                continue
            }
            total += bytes.size
            assemblies += parseManagedAssembly(entry.name, bytes, limits.maxAssemblyNames)
        }
        val validCli = assemblies.count { it.cliMetadataPresent }
        val signals = listOf(monoLibs.isNotEmpty(), unityLibs.isNotEmpty(), validCli > 0).count { it }
        return UnityMonoRuntimeSummary(
            detected = signals > 0,
            confidence = if (signals >= 2) "HIGH" else "MEDIUM",
            monoLibraries = monoLibs,
            unityLibraries = unityLibs,
            assemblies = assemblies,
            truncated = truncated,
        )
    }

    private fun parseManagedAssembly(entryName: String, bytes: ByteArray, maxNames: Int): ManagedAssemblySummary {
        var peValidated = false
        return runCatching {
            require(bytes.size >= 0x40 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte()) { "missing MZ header" }
            val pe = u32le(bytes, 0x3c).toInt()
            require(pe >= 0 && pe + 24 <= bytes.size) { "PE header offset is out of bounds" }
            require(bytes[pe] == 'P'.code.toByte() && bytes[pe + 1] == 'E'.code.toByte() && bytes[pe + 2] == 0.toByte() && bytes[pe + 3] == 0.toByte()) { "missing PE signature" }
            peValidated = true
            val sectionCount = u16le(bytes, pe + 6)
            val optionalSize = u16le(bytes, pe + 20)
            val optional = pe + 24
            require(sectionCount in 1..256 && optional + optionalSize <= bytes.size) { "invalid PE section/optional header bounds" }
            val magic = u16le(bytes, optional)
            val dataDirStart = when (magic) {
                0x10b -> optional + 96
                0x20b -> optional + 112
                else -> throw IllegalArgumentException("unsupported PE optional header magic")
            }
            val numberOfRva = when (magic) {
                0x10b -> u32le(bytes, optional + 92)
                else -> u32le(bytes, optional + 108)
            }
            require(numberOfRva > 14 && dataDirStart + 15 * 8 <= optional + optionalSize) { "CLI data directory is absent" }
            val cliRva = u32le(bytes, dataDirStart + 14 * 8)
            val cliSize = u32le(bytes, dataDirStart + 14 * 8 + 4)
            require(cliRva != 0L && cliSize >= 0x48) { "CLI header is absent" }
            val sectionTable = optional + optionalSize
            require(sectionTable + sectionCount * 40 <= bytes.size) { "PE section table is truncated" }
            fun rvaToOffset(rva: Long): Int? {
                for (i in 0 until sectionCount) {
                    val base = sectionTable + i * 40
                    val virtualSize = u32le(bytes, base + 8)
                    val virtualAddress = u32le(bytes, base + 12)
                    val rawSize = u32le(bytes, base + 16)
                    val rawPtr = u32le(bytes, base + 20)
                    val span = maxOf(virtualSize, rawSize)
                    if (rva >= virtualAddress && rva < virtualAddress + span) {
                        val delta = rva - virtualAddress
                        val off = rawPtr + delta
                        if (off in 0 until bytes.size.toLong()) return off.toInt()
                    }
                }
                return null
            }
            val cli = rvaToOffset(cliRva) ?: throw IllegalArgumentException("CLI RVA does not map to a PE section")
            require(cli + 16 <= bytes.size) { "CLI header is truncated" }
            val metadataRva = u32le(bytes, cli + 8)
            val metadataSize = u32le(bytes, cli + 12)
            val metadata = rvaToOffset(metadataRva) ?: throw IllegalArgumentException("CLI metadata RVA does not map to a PE section")
            require(metadataSize >= 20 && metadata + 20 <= bytes.size) { "CLI metadata root is truncated" }
            require(u32le(bytes, metadata) == CLI_METADATA_MAGIC) { "invalid CLI metadata signature" }
            val versionLength = u32le(bytes, metadata + 12).coerceAtMost(4096).toInt()
            require(metadata + 16 + versionLength <= bytes.size) { "CLI metadata version string is truncated" }
            val version = bytes.copyOfRange(metadata + 16, metadata + 16 + versionLength)
                .toString(StandardCharsets.UTF_8).trimEnd('\u0000', ' ', '\r', '\n')
            val alignedVersionEnd = align4(metadata + 16 + versionLength)
            require(alignedVersionEnd + 4 <= bytes.size) { "CLI metadata stream header is truncated" }
            val streamCount = u16le(bytes, alignedVersionEnd + 2)
            require(streamCount in 1..64) { "invalid CLI metadata stream count" }
            var streamCursor = alignedVersionEnd + 4
            val streams = mutableListOf<ManagedMetadataStreamSummary>()
            repeat(streamCount) {
                require(streamCursor + 8 <= bytes.size) { "CLI metadata stream directory is truncated" }
                val streamOffset = u32le(bytes, streamCursor)
                val streamSize = u32le(bytes, streamCursor + 4)
                var nameEnd = streamCursor + 8
                while (nameEnd < bytes.size && nameEnd - (streamCursor + 8) < 64 && bytes[nameEnd] != 0.toByte()) nameEnd++
                require(nameEnd < bytes.size && bytes[nameEnd] == 0.toByte()) { "CLI metadata stream name is unterminated" }
                val streamName = bytes.copyOfRange(streamCursor + 8, nameEnd).toString(StandardCharsets.US_ASCII)
                require(streamOffset + streamSize <= metadataSize) { "CLI metadata stream exceeds metadata root" }
                streams += ManagedMetadataStreamSummary(streamName, streamOffset, streamSize)
                streamCursor = align4(nameEnd + 1)
            }
            val tableSummaries = parseManagedTableRows(bytes, metadata, metadataSize, streams)
            val reconstruction = runCatching { ManagedMetadataReconstructor.reconstruct(bytes, metadata, metadataSize, streams) }.getOrNull()
            val scanEnd = minOf(bytes.size, metadata + metadataSize.coerceAtMost(4L * 1024L * 1024L).toInt())
            val names = extractPrintableStrings(bytes, metadata, scanEnd, maxNames)
                .filter { looksManagedName(it) }
                .distinct().take(maxNames)
            ManagedAssemblySummary(
                entryName = entryName,
                sizeBytes = bytes.size.toLong(),
                peValid = true,
                cliMetadataPresent = true,
                metadataVersion = version.ifBlank { null },
                nameCandidates = names,
                metadataStreams = streams,
                metadataTables = reconstruction?.tables ?: tableSummaries,
                assemblyName = reconstruction?.assemblyName,
                assemblyVersion = reconstruction?.assemblyVersion,
                typeReferences = reconstruction?.typeReferences.orEmpty(),
                typeDefinitions = reconstruction?.typeDefinitions.orEmpty(),
                methodDefinitions = reconstruction?.methodDefinitions.orEmpty(),
                memberReferences = reconstruction?.memberReferences.orEmpty(),
                assemblyReferences = reconstruction?.assemblyReferences.orEmpty(),
                reconstructionTruncated = reconstruction?.truncated ?: true,
            )
        }.getOrElse { error ->
            ManagedAssemblySummary(entryName = entryName, sizeBytes = bytes.size.toLong(), peValid = peValidated, cliMetadataPresent = false, metadataVersion = null, nameCandidates = emptyList(), parseError = error.message?.take(220))
        }
    }

    private fun scanUnreal(
        zip: ZipFile,
        groups: EntryGroups,
        native: NativeSummary?,
        archiveTruncated: Boolean,
        limits: Limits,
    ): UnrealRuntimeSummary? {
        val engines = native?.libraries.orEmpty().filter {
            val n = it.entryName.substringAfterLast('/').lowercase()
            n == "libue4.so" || n == "libunreal.so"
        }.map { it.entryName }.distinct().sorted()
        val containers = groups.unrealContainers.sortedBy { it.name }
        val obb = groups.obbEntries.sortedBy { it.name }
        val commandLine = groups.commandLineEntries.asSequence().map { it.name }.distinct().sorted().toList()
        if (engines.isEmpty() && containers.isEmpty() && obb.isEmpty()) return null
        val mapped = containers.take(limits.maxUnrealContainers).map { entry ->
            val n = entry.name.lowercase()
            val kind = when {
                n.endsWith(".pak") -> "PAK"
                n.endsWith(".utoc") -> "IOSTORE_TOC"
                else -> "IOSTORE_CAS"
            }
            val probe = runCatching { zip.getInputStream(entry).use { readAtMost(it, 4096) } }.getOrNull()
            UnrealContainerSummary(
                entryName = entry.name,
                kind = kind,
                sizeBytes = safeSize(entry),
                probeSha256 = probe?.let { MessageDigest.getInstance("SHA-256").digest(it).toHex() },
                probeBytes = probe?.size ?: 0,
            )
        }
        val obbRefs = obb.take(limits.maxObbEntries).map { RuntimeFileReference(it.name, safeSize(it)) }
        val signals = listOf(engines.isNotEmpty(), containers.isNotEmpty(), obb.isNotEmpty()).count { it }
        return UnrealRuntimeSummary(
            detected = true,
            confidence = if (signals >= 2) "HIGH" else "MEDIUM",
            engineLibraries = engines,
            containers = mapped,
            obbEntries = obbRefs,
            commandLineEntries = commandLine.take(32),
            truncated = archiveTruncated || containers.size > mapped.size || obb.size > obbRefs.size,
        )
    }


    private fun parseManagedTableRows(
        bytes: ByteArray,
        metadataRoot: Int,
        metadataSize: Long,
        streams: List<ManagedMetadataStreamSummary>,
    ): List<ManagedMetadataTableSummary> {
        val tablesStream = streams.firstOrNull { it.name == "#~" || it.name == "#-" } ?: return emptyList()
        val startLong = metadataRoot.toLong() + tablesStream.offset
        val endLong = startLong + tablesStream.sizeBytes
        require(startLong >= 0 && endLong <= bytes.size && endLong <= metadataRoot.toLong() + metadataSize) { "CLI tables stream is out of bounds" }
        val start = startLong.toInt()
        val end = endLong.toInt()
        require(start + 24 <= end) { "CLI tables stream header is truncated" }
        val valid = u64leLong(bytes, start + 8)
        var cursor = start + 24
        val interesting = mapOf(
            0 to "Module", 1 to "TypeRef", 2 to "TypeDef", 6 to "MethodDef", 10 to "MemberRef",
            12 to "CustomAttribute", 32 to "Assembly", 35 to "AssemblyRef", 40 to "ManifestResource",
        )
        val out = mutableListOf<ManagedMetadataTableSummary>()
        for (tableId in 0 until 64) {
            if ((valid ushr tableId) and 1L == 0L) continue
            require(cursor + 4 <= end) { "CLI table row-count directory is truncated" }
            val rows = u32le(bytes, cursor)
            interesting[tableId]?.let { out += ManagedMetadataTableSummary(tableId, it, rows) }
            cursor += 4
        }
        return out
    }

    private fun align4(value: Int): Int = (value + 3) and -4

    private fun u64leLong(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0 && offset + 8 <= bytes.size)
        var result = 0L
        repeat(8) { i -> result = result or ((bytes[offset + i].toLong() and 0xffL) shl (8 * i)) }
        return result
    }

    private fun readAtMost(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream(minOf(maxBytes, 4096))
        val buf = ByteArray(minOf(DEFAULT_BUFFER_SIZE, maxBytes))
        var remaining = maxBytes
        while (remaining > 0) {
            val read = input.read(buf, 0, minOf(buf.size, remaining))
            if (read <= 0) break
            out.write(buf, 0, read)
            remaining -= read
        }
        return out.toByteArray()
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Long): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buf)
            if (read <= 0) break
            total += read
            require(total <= maxBytes) { "entry exceeds bounded parser budget" }
            out.write(buf, 0, read)
        }
        return out.toByteArray()
    }

    private fun extractPrintableStrings(bytes: ByteArray, start: Int, endExclusive: Int, max: Int): List<String> {
        val out = mutableListOf<String>()
        var begin = -1
        var i = start.coerceAtLeast(0)
        val end = endExclusive.coerceAtMost(bytes.size)
        while (i <= end) {
            val printable = i < end && (bytes[i].toInt() and 0xff) in 0x20..0x7e
            if (printable && begin < 0) begin = i
            if (!printable && begin >= 0) {
                val len = i - begin
                if (len in 3..180 && out.size < max * 4) out += bytes.copyOfRange(begin, i).toString(StandardCharsets.US_ASCII)
                begin = -1
            }
            i++
        }
        return out
    }

    private fun looksManagedName(value: String): Boolean {
        if (value.length !in 3..160 || !value.any(Char::isLetter)) return false
        return value.endsWith(".dll", true) || value.matches(Regex("[A-Za-z_][A-Za-z0-9_`.+-]{2,159}")) ||
            value.matches(Regex("[A-Za-z_][A-Za-z0-9_.`+:-]{2,159}"))
    }

    private fun safeSize(entry: ZipEntry): Long = entry.size.coerceAtLeast(0)

    private fun u16le(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= bytes.size)
        return (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun u32le(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0 && offset + 4 <= bytes.size)
        return (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)
    }

    private fun u64le(bytes: ByteArray, offset: Int): ULong {
        require(offset >= 0 && offset + 8 <= bytes.size)
        var result = 0uL
        repeat(8) { i -> result = result or ((bytes[offset + i].toULong() and 0xffuL) shl (8 * i)) }
        return result
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private const val HERMES_HEADER_PROBE_BYTES = 128
    private const val HERMES_SMALL_FUNCTION_HEADER_BYTES = 12
    private val HERMES_MAGIC = 0x1F1903C103BC1FC6uL
    private const val CLI_METADATA_MAGIC = 0x424A5342L // BSJB
}
