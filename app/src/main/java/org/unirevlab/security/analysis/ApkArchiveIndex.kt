package org.unirevlab.security.analysis

import java.io.File
import java.util.TreeSet
import java.util.zip.ZipException
import java.util.zip.ZipFile

/**
 * One bounded central-directory classification pass shared by the local analyzers.
 *
 * The index intentionally stores only the bounded metadata each downstream stage already retained.
 * If duplicate relevant ZIP names are observed, consumers that need ZipEntry identity must fall back
 * to their legacy enumeration path rather than risk changing evidence/provenance.
 */
data class ApkArchiveIndex(
    val archiveEntries: Int,
    val archiveDexFiles: Int,
    val archiveNativeLibraries: Int,
    val archiveHasManifest: Boolean,
    val archiveSuspiciousPaths: Int,
    val archiveTruncated: Boolean,
    val dexEntryNames: List<String>,
    val dexEntryCount: Int,
    val nativeEntryNames: List<String>,
    val nativeEntryCount: Int,
    val runtimeProfileEntryNamesLower: Set<String>,
    val runtimeArtifactEntries: List<EntryMetadata>,
    val runtimeArtifactTruncated: Boolean,
    val mavenPomEntries: List<EntryMetadata>,
    val duplicateDexNames: Boolean,
    val duplicateNativeNames: Boolean,
    val duplicateRuntimeArtifactNames: Boolean,
    val duplicateMavenPomNames: Boolean,
) {
    data class EntryMetadata(
        val name: String,
        val size: Long,
        val compressedSize: Long,
        val crc: Long,
    )

    companion object {
        private const val ARCHIVE_STATS_LIMIT = 20_000
        private const val MAX_DEX_NAMES = 32
        private const val MAX_NATIVE_NAMES = 128
        private const val RUNTIME_PROFILE_TOTAL_ENTRY_LIMIT = 100_000
        private const val RUNTIME_ARTIFACT_FILE_LIMIT = 100_000
        private const val MAVEN_POM_LIMIT = 128

        fun build(apk: File): ApkArchiveIndex? = try {
            ZipFile(apk).use { zip ->
                var totalEntries = 0
                var archiveEntries = 0
                var archiveDex = 0
                var archiveNative = 0
                var archiveManifest = false
                var archiveSuspicious = 0
                var dexCount = 0
                var nativeCount = 0
                var runtimeFileCount = 0
                var runtimeArtifactTruncated = false

                val dexNames = TreeSet<String>()
                val nativeNames = TreeSet<String>()
                val profileNames = LinkedHashSet<String>()
                val runtimeEntries = ArrayList<EntryMetadata>(4096)
                val mavenEntries = ArrayList<EntryMetadata>(MAVEN_POM_LIMIT)

                val dexSeen = HashSet<String>()
                val nativeSeen = HashSet<String>()
                val runtimeSeen = HashSet<String>()
                val mavenSeen = HashSet<String>()
                var duplicateDex = false
                var duplicateNative = false
                var duplicateRuntime = false
                var duplicateMaven = false

                val iterator = zip.entries()
                while (iterator.hasMoreElements()) {
                    val entry = iterator.nextElement()
                    totalEntries++
                    val name = entry.name
                    val isDirectory = entry.isDirectory

                    if (totalEntries <= ARCHIVE_STATS_LIMIT) {
                        archiveEntries++
                        if (ArchiveClassifier.isDex(name)) archiveDex++
                        if (ArchiveClassifier.isNativeLibrary(name)) archiveNative++
                        if (name == "AndroidManifest.xml") archiveManifest = true
                        if (ArchiveClassifier.isSuspiciousPath(name)) archiveSuspicious++
                    }

                    if (totalEntries <= RUNTIME_PROFILE_TOTAL_ENTRY_LIMIT && !isDirectory) {
                        profileNames += name.lowercase()
                    }
                    if (runtimeFileCount >= RUNTIME_ARTIFACT_FILE_LIMIT) runtimeArtifactTruncated = true
                    if (isDirectory) continue

                    if (runtimeFileCount < RUNTIME_ARTIFACT_FILE_LIMIT) {
                        runtimeFileCount++
                        if (!runtimeSeen.add(name)) duplicateRuntime = true
                        runtimeEntries += EntryMetadata(name, entry.size, entry.compressedSize, entry.crc)
                    } else {
                        runtimeArtifactTruncated = true
                    }

                    if (ArchiveClassifier.isDex(name)) {
                        dexCount++
                        if (!dexSeen.add(name)) duplicateDex = true
                        dexNames += name
                        if (dexNames.size > MAX_DEX_NAMES) dexNames.pollLast()
                    }
                    if (ArchiveClassifier.isNativeLibrary(name)) {
                        nativeCount++
                        if (!nativeSeen.add(name)) duplicateNative = true
                        nativeNames += name
                        if (nativeNames.size > MAX_NATIVE_NAMES) nativeNames.pollLast()
                    }
                    if (name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties")) {
                        if (!mavenSeen.add(name)) duplicateMaven = true
                        if (mavenEntries.size < MAVEN_POM_LIMIT) {
                            mavenEntries += EntryMetadata(name, entry.size, entry.compressedSize, entry.crc)
                        }
                    }
                }

                ApkArchiveIndex(
                    archiveEntries = archiveEntries,
                    archiveDexFiles = archiveDex,
                    archiveNativeLibraries = archiveNative,
                    archiveHasManifest = archiveManifest,
                    archiveSuspiciousPaths = archiveSuspicious,
                    archiveTruncated = totalEntries > ARCHIVE_STATS_LIMIT,
                    dexEntryNames = dexNames.toList(),
                    dexEntryCount = dexCount,
                    nativeEntryNames = nativeNames.toList(),
                    nativeEntryCount = nativeCount,
                    runtimeProfileEntryNamesLower = profileNames,
                    runtimeArtifactEntries = runtimeEntries,
                    runtimeArtifactTruncated = runtimeArtifactTruncated,
                    mavenPomEntries = mavenEntries,
                    duplicateDexNames = duplicateDex,
                    duplicateNativeNames = duplicateNative,
                    duplicateRuntimeArtifactNames = duplicateRuntime,
                    duplicateMavenPomNames = duplicateMaven,
                )
            }
        } catch (_: ZipException) {
            null
        } catch (_: java.io.IOException) {
            null
        }
    }
}
