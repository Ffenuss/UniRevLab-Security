package org.unirevlab.security.analysis

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONObject
import org.unirevlab.security.nativecore.NativeAnalysis

/** Runs the pinned Rodroid parser through JNI and packages only engine-produced artifacts. */
object RealIl2CppDumpEngine {
    data class Result(
        val complete: Boolean,
        val status: String,
        val error: String?,
        val engine: String?,
        val engineRevision: String?,
        val metadataVersion: Double?,
        val architecture: String?,
        val typeCount: Int,
        val methodCount: Int,
        val codeRegistration: String?,
        val metadataRegistration: String?,
        val registrationStrategy: String?,
        val dumpCsFile: File?,
        val packageFile: File?,
        val manifestFile: File?,
        val generatedFiles: List<String>,
        val gameplaySurfaceCount: Int = 0,
        val applicationSurfaceCount: Int = 0,
    )

    fun dump(metadataFile: File, libraryFile: File, outputDirectory: File): Result {
        outputDirectory.deleteRecursively()
        require(outputDirectory.mkdirs()) { "Не удалось создать каталог реального IL2CPP dump" }
        val raw = NativeAnalysis.tryDumpIl2CppPairJson(
            binaryPath = libraryFile.absolutePath,
            metadataPath = metadataFile.absolutePath,
            outputDir = outputDirectory.absolutePath,
        ) ?: return Result(
            false, "NATIVE_ENGINE_UNAVAILABLE", "Rust IL2CPP engine не загружен для ABI устройства",
            null, null, null, null, 0, 0, null, null, null, null, null, null, emptyList(),
        )
        val json = runCatching { JSONObject(raw) }.getOrElse { error ->
            return Result(false, "INVALID_ENGINE_RESPONSE", error.message, null, null, null, null, 0, 0, null, null, null, null, null, null, emptyList())
        }
        if (json.optString("status") != "COMPLETE") {
            outputDirectory.deleteRecursively()
            return Result(false, json.optString("status", "FAILED"), json.optString("error", "Неизвестная ошибка IL2CPP engine"), null, null, null, null, 0, 0, null, null, null, null, null, null, emptyList())
        }
        val dumpCs = File(outputDirectory, "dump.cs").takeIf(File::isFile)
        if (dumpCs == null || dumpCs.length() == 0L) {
            outputDirectory.deleteRecursively()
            return Result(false, "INCOMPLETE_OUTPUT", "Engine не создал непустой dump.cs", null, null, null, null, 0, 0, null, null, null, null, null, null, emptyList())
        }
        val generated = json.optJSONArray("generatedFiles")?.let { array ->
            (0 until array.length()).mapNotNull { array.optString(it).takeIf(String::isNotBlank) }
        }.orEmpty()
        val surfaces = ConfirmedIl2CppSurfaceExporter.export(dumpCs, outputDirectory)
        val packageFile = File(outputDirectory.parentFile, "${outputDirectory.name}-real-il2cpp-dump.zip")
        zipDirectory(outputDirectory, packageFile)
        return Result(
            complete = true,
            status = "COMPLETE",
            error = null,
            engine = json.optString("engine").ifBlank { null },
            engineRevision = json.optString("engineRevision").ifBlank { null },
            metadataVersion = json.optDouble("metadataVersion").takeUnless(Double::isNaN),
            architecture = json.optString("architecture").ifBlank { null },
            typeCount = json.optInt("typeCount"),
            methodCount = json.optInt("methodCount"),
            codeRegistration = json.optString("codeRegistration").ifBlank { null },
            metadataRegistration = json.optString("metadataRegistration").ifBlank { null },
            registrationStrategy = json.optString("registrationStrategy").ifBlank { null },
            dumpCsFile = dumpCs,
            packageFile = packageFile,
            manifestFile = File(outputDirectory, "unirevlab-dump-manifest.json").takeIf(File::isFile),
            generatedFiles = generated,
            gameplaySurfaceCount = surfaces.gameplayCount,
            applicationSurfaceCount = surfaces.applicationCount,
        )
    }

    private fun zipDirectory(directory: File, destination: File) {
        ZipOutputStream(BufferedOutputStream(FileOutputStream(destination))).use { zip ->
            directory.walkTopDown().filter(File::isFile).sortedBy { it.relativeTo(directory).invariantSeparatorsPath }.forEach { file ->
                val relative = file.relativeTo(directory).invariantSeparatorsPath
                require(!relative.startsWith("/") && ".." !in relative.split('/')) { "Небезопасный путь dump artifact" }
                zip.putNextEntry(ZipEntry(relative).apply { time = 0L })
                BufferedInputStream(FileInputStream(file)).use { it.copyTo(zip, 128 * 1024) }
                zip.closeEntry()
            }
        }
    }
}
