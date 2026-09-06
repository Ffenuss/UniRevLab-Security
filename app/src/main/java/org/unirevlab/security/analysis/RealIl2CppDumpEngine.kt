package org.unirevlab.security.analysis

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONObject
import org.json.JSONArray
import org.unirevlab.security.nativecore.NativeAnalysis

/** Runs the pinned Rodroid parser through JNI and packages only engine-produced artifacts. */
object RealIl2CppDumpEngine {
    data class NamedLibrary(val abi: String, val sourcePath: String, val file: File)

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
        val successfulAbis: List<String> = emptyList(),
        val failedAbis: List<String> = emptyList(),
        val pairLocated: Boolean = true,
    )

    fun notAvailable(error: String): Result = Result(
        complete = false,
        status = "IL2CPP_PAIR_NOT_AVAILABLE",
        error = error,
        engine = "il2cpp-dumper-rs",
        engineRevision = null,
        metadataVersion = null,
        architecture = null,
        typeCount = 0,
        methodCount = 0,
        codeRegistration = null,
        metadataRegistration = null,
        registrationStrategy = null,
        dumpCsFile = null,
        packageFile = null,
        manifestFile = null,
        generatedFiles = emptyList(),
        pairLocated = false,
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

    /** Runs the real engine independently for every discovered ABI and creates one auditable package. */
    fun dumpMultiple(metadataFile: File, libraries: List<NamedLibrary>, outputDirectory: File): Result {
        require(libraries.isNotEmpty()) { "At least one libil2cpp.so is required" }
        outputDirectory.deleteRecursively()
        require(outputDirectory.mkdirs()) { "Unable to create multi-ABI IL2CPP output directory" }
        val attempts = libraries.distinctBy { it.abi }.map { library ->
            val abi = safeAbi(library.abi)
            val directory = File(outputDirectory, abi)
            val result = dump(metadataFile, library.file, directory)
            result.packageFile?.delete()
            AbiAttempt(abi, library.sourcePath, result)
        }
        val complete = attempts.filter { it.result.complete }
        if (complete.isEmpty()) {
            val first = attempts.first().result
            return first.copy(
                error = attempts.joinToString("; ") { "${it.abi}: ${it.result.error ?: it.result.status}" },
                failedAbis = attempts.map(AbiAttempt::abi),
            )
        }

        val gameplay = JSONArray()
        val application = JSONArray()
        complete.forEach { attempt ->
            val surfaces = File(outputDirectory, "${attempt.abi}/security-surfaces.json")
            if (surfaces.isFile) {
                val json = runCatching { JSONObject(surfaces.readText(Charsets.UTF_8)) }.getOrNull()
                appendWithAbi(json?.optJSONArray("gameplayOffsets"), gameplay, attempt.abi)
                appendWithAbi(json?.optJSONArray("applicationAndMonetizationOffsets"), application, attempt.abi)
            }
        }
        val aggregate = JSONObject()
            .put("schemaVersion", "1.0")
            .put("source", "completed Rodroid dumps for every discovered ABI")
            .put("semantics", "Only addresses emitted by a completed engine dump are included. Field offsets are not absolute addresses.")
            .put("gameplayOffsets", gameplay)
            .put("applicationAndMonetizationOffsets", application)
        File(outputDirectory, "confirmed-offsets-all-abi.json").writeText(aggregate.toString(2), Charsets.UTF_8)
        writeAggregateCsv(outputDirectory, gameplay, application)
        writeReadableSummary(outputDirectory, attempts, gameplay.length(), application.length())

        val manifest = JSONObject()
            .put("schemaVersion", "1.0")
            .put("engine", "il2cpp-dumper-rs")
            .put("metadataSha256", sha256(metadataFile))
            .put("attemptedAbis", JSONArray(attempts.map(AbiAttempt::abi)))
            .put("successfulAbis", JSONArray(complete.map(AbiAttempt::abi)))
            .put("failedAbis", JSONArray(attempts.filterNot { it.result.complete }.map { it.abi }))
            .put("results", JSONArray(attempts.map { attempt ->
                JSONObject()
                    .put("abi", attempt.abi)
                    .put("sourcePath", attempt.sourcePath)
                    .put("status", attempt.result.status)
                    .put("error", attempt.result.error ?: JSONObject.NULL)
                    .put("architecture", attempt.result.architecture ?: JSONObject.NULL)
                    .put("codeRegistration", attempt.result.codeRegistration ?: JSONObject.NULL)
                    .put("metadataRegistration", attempt.result.metadataRegistration ?: JSONObject.NULL)
                    .put("registrationStrategy", attempt.result.registrationStrategy ?: JSONObject.NULL)
            }))
        File(outputDirectory, "multi-abi-manifest.json").writeText(manifest.toString(2), Charsets.UTF_8)

        val primary = complete.minByOrNull { ABI_PRIORITY.indexOf(it.abi).let { priority -> if (priority < 0) Int.MAX_VALUE else priority } }!!
        val packageFile = File(outputDirectory.parentFile, "${outputDirectory.name}-real-il2cpp-dump.zip")
        zipDirectory(outputDirectory, packageFile)
        return primary.result.copy(
            dumpCsFile = primary.result.dumpCsFile,
            packageFile = packageFile,
            manifestFile = File(outputDirectory, "multi-abi-manifest.json"),
            generatedFiles = outputDirectory.walkTopDown().filter(File::isFile).map { it.relativeTo(outputDirectory).invariantSeparatorsPath }.sorted().toList(),
            gameplaySurfaceCount = gameplay.length(),
            applicationSurfaceCount = application.length(),
            successfulAbis = complete.map(AbiAttempt::abi),
            failedAbis = attempts.filterNot { it.result.complete }.map(AbiAttempt::abi),
        )
    }

    private fun appendWithAbi(source: JSONArray?, destination: JSONArray, abi: String) {
        if (source == null) return
        for (index in 0 until source.length()) {
            val value = source.optJSONObject(index) ?: continue
            destination.put(JSONObject(value.toString()).put("abi", abi))
        }
    }

    private fun writeAggregateCsv(directory: File, gameplay: JSONArray, application: JSONArray) {
        File(directory, "confirmed-offsets-all-abi.csv").bufferedWriter(Charsets.UTF_8).use { output ->
            output.appendLine("abi,domain,category,address_kind,address,confidence,managed_identity")
            sequenceOf(gameplay, application).forEach { array ->
                for (index in 0 until array.length()) {
                    val item = array.optJSONObject(index) ?: continue
                    output.appendLine(
                        listOf("abi", "domain", "category", "addressKind", "address", "confidence", "managedIdentity")
                            .joinToString(",") { key -> csv(item.optString(key)) }
                    )
                }
            }
        }
    }

    private fun writeReadableSummary(directory: File, attempts: List<AbiAttempt>, gameplay: Int, application: Int) {
        File(directory, "ЧИТАТЬ-МЕНЯ.txt").writeText(
            buildString {
                appendLine("UniRevLab: настоящий IL2CPP dump")
                appendLine("Успешные ABI: ${attempts.filter { it.result.complete }.joinToString { it.abi }}")
                appendLine("Неуспешные ABI: ${attempts.filterNot { it.result.complete }.joinToString { it.abi }.ifBlank { "нет" }}")
                appendLine("Игровые подтверждённые поверхности: $gameplay")
                appendLine("Приложение/монетизация: $application")
                appendLine("Каждая папка ABI содержит dump.cs, script.json, строки, заголовки и собственный manifest.")
                appendLine("confirmed-offsets-all-abi.* содержит только адреса из успешно завершённых dump; гипотезы туда не попадают.")
            },
            Charsets.UTF_8,
        )
        File(directory, "README.txt").writeText(
            buildString {
                appendLine("UniRevLab: real IL2CPP dump")
                appendLine("Successful ABIs: ${attempts.filter { it.result.complete }.joinToString { it.abi }}")
                appendLine("Failed ABIs: ${attempts.filterNot { it.result.complete }.joinToString { it.abi }.ifBlank { "none" }}")
                appendLine("Confirmed gameplay surfaces: $gameplay")
                appendLine("Application/monetization surfaces: $application")
                appendLine("Each ABI directory contains dump.cs, script.json, strings, headers, and its engine manifest.")
                appendLine("confirmed-offsets-all-abi.* contains only addresses from completed dumps; hypotheses are excluded.")
            },
            Charsets.UTF_8,
        )
    }

    private fun sha256(file: File): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered(128 * 1024).use { input ->
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun safeAbi(value: String): String = value.replace(Regex("[^A-Za-z0-9._-]"), "_").take(48).ifBlank { "unknown" }
    private fun csv(value: String): String = "\"${value.replace("\"", "\"\"")}\""

    private data class AbiAttempt(val abi: String, val sourcePath: String, val result: Result)

    private val ABI_PRIORITY = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

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
