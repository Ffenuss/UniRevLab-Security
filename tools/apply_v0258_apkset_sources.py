from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path):
    return (ROOT / path).read_text(encoding="utf-8")

def write(path, text):
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")

def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f"missing patch anchor: {label}")
    if text.count(old) != 1:
        raise SystemExit(f"ambiguous patch anchor {label}: {text.count(old)} matches")
    return text.replace(old, new, 1)

# Version + cache invalidation.
build = read("app/build.gradle.kts")
build = replace_once(build, 'versionCode = 36\n        versionName = "0.25.7-dev-full-pickers"', 'versionCode = 37\n        versionName = "0.25.8-dev-apkset-sources"', "version")
write("app/build.gradle.kts", build)

nested = r'''package org.unirevlab.security.analysis

import java.io.File
import java.io.FileOutputStream
import java.io.InterruptedIOException
import java.util.Locale
import java.util.zip.ZipException
import java.util.zip.ZipFile

/**
 * Recognizes backup/container formats whose outer ZIP contains one base APK and optional split APKs.
 * Plain APKs are deliberately rejected so a normal application package is never reinterpreted as a set.
 */
object NestedApkSet {
    data class Item(
        val entryName: String,
        val file: File,
        val prefix: String,
        val isBase: Boolean,
    )

    data class Extracted(
        val root: File,
        val items: List<Item>,
    ) {
        val base: Item get() = items.first { it.isBase }
        val splits: List<Item> get() = items.filterNot { it.isBase }
        fun cleanup() { root.deleteRecursively() }
        fun selectForReportEntry(reportEntry: String?): Item {
            if (reportEntry.isNullOrBlank()) return base
            val prefix = reportEntry.substringBefore("!/", missingDelimiterValue = "")
            if (prefix == "base.apk") return base
            if (prefix.startsWith("split:")) {
                val leaf = prefix.removePrefix("split:")
                return splits.firstOrNull { it.file.name == leaf || it.entryName.substringAfterLast('/') == leaf } ?: base
            }
            return base
        }
    }

    private data class Candidate(val name: String, val size: Long)

    fun extract(container: File, destinationRoot: File): Extracted? {
        val outer = ApkArchiveIndex.build(container) ?: return null
        if (outer.archiveHasManifest || outer.dexEntryCount > 0 || outer.nativeEntryCount > 0) return null

        val candidates = try {
            ZipFile(container).use { zip ->
                val result = ArrayList<Candidate>()
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    checkCancelled()
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val lower = entry.name.lowercase(Locale.ROOT)
                    if (!lower.endsWith(".apk")) continue
                    if (entry.size > MAX_SINGLE_APK_BYTES) throw IllegalArgumentException("Nested APK exceeds size limit")
                    result += Candidate(entry.name, entry.size)
                    require(result.size <= MAX_APK_COUNT) { "APK-set contains too many APK files" }
                }
                result
            }
        } catch (e: InterruptedIOException) {
            throw e
        } catch (_: ZipException) {
            return null
        }
        if (candidates.isEmpty()) return null

        val declared = candidates.sumOf { it.size.coerceAtLeast(0L) }
        require(declared <= MAX_TOTAL_EXTRACTED_BYTES) { "APK-set exceeds decompression limit" }
        destinationRoot.deleteRecursively()
        require(destinationRoot.mkdirs() || destinationRoot.isDirectory) { "Cannot create APK-set workspace" }

        val extracted = ArrayList<Pair<Candidate, File>>(candidates.size)
        var copiedTotal = 0L
        try {
            ZipFile(container).use { zip ->
                candidates.forEachIndexed { index, candidate ->
                    checkCancelled()
                    val entry = requireNotNull(zip.getEntry(candidate.name)) { "Nested APK disappeared from container" }
                    val out = File(destinationRoot, "apk-${index.toString().padStart(3, '0')}-${safeLeaf(candidate.name)}")
                    var copied = 0L
                    zip.getInputStream(entry).buffered(BUFFER).use { input ->
                        FileOutputStream(out).buffered(BUFFER).use { output ->
                            val buffer = ByteArray(BUFFER)
                            while (true) {
                                checkCancelled()
                                val read = input.read(buffer)
                                if (read < 0) break
                                if (read == 0) continue
                                copied += read
                                copiedTotal += read
                                require(copied <= MAX_SINGLE_APK_BYTES) { "Nested APK exceeds decompression limit" }
                                require(copiedTotal <= MAX_TOTAL_EXTRACTED_BYTES) { "APK-set exceeds decompression limit" }
                                output.write(buffer, 0, read)
                            }
                        }
                    }
                    require(out.length() > 0L) { "Nested APK is empty" }
                    val indexInfo = ApkArchiveIndex.build(out) ?: error("Nested .apk is not a valid ZIP/APK: ${candidate.name}")
                    require(indexInfo.archiveHasManifest) { "Nested APK has no AndroidManifest.xml: ${candidate.name}" }
                    extracted += candidate to out
                }
            }
        } catch (t: Throwable) {
            destinationRoot.deleteRecursively()
            throw t
        }

        val basePair = extracted.firstOrNull { it.first.name.substringAfterLast('/').equals("base.apk", ignoreCase = true) }
            ?: extracted.filter { (_, file) -> ApkArchiveIndex.build(file)?.dexEntryCount?.let { it > 0 } == true }.maxByOrNull { it.second.length() }
            ?: extracted.maxByOrNull { it.second.length() }
            ?: return null

        val ordered = buildList {
            add(basePair)
            extracted.filterNot { it === basePair }.sortedBy { it.first.name }.forEach(::add)
        }
        val items = ordered.mapIndexed { index, (candidate, file) ->
            val base = index == 0
            val leaf = file.name.substringAfterLast('-').ifBlank { safeLeaf(candidate.name) }
            val originalLeaf = candidate.name.substringAfterLast('/').ifBlank { leaf }
            Item(
                entryName = candidate.name,
                file = file,
                prefix = if (base) "base.apk" else "split:$originalLeaf",
                isBase = base,
            )
        }
        return Extracted(destinationRoot, items)
    }

    private fun safeLeaf(name: String): String = name.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").take(120).ifBlank { "split.apk" }

    private fun checkCancelled() {
        if (Thread.currentThread().isInterrupted) throw InterruptedIOException("APK-set extraction cancelled")
    }

    private const val MAX_APK_COUNT = 128
    private const val MAX_SINGLE_APK_BYTES = 2L * 1024L * 1024L * 1024L
    private const val MAX_TOTAL_EXTRACTED_BYTES = 4L * 1024L * 1024L * 1024L
    private const val BUFFER = 128 * 1024
}
'''
write("app/src/main/java/org/unirevlab/security/analysis/NestedApkSet.kt", nested)

nested_test = r'''package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class NestedApkSetTest {
    @Test fun extractsBaseAndSplitFromOuterContainer() {
        val root = createTempDir(prefix = "apkset-test-")
        try {
            val base = File(root, "base.apk")
            fakeApk(base, withDex = true)
            val split = File(root, "config.arm64_v8a.apk")
            fakeApk(split, withDex = false)
            val outer = File(root, "sample.apk+")
            ZipOutputStream(outer.outputStream()).use { out ->
                addFile(out, "base.apk", base)
                addFile(out, "splits/config.arm64_v8a.apk", split)
                out.putNextEntry(ZipEntry("meta.json")); out.write("{}".toByteArray()); out.closeEntry()
            }
            val extracted = NestedApkSet.extract(outer, File(root, "out"))
            assertNotNull(extracted)
            extracted!!
            assertEquals("base.apk", extracted.base.prefix)
            assertEquals(1, extracted.splits.size)
            assertEquals("split:config.arm64_v8a.apk", extracted.splits.single().prefix)
            assertEquals(extracted.splits.single(), extracted.selectForReportEntry("split:config.arm64_v8a.apk!/lib/arm64-v8a/libx.so"))
        } finally { root.deleteRecursively() }
    }

    @Test fun doesNotTreatPlainApkAsContainer() {
        val root = createTempDir(prefix = "apkset-plain-")
        try {
            val apk = File(root, "plain.apk")
            fakeApk(apk, withDex = true)
            assertNull(NestedApkSet.extract(apk, File(root, "out")))
        } finally { root.deleteRecursively() }
    }

    private fun fakeApk(file: File, withDex: Boolean) {
        ZipOutputStream(file.outputStream()).use { out ->
            out.putNextEntry(ZipEntry("AndroidManifest.xml")); out.write(byteArrayOf(1, 2, 3)); out.closeEntry()
            if (withDex) { out.putNextEntry(ZipEntry("classes.dex")); out.write("dex\n035\u0000".toByteArray()); out.closeEntry() }
        }
    }

    private fun addFile(out: ZipOutputStream, name: String, file: File) {
        out.putNextEntry(ZipEntry(name)); file.inputStream().use { it.copyTo(out) }; out.closeEntry()
    }
}
'''
write("app/src/test/java/org/unirevlab/security/analysis/NestedApkSetTest.kt", nested_test)

# LocalArtifactInspector: detect nested APK-set before treating the outer container as an APK.
inspector = read("app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt")
inspector = replace_once(inspector, 'const val ENGINE_VERSION = "0.22.5-dev-native-speed"', 'const val ENGINE_VERSION = "0.25.8-dev-apkset-sources"', "engine cache version")
old = '''            val report = inspectPreparedFile(
                apk = temp,
                scope = scope,
                displayName = displayName,
                sizeBytes = sizeBytes,
                sha256 = digest,
                progress = progress,
            )
            progress.emit(AnalysisStage.SAVING, 99, "Сохраняем нормализованный результат в локальный SHA-256 кэш…")
            resultCache.store(report)
            progress.emit(AnalysisStage.COMPLETE, 100, "Анализ завершён")
            report
'''
new = '''            val nestedRoot = File(cacheDir, "nested-apkset/${digest.take(24)}")
            val nested = NestedApkSet.extract(temp, nestedRoot)
            val report = if (nested != null) {
                try {
                    val baseInfo = context.packageManager.getPackageArchiveInfo(nested.base.file.absolutePath, 0)
                        ?: error("Не удалось прочитать base APK внутри контейнера")
                    val packageName = baseInfo.packageName ?: error("В base APK отсутствует packageName")
                    val descriptor = InstalledAppDescriptor(
                        label = displayName,
                        packageName = packageName,
                        versionName = baseInfo.versionName,
                        versionCode = baseInfo.longVersionCodeCompat(),
                        isSystem = false,
                        isEnabled = true,
                        baseApkPath = nested.base.file.absolutePath,
                        splitApkPaths = nested.splits.map { it.file.absolutePath },
                        installerPackageName = null,
                    )
                    val nestedReport = inspectInstalledApp(descriptor, scope) { nestedProgress ->
                        val scaled = 10 + ((nestedProgress.percent.coerceIn(0, 100) * 88) / 100)
                        val fraction = scaled / 100.0
                        onProgress?.invoke(
                            nestedProgress.copy(
                                percent = scaled,
                                fractionComplete = fraction,
                                startedAtEpochMs = progress.startedAtEpochMs,
                                detail = "APK-set: ${nestedProgress.detail}",
                            )
                        )
                    }
                    nestedReport.copy(
                        artifact = nestedReport.artifact.copy(
                            displayName = displayName,
                            sizeBytes = sizeBytes,
                            sha256 = digest,
                            sourceKind = "APK_SET_FILE",
                            sourcePackageName = packageName,
                            sourceInstallerPackageName = null,
                            splitApkCount = nested.splits.size,
                        )
                    )
                } finally {
                    nested.cleanup()
                }
            } else {
                inspectPreparedFile(
                    apk = temp,
                    scope = scope,
                    displayName = displayName,
                    sizeBytes = sizeBytes,
                    sha256 = digest,
                    progress = progress,
                )
            }
            progress.emit(AnalysisStage.SAVING, 99, "Сохраняем нормализованный результат в локальный SHA-256 кэш…")
            resultCache.store(report)
            progress.emit(AnalysisStage.COMPLETE, 100, "Анализ завершён")
            report
'''
inspector = replace_once(inspector, old, new, "nested APK-set inspect")
write("app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt", inspector)

# MainActivity retains the installed application descriptor as the post-analysis source.
main = read("app/src/main/java/org/unirevlab/security/MainActivity.kt")
main = replace_once(main, '    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }\n', '    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }\n    var lastInstalledApp by remember { mutableStateOf<InstalledAppDescriptor?>(null) }\n', "remember installed source")
main = replace_once(main, '            lastArtifactUri = uri\n            requestAnalysisNotificationPermission()', '            lastArtifactUri = uri\n            lastInstalledApp = null\n            requestAnalysisNotificationPermission()', "file clears installed source")
main = replace_once(main, '                    initialSourceUri = lastArtifactUri,\n                    onBack', '                    initialSourceUri = lastArtifactUri,\n                    initialInstalledApp = lastInstalledApp,\n                    onBack', "PatchLab installed param")
main = replace_once(main, '                lastArtifactUri = null\n                requestAnalysisNotificationPermission()\n                AnalysisManager.startInstalled(app, requireNotNull(scope))', '                lastArtifactUri = null\n                lastInstalledApp = app\n                requestAnalysisNotificationPermission()\n                AnalysisManager.startInstalled(app, requireNotNull(scope))', "remember selected installed app")
write("app/src/main/java/org/unirevlab/security/MainActivity.kt", main)

# PatchLabEngine supports plain APK, nested APK-set and installed base/split sources while preserving report entry prefixes.
engine = read("app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt")
engine = replace_once(engine, 'import org.unirevlab.security.model.Finding\nimport org.unirevlab.security.model.StaticAnalysisReport', 'import org.unirevlab.security.model.Finding\nimport org.unirevlab.security.model.InstalledAppDescriptor\nimport org.unirevlab.security.model.StaticAnalysisReport', "engine installed import")
engine = replace_once(engine, '        val archiveEntries: List<String>,\n        val modifiedDexEntries:', '        val archiveEntries: List<String>,\n        val sourcePrefix: String? = null,\n        val modifiedDexEntries:', "workspace sourcePrefix")
start = engine.index('    fun prepare(context: Context, sourceUri: Uri, report: StaticAnalysisReport): Workspace {')
end = engine.index('\n    fun disassembleDex(', start)
old_prepare = engine[start:end]
new_prepare = r'''    fun prepare(
        context: Context,
        sourceUri: Uri,
        report: StaticAnalysisReport,
        preferredReportEntry: String? = null,
    ): Workspace {
        val artifactSha = report.artifact.sha256.ifBlank { sha256Uri(context, sourceUri) }
        val root = freshRoot(context, artifactSha, preferredReportEntry)
        val container = File(root, "selected-source.bin")
        context.contentResolver.openInputStream(sourceUri).use { input ->
            requireNotNull(input) { "Не удалось открыть исходный APK/APK-set" }
            FileOutputStream(container).use { output -> input.copyTo(output, COPY_BUFFER) }
        }
        require(container.length() > 0L) { "Исходный файл пуст" }
        val actualOuterSha = sha256(container)
        if (report.artifact.sha256.isNotBlank()) {
            require(actualOuterSha.equals(report.artifact.sha256, ignoreCase = true)) {
                "Выбранный файл не совпадает с проанализированным артефактом: SHA-256 отличается"
            }
        }
        val nested = NestedApkSet.extract(container, File(root, "apkset"))
        return if (nested != null) {
            val selected = nested.selectForReportEntry(preferredReportEntry)
            prepareCopiedApk(root, selected.file, report, selected.prefix, artifactSha)
        } else {
            prepareCopiedApk(root, container, report, null, actualOuterSha, sourceAlreadyInsideRoot = true)
        }
    }

    fun prepareInstalled(
        context: Context,
        app: InstalledAppDescriptor,
        report: StaticAnalysisReport,
        preferredReportEntry: String? = null,
    ): Workspace {
        require(report.artifact.sourceKind == "INSTALLED_APP") { "Отчёт не относится к установленному приложению" }
        require(report.artifact.sourcePackageName == null || report.artifact.sourcePackageName == app.packageName) {
            "Выбранный установленный пакет не совпадает с отчётом"
        }
        val prefix = preferredReportEntry?.substringBefore("!/", missingDelimiterValue = "")
        val selected: Pair<File, String> = if (prefix != null && prefix.startsWith("split:")) {
            val leaf = prefix.removePrefix("split:")
            val file = app.splitApkPaths.map(::File).firstOrNull { it.name == leaf }
                ?: error("Split APK из отчёта больше не установлен: $leaf")
            file to "split:${file.name}"
        } else {
            File(app.baseApkPath) to "base.apk"
        }
        require(selected.first.isFile && selected.first.canRead()) { "APK установленного приложения недоступен" }
        val artifactSha = report.artifact.sha256.ifBlank { sha256(selected.first) }
        val root = freshRoot(context, artifactSha, selected.second)
        return prepareCopiedApk(root, selected.first, report, selected.second, artifactSha)
    }

    private fun freshRoot(context: Context, artifactSha: String, discriminator: String?): File {
        val suffix = discriminator?.let { "-${sha256Text(it).take(8)}" }.orEmpty()
        return File(context.cacheDir, "patchlab/${artifactSha.take(24)}$suffix").apply {
            deleteRecursively()
            require(mkdirs() || isDirectory) { "Не удалось создать Patch Lab workspace" }
        }
    }

    private fun prepareCopiedApk(
        root: File,
        source: File,
        report: StaticAnalysisReport,
        sourcePrefix: String?,
        artifactSha: String,
        sourceAlreadyInsideRoot: Boolean = false,
    ): Workspace {
        val original = if (sourceAlreadyInsideRoot) source else File(root, "original.apk").also { destination ->
            source.inputStream().buffered(COPY_BUFFER).use { input ->
                destination.outputStream().buffered(COPY_BUFFER).use { output -> input.copyTo(output, COPY_BUFFER) }
            }
        }
        require(original.length() > 0L) { "Исходный APK пуст" }
        val entries = mutableListOf<String>()
        val dex = mutableListOf<String>()
        val native = mutableListOf<String>()
        ZipFile(original).use { zip ->
            val sequence = zip.entries()
            while (sequence.hasMoreElements()) {
                val entry = sequence.nextElement()
                if (entry.isDirectory) continue
                val display = displayEntry(sourcePrefix, entry.name)
                entries += display
                if (DEX_ENTRY.matches(entry.name.substringAfterLast('/'))) dex += display
                if (entry.name.lowercase(Locale.ROOT).endsWith(".so")) native += display
            }
        }
        require(dex.isNotEmpty() || native.isNotEmpty() || entries.isNotEmpty()) { "APK не содержит анализируемых entry" }
        return Workspace(
            root = root,
            originalApk = original,
            artifactSha256 = artifactSha,
            apiLevel = (report.manifest?.targetSdk ?: 35).coerceIn(15, 36),
            minSdk = (report.manifest?.minSdk ?: 26).coerceAtLeast(1),
            dexEntries = dex.sortedWith(compareBy(::dexOrdinal)),
            nativeEntries = native.sorted(),
            archiveEntries = entries.sorted(),
            sourcePrefix = sourcePrefix,
        )
    }
'''
engine = engine[:start] + new_prepare + engine[end:]
engine = replace_once(engine, 'val entry = requireNotNull(zip.getEntry(dexEntry)) { "DEX отсутствует в исходном APK: $dexEntry" }', 'val rawDexEntry = rawEntryName(workspace, dexEntry)\n                val entry = requireNotNull(zip.getEntry(rawDexEntry)) { "DEX отсутствует в исходном APK: $dexEntry" }', "raw dex lookup")
engine = replace_once(engine, 'val entry = requireNotNull(zip.getEntry(entryName)) { "Файл не найден в APK: $entryName" }', 'val rawName = rawEntryName(workspace, entryName)\n            val entry = requireNotNull(zip.getEntry(rawName)) { "Файл не найден в APK: $entryName" }', "raw text lookup")
engine = replace_once(engine, '        val apkDiff = ApkMutationDiffEngine.compare(workspace.originalApk, signed, changedEntries)', '        val apkDiff = ApkMutationDiffEngine.compare(workspace.originalApk, signed, changedEntries.map { rawEntryName(workspace, it) })', "diff raw expected")
engine = replace_once(engine, '''                    val name = originalEntry.name
                    if (isSignatureEntry(name)) continue
                    val replacement = rebuiltDex[name] ?: workspace.replacements[name]
''', '''                    val name = originalEntry.name
                    if (isSignatureEntry(name)) continue
                    val displayName = displayEntry(workspace.sourcePrefix, name)
                    val replacement = rebuiltDex[displayName] ?: workspace.replacements[displayName]
''', "repack display lookup")
anchor = '    private fun safeEntryName(value: String): String = value.replace(\'/\', \'_\').replace(\'\\\\\', \'_\')\n\n'
helpers = '''    private fun displayEntry(prefix: String?, rawName: String): String =
        if (prefix.isNullOrBlank()) rawName else "$prefix!/$rawName"

    private fun rawEntryName(workspace: Workspace, displayName: String): String {
        val prefix = workspace.sourcePrefix ?: return displayName
        val marker = "$prefix!/"
        require(displayName.startsWith(marker)) { "Entry относится к другому APK в наборе: $displayName" }
        return displayName.removePrefix(marker)
    }

'''
engine = replace_once(engine, anchor, anchor + helpers, "entry helper insertion")
write("app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt", engine)

# PatchLab UI keeps installed source and switches base/split automatically when a report target belongs elsewhere.
screen = read("app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt")
screen = replace_once(screen, 'import org.unirevlab.security.model.Finding\nimport org.unirevlab.security.model.StaticAnalysisReport', 'import org.unirevlab.security.model.Finding\nimport org.unirevlab.security.model.InstalledAppDescriptor\nimport org.unirevlab.security.model.StaticAnalysisReport', "screen installed import")
screen = replace_once(screen, '    initialSourceUri: Uri?,\n    onBack:', '    initialSourceUri: Uri?,\n    initialInstalledApp: InstalledAppDescriptor?,\n    onBack:', "screen installed param")
screen = replace_once(screen, '    var sourceUri by remember(report.artifact.sha256) { mutableStateOf(initialSourceUri) }\n', '    var sourceUri by remember(report.artifact.sha256) { mutableStateOf(initialSourceUri) }\n    var sourceInstalledApp by remember(report.artifact.sha256) { mutableStateOf(initialInstalledApp) }\n', "screen installed state")
screen = replace_once(screen, '            sourceUri = uri\n            workspace = null', '            sourceUri = uri\n            sourceInstalledApp = null\n            workspace = null', "manual picker clears installed")
old_prepare_ui = '''    fun prepareWorkspace() {
        val uri = sourceUri ?: return
        scope.launch {
            busy = true
            error = null
            status = "Копирование и проверка исходного APK…"
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.prepare(context, uri, report) } }
'''
new_prepare_ui = '''    fun prepareWorkspace() {
        val uri = sourceUri
        val installed = sourceInstalledApp
        if (uri == null && installed == null) return
        scope.launch {
            busy = true
            error = null
            status = if (installed != null) "Готовим base/split APK установленного приложения…" else "Копирование и проверка исходного APK/APK-set…"
            val preferred = initialTarget?.dexEntry ?: initialTarget?.nativeEntry
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    if (installed != null) PatchLabEngine.prepareInstalled(context, installed, report, preferred)
                    else PatchLabEngine.prepare(context, requireNotNull(uri), report, preferred)
                }
            }
'''
screen = replace_once(screen, old_prepare_ui, new_prepare_ui, "prepare workspace source set")
# Insert helper before disassembleCurrentDex.
marker = '    fun disassembleCurrentDex() {\n'
helper = '''    suspend fun workspaceForReportEntry(reportEntry: String): PatchLabEngine.Workspace {
        val current = workspace
        if (current != null && (reportEntry in current.dexEntries || reportEntry in current.archiveEntries || reportEntry in current.nativeEntries)) return current
        val installed = sourceInstalledApp
        val uri = sourceUri
        return withContext(Dispatchers.IO) {
            if (installed != null) PatchLabEngine.prepareInstalled(context, installed, report, reportEntry)
            else if (uri != null) PatchLabEngine.prepare(context, uri, report, reportEntry)
            else error("Источник анализа недоступен")
        }
    }

'''
screen = replace_once(screen, marker, helper + marker, "workspace switch helper")
# Disassembly auto-switches to the correct source APK.
old_dis = '''    fun disassembleCurrentDex() {
        val ws = workspace ?: return
        val dex = selectedDex ?: return
        scope.launch {
            busy = true
            error = null
            status = "baksmali: разбор $dex…"
            val result = runCatching { withContext(Dispatchers.IO) { PatchLabEngine.disassembleDex(ws, dex) } }
            result.getOrNull()?.let { list ->
                classes = list
'''
new_dis = '''    fun disassembleCurrentDex() {
        val dex = selectedDex ?: return
        scope.launch {
            busy = true
            error = null
            status = "baksmali: разбор $dex…"
            val result = runCatching {
                val targetWs = workspaceForReportEntry(dex)
                val list = withContext(Dispatchers.IO) { PatchLabEngine.disassembleDex(targetWs, dex) }
                targetWs to list
            }
            result.getOrNull()?.let { (targetWs, list) ->
                workspace = targetWs
                classes = list
'''
screen = replace_once(screen, old_dis, new_dis, "auto switch disassembly")
# Opening a tamper target also switches source APK.
old_open = '''        val ws = workspace ?: return
        val dex = item.dexEntry ?: return
        val cls = item.classDescriptor ?: return
        scope.launch {
'''
new_open = '''        val dex = item.dexEntry ?: return
        val cls = item.classDescriptor ?: return
        scope.launch {
'''
screen = replace_once(screen, old_open, new_open, "open target ws removal")
screen = replace_once(screen, '''                withContext(Dispatchers.IO) {
                    val list = PatchLabEngine.disassembleDex(ws, dex)
                    val text = PatchLabEngine.loadClass(ws, dex, cls)
                    list to text
                }
            }
            result.getOrNull()?.let { (list, text) ->
                selectedDex = dex
''', '''                val targetWs = workspaceForReportEntry(dex)
                withContext(Dispatchers.IO) {
                    val list = PatchLabEngine.disassembleDex(targetWs, dex)
                    val text = PatchLabEngine.loadClass(targetWs, dex, cls)
                    Triple(targetWs, list, text)
                }
            }
            result.getOrNull()?.let { (targetWs, list, text) ->
                workspace = targetWs
                selectedDex = dex
''', "open target switch")
# Trace hook source switch.
screen = replace_once(screen, '        val ws = workspace ?: return\n        scope.launch {\n            busy = true\n            error = null\n            built = null\n            status = "Генерируем trace hook:', '        scope.launch {\n            busy = true\n            error = null\n            built = null\n            status = "Генерируем trace hook:', "hook ws removal")
screen = replace_once(screen, '''                withContext(Dispatchers.IO) {
                    val list = PatchLabEngine.disassembleDex(ws, proposal.dexEntry)
                    val before = PatchLabEngine.loadClass(ws, proposal.dexEntry, proposal.classDescriptor)
                    val after = PatchLabEngine.addEntryLogHook(before, proposal.methodName, proposal.prototype, "auto:${proposal.category}")
                    PatchLabEngine.saveClass(ws, proposal.dexEntry, proposal.classDescriptor, after)
                    list to after
                }
            }
            result.getOrNull()?.let { (list, after) ->
                selectedDex = proposal.dexEntry
''', '''                val targetWs = workspaceForReportEntry(proposal.dexEntry)
                withContext(Dispatchers.IO) {
                    val list = PatchLabEngine.disassembleDex(targetWs, proposal.dexEntry)
                    val before = PatchLabEngine.loadClass(targetWs, proposal.dexEntry, proposal.classDescriptor)
                    val after = PatchLabEngine.addEntryLogHook(before, proposal.methodName, proposal.prototype, "auto:${proposal.category}")
                    PatchLabEngine.saveClass(targetWs, proposal.dexEntry, proposal.classDescriptor, after)
                    Triple(targetWs, list, after)
                }
            }
            result.getOrNull()?.let { (targetWs, list, after) ->
                workspace = targetWs
                selectedDex = proposal.dexEntry
''', "hook target switch")
# Source UI and prepare enablement.
screen = replace_once(screen, '            Text(sourceUri?.lastPathSegment ?: "APK не выбран", style = MaterialTheme.typography.bodySmall)', '            Text(sourceInstalledApp?.let { "Установлено: ${it.label} (${it.packageName}) · APK: ${it.apkCount}" } ?: sourceUri?.lastPathSegment ?: "APK не выбран", style = MaterialTheme.typography.bodySmall)')
screen = replace_once(screen, '            ) { Text(if (sourceUri == null) "Выбрать исходный APK" else "Выбрать другой APK") }\n            Button(onClick = ::prepareWorkspace, enabled = sourceUri != null && !busy, modifier = Modifier.fillMaxWidth()) {', '            ) { Text(if (sourceUri == null && sourceInstalledApp == null) "Выбрать исходный APK" else "Выбрать другой APK/APK-set") }\n            Button(onClick = ::prepareWorkspace, enabled = (sourceUri != null || sourceInstalledApp != null) && !busy, modifier = Modifier.fillMaxWidth()) {')
# DEX picker can expose every DEX reported across base + splits; selecting another one is resolved lazily.
screen = replace_once(screen, '            workspace?.let { ws ->\n                HorizontalDivider()', '            workspace?.let { ws ->\n                val reportDexEntries = remember(report, ws.sourcePrefix) {\n                    (report.dex?.methods.orEmpty().map { it.dexEntry } + report.dex?.codeMethods.orEmpty().map { it.dexEntry })\n                        .distinct().sortedWith(compareBy { it })\n                        .ifEmpty { ws.dexEntries }\n                }\n                HorizontalDivider()')
screen = replace_once(screen, '                            enabled = ws.dexEntries.isNotEmpty() && !busy,\n                            modifier = Modifier.fillMaxWidth(),\n                        ) { Text("Выбрать DEX (${ws.dexEntries.size})") }', '                            enabled = reportDexEntries.isNotEmpty() && !busy,\n                            modifier = Modifier.fillMaxWidth(),\n                        ) { Text("Выбрать DEX (${reportDexEntries.size})") }')
screen = replace_once(screen, '                        items = ws.dexEntries,', '                        items = reportDexEntries,')
write("app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt", screen)

print("v0.25.8 APK-set/source patch applied")
