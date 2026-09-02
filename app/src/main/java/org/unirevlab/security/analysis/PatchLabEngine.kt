package org.unirevlab.security.analysis

import android.content.Context
import android.net.Uri
import com.android.apksig.ApkSigner
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import org.jf.baksmali.Baksmali
import org.jf.baksmali.BaksmaliOptions
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.smali.Smali
import org.jf.smali.SmaliOptions
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.InstalledAppDescriptor
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Authorized on-device patch workspace.
 *
 * The original APK is never modified in place. A workspace contains a private copy, on-demand
 * baksmali output, explicit edited files, a rebuilt unsigned APK and a separately signed test APK.
 */
object PatchLabEngine {
    data class PatchTarget(
        val findingId: String? = null,
        val dexEntry: String? = null,
        val classDescriptor: String? = null,
        val methodName: String? = null,
        val prototype: String? = null,
        val nativeEntry: String? = null,
        val evidenceLocation: String? = null,
        val evidenceValue: String? = null,
    ) {
        val methodLabel: String?
            get() = if (classDescriptor != null && methodName != null && prototype != null) {
                "$classDescriptor->$methodName$prototype"
            } else null
    }

    data class Workspace(
        val root: File,
        val originalApk: File,
        val artifactSha256: String,
        val apiLevel: Int,
        val minSdk: Int,
        val dexEntries: List<String>,
        val nativeEntries: List<String>,
        val archiveEntries: List<String>,
        val sourcePrefix: String? = null,
        val modifiedDexEntries: MutableSet<String> = linkedSetOf(),
        val replacements: MutableMap<String, File> = linkedMapOf(),
        val smaliBaselines: MutableMap<String, String> = linkedMapOf(),
        val smaliEdits: MutableMap<String, String> = linkedMapOf(),
        val textBaselines: MutableMap<String, String> = linkedMapOf(),
        val textEdits: MutableMap<String, String> = linkedMapOf(),
    )

    data class BuildResult(
        val signedApk: File,
        val sha256: String,
        val changedEntries: List<String>,
        val apkDiff: ApkMutationDiffEngine.ApkDiffReport,
        val codeDiffs: List<ApkMutationDiffEngine.CodeDiff>,
        val signerLabel: String = "UniRevLab Patch Lab Test",
    )

    fun resolveTarget(report: StaticAnalysisReport, finding: Finding?): PatchTarget? {
        if (finding == null) return null
        val evidence = finding.evidence
        val joined = evidence.joinToString("\n") { "${it.location}\n${it.value}" }
        val dexEntry = Regex("(?:^|[!/])((?:classes(?:\\d+)?\\.dex))", RegexOption.IGNORE_CASE)
            .find(joined)?.groupValues?.getOrNull(1)
        val nativeEntry = Regex("(?:^|[!/])((?:lib/)?[^\\s!]+\\.so)", RegexOption.IGNORE_CASE)
            .find(joined)?.groupValues?.getOrNull(1)

        val directMethod = Regex("(L[^;\\s]+;)->([^\\s(]+)(\\([^\\n]*?\\)[VZBSCIJFDL\\[][^\\s:]*)")
            .find(joined)
        if (directMethod != null) {
            val targetClass = directMethod.groupValues[1]
            val targetName = directMethod.groupValues[2]
            val targetPrototype = directMethod.groupValues[3]
            val dexSummary = report.dex
            val codeKeys = dexSummary?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
            val direct = dexSummary?.methods.orEmpty().firstOrNull { method ->
                method.declaringClass == targetClass && method.name == targetName && method.prototype == targetPrototype &&
                    "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys
            }
            if (direct != null) {
                return PatchTarget(
                    findingId = finding.id, dexEntry = direct.dexEntry, classDescriptor = direct.declaringClass,
                    methodName = direct.name, prototype = direct.prototype, nativeEntry = nativeEntry,
                    evidenceLocation = evidence.firstOrNull()?.location, evidenceValue = evidence.firstOrNull()?.value,
                )
            }
            val methodsByKey = dexSummary?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
            val packagePrefix = report.manifest?.packageName?.takeIf { it.isNotBlank() }?.replace('.', '/')?.let { "L$it/" }
            val caller = dexSummary?.callXrefs.orEmpty().asSequence()
                .filter { it.calleeClass == targetClass && it.calleeName == targetName && it.calleePrototype == targetPrototype }
                .mapNotNull { xref -> methodsByKey[xref.dexEntry to xref.callerMethodIndex] }
                .filter { method -> "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys }
                .sortedByDescending { method -> packagePrefix != null && method.declaringClass.startsWith(packagePrefix) }
                .firstOrNull()
            if (caller != null) {
                return PatchTarget(
                    findingId = finding.id, dexEntry = caller.dexEntry, classDescriptor = caller.declaringClass,
                    methodName = caller.name, prototype = caller.prototype, nativeEntry = nativeEntry,
                    evidenceLocation = evidence.firstOrNull()?.location,
                    evidenceValue = "External callee: $targetClass->$targetName$targetPrototype",
                )
            }
        }

        // Findings are intentionally schema-agnostic. Fall back to the bounded DEX index and pick
        // an exact indexed method whose class/name/prototype is present in the evidence text.
        val fallbackCodeKeys = report.dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
        val method = report.dex?.methods?.firstOrNull { candidate ->
            joined.contains(candidate.declaringClass, ignoreCase = false) &&
                joined.contains(candidate.name, ignoreCase = false) &&
                joined.contains(candidate.prototype, ignoreCase = false) &&
                "${candidate.dexEntry}|${candidate.declaringClass}|${candidate.name}|${candidate.prototype}" in fallbackCodeKeys
        }
        return PatchTarget(
            findingId = finding.id,
            dexEntry = method?.dexEntry ?: dexEntry,
            classDescriptor = method?.declaringClass,
            methodName = method?.name,
            prototype = method?.prototype,
            nativeEntry = nativeEntry,
            evidenceLocation = evidence.firstOrNull()?.location,
            evidenceValue = evidence.firstOrNull()?.value,
        )
    }

    fun prepare(
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

    fun disassembleDex(workspace: Workspace, dexEntry: String): List<String> {
        require(dexEntry in workspace.dexEntries) { "Неизвестный DEX: $dexEntry" }
        val dir = smaliDir(workspace, dexEntry)
        val ready = File(dir, ".unirevlab-ready")
        if (!ready.isFile) {
            dir.deleteRecursively()
            dir.mkdirs()
            val dexFile = File(workspace.root, "dex/${safeEntryName(dexEntry)}").apply {
                parentFile?.mkdirs()
            }
            ZipFile(workspace.originalApk).use { zip ->
                val rawDexEntry = rawEntryName(workspace, dexEntry)
                val entry = requireNotNull(zip.getEntry(rawDexEntry)) { "DEX отсутствует в исходном APK: $dexEntry" }
                zip.getInputStream(entry).use { input ->
                    FileOutputStream(dexFile).use { output -> input.copyTo(output, COPY_BUFFER) }
                }
            }
            val opcodes = Opcodes.forApi(workspace.apiLevel)
            val dex = DexFileFactory.loadDexFile(dexFile, opcodes)
            val options = BaksmaliOptions().apply {
                apiLevel = workspace.apiLevel
                localsDirective = true
                parameterRegisters = true
                debugInfo = true
                codeOffsets = true
            }
            val jobs = Runtime.getRuntime().availableProcessors().coerceIn(1, 2)
            check(Baksmali.disassembleDexFile(dex, dir, jobs, options)) {
                "baksmali не смог разобрать $dexEntry"
            }
            ready.writeText("ok", Charsets.UTF_8)
        }
        return listClasses(dir)
    }

    fun loadClass(workspace: Workspace, dexEntry: String, classDescriptor: String): String {
        val file = classFile(workspace, dexEntry, classDescriptor)
        require(file.isFile) { "Smali-класс не найден: $classDescriptor" }
        require(file.length() <= MAX_EDITABLE_TEXT_BYTES) { "Smali-класс слишком большой для встроенного редактора" }
        return file.readText(Charsets.UTF_8)
    }

    fun saveClass(workspace: Workspace, dexEntry: String, classDescriptor: String, text: String) {
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_EDITABLE_TEXT_BYTES) { "Smali-класс слишком большой" }
        require(text.contains(".class")) { "В Smali отсутствует .class" }
        val file = classFile(workspace, dexEntry, classDescriptor)
        require(file.parentFile?.isDirectory == true || file.parentFile?.mkdirs() == true) { "Не удалось создать каталог Smali" }
        val key = "$dexEntry|$classDescriptor"
        if (key !in workspace.smaliBaselines && file.isFile) workspace.smaliBaselines[key] = file.readText(Charsets.UTF_8)
        file.writeText(text, Charsets.UTF_8)
        workspace.smaliEdits[key] = text
        workspace.modifiedDexEntries += dexEntry
    }

    fun addEntryLogHook(
        classText: String,
        methodName: String,
        prototype: String,
        findingId: String? = null,
    ): String {
        val range = methodRange(classText, methodName, prototype)
        val block = classText.substring(range)
        val locals = LOCALS.find(block) ?: error("Метод не содержит .locals; сначала сохраните baksmali-представление заново")
        val oldLocals = locals.groupValues[2].toInt()
        require(oldLocals <= 253) { "В методе слишком много локальных регистров для автоматического Log hook" }
        val first = oldLocals
        val second = oldLocals + 1
        val indent = locals.groupValues[1]
        val newLocalsLine = "${indent}.locals ${oldLocals + 2}"
        val hookLabel = escapeSmaliString("${findingId ?: "manual"}: $methodName$prototype")
        require(!block.contains(hookLabel)) { "Этот trace hook уже добавлен в метод" }
        val hook = buildString {
            append('\n')
            append(indent).append("const-string v").append(first).append(", \"UniRevLab\"\n")
            append(indent).append("const-string v").append(second).append(", \"").append(hookLabel).append("\"\n")
            append(indent).append("invoke-static/range {v").append(first).append(" .. v").append(second)
                .append("}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n")
        }
        val updatedBlock = block.replaceRange(locals.range, newLocalsLine + hook)
        return classText.replaceRange(range, updatedBlock)
    }

    fun forceBooleanReturn(
        classText: String,
        methodName: String,
        prototype: String,
        value: Boolean,
    ): String {
        require(prototype.endsWith(")Z")) { "Шаблон force boolean применим только к методам, возвращающим boolean" }
        val range = methodRange(classText, methodName, prototype)
        val block = classText.substring(range)
        val locals = LOCALS.find(block) ?: error("Метод не содержит .locals")
        val oldLocals = locals.groupValues[2].toInt()
        require(oldLocals <= 254) { "В методе слишком много локальных регистров" }
        val reg = oldLocals
        val indent = locals.groupValues[1]
        val newLocalsLine = "${indent}.locals ${oldLocals + 1}"
        val hook = buildString {
            append('\n')
            append(indent).append("const/16 v").append(reg).append(", ").append(if (value) "0x1" else "0x0").append('\n')
            append(indent).append("return v").append(reg).append('\n')
        }
        val updatedBlock = block.replaceRange(locals.range, newLocalsLine + hook)
        return classText.replaceRange(range, updatedBlock)
    }

    fun replaceArchiveEntry(workspace: Workspace, entryName: String, replacement: File) {
        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }
        require(replacement.isFile) { "Файл замены не найден" }
        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.bin").apply { parentFile?.mkdirs() }
        replacement.inputStream().use { input -> stored.outputStream().use { output -> input.copyTo(output, COPY_BUFFER) } }
        require(stored.length() > 0L) { "Файл замены пуст" }
        workspace.replacements[entryName] = stored
    }

    fun replaceArchiveEntry(context: Context, workspace: Workspace, entryName: String, replacementUri: Uri) {
        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }
        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.bin").apply { parentFile?.mkdirs() }
        context.contentResolver.openInputStream(replacementUri).use { input ->
            requireNotNull(input) { "Не удалось открыть файл замены" }
            FileOutputStream(stored).buffered(COPY_BUFFER).use { output -> input.copyTo(output, COPY_BUFFER) }
        }
        require(stored.length() > 0L) { "Файл замены пуст" }
        workspace.replacements[entryName] = stored
    }

    fun loadArchiveText(workspace: Workspace, entryName: String): String {
        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }
        val bytes = workspace.replacements[entryName]?.readBytes() ?: ZipFile(workspace.originalApk).use { zip ->
            val rawName = rawEntryName(workspace, entryName)
            val entry = requireNotNull(zip.getEntry(rawName)) { "Файл не найден в APK: $entryName" }
            require(entry.size < 0L || entry.size <= MAX_EDITABLE_TEXT_BYTES) { "Файл слишком большой для текстового редактора" }
            zip.getInputStream(entry).use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(32 * 1024)
                var total = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read == 0) continue
                    total += read
                    require(total <= MAX_EDITABLE_TEXT_BYTES) { "Файл слишком большой для текстового редактора" }
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            }
        }
        require(bytes.none { it == 0.toByte() }) { "Entry выглядит как бинарный файл, текстовое редактирование отключено" }
        val text = bytes.toString(Charsets.UTF_8)
        require('\uFFFD' !in text) { "Entry не является корректным UTF-8 текстом" }
        return text
    }

    fun saveArchiveText(workspace: Workspace, entryName: String, text: String) {
        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }
        val bytes = text.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_EDITABLE_TEXT_BYTES) { "Текстовый entry слишком большой" }
        if (entryName !in workspace.textBaselines) workspace.textBaselines[entryName] = loadArchiveText(workspace, entryName)
        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.txt").apply { parentFile?.mkdirs() }
        stored.writeBytes(bytes)
        workspace.replacements[entryName] = stored
        workspace.textEdits[entryName] = text
    }

    fun build(workspace: Workspace): BuildResult {
        require(workspace.modifiedDexEntries.isNotEmpty() || workspace.replacements.isNotEmpty()) {
            "Нет сохранённых изменений для сборки"
        }
        val rebuiltDex = linkedMapOf<String, File>()
        workspace.modifiedDexEntries.forEach { dexEntry ->
            val dir = smaliDir(workspace, dexEntry)
            require(File(dir, ".unirevlab-ready").isFile) { "$dexEntry ещё не разобран" }
            val output = File(workspace.root, "rebuilt/${safeEntryName(dexEntry)}").apply { parentFile?.mkdirs() }
            val options = SmaliOptions().apply {
                apiLevel = workspace.apiLevel
                jobs = Runtime.getRuntime().availableProcessors().coerceIn(1, 2)
                outputDexFile = output.absolutePath
                verboseErrors = true
            }
            check(Smali.assemble(options, listOf(dir.absolutePath))) { "smali не смог собрать $dexEntry" }
            require(output.length() > 0L) { "Собранный $dexEntry пуст" }
            rebuiltDex[dexEntry] = output
        }

        val unsigned = File(workspace.root, "output/unirevlab-patched-unsigned.apk").apply { parentFile?.mkdirs(); delete() }
        repack(workspace, rebuiltDex, unsigned)
        require(unsigned.length() > 0L) { "Пересобранный APK пуст" }

        val signed = File(workspace.root, "output/unirevlab-patched-signed.apk").apply { delete() }
        signTestApk(unsigned, signed, workspace.minSdk)
        require(signed.length() > 0L) { "Подписанный APK пуст" }
        val changedEntries = (workspace.modifiedDexEntries + workspace.replacements.keys).sorted()
        val apkDiff = ApkMutationDiffEngine.compare(workspace.originalApk, signed, changedEntries.map { rawEntryName(workspace, it) })
        require(apkDiff.unexpectedContentChanges.isEmpty()) {
            "Пересборка изменила неожиданные entry: ${apkDiff.unexpectedContentChanges.take(8).joinToString()}"
        }
        val codeDiffs = buildList {
            workspace.smaliBaselines.forEach { (key, before) ->
                val after = workspace.smaliEdits[key] ?: return@forEach
                if (before != after) add(ApkMutationDiffEngine.diffText("SMALI", key, before, after))
            }
            workspace.textBaselines.forEach { (entry, before) ->
                val after = workspace.textEdits[entry] ?: return@forEach
                if (before != after) add(ApkMutationDiffEngine.diffText("TEXT_ENTRY", entry, before, after))
            }
        }
        return BuildResult(
            signedApk = signed,
            sha256 = sha256(signed),
            changedEntries = changedEntries,
            apkDiff = apkDiff,
            codeDiffs = codeDiffs,
        )
    }

    private fun repack(workspace: Workspace, rebuiltDex: Map<String, File>, outputApk: File) {
        ZipFile(workspace.originalApk).use { source ->
            val counting = CountingOutputStream(FileOutputStream(outputApk).buffered(COPY_BUFFER))
            ZipOutputStream(counting).use { out ->
                val entries = source.entries()
                while (entries.hasMoreElements()) {
                    val originalEntry = entries.nextElement()
                    val name = originalEntry.name
                    if (isSignatureEntry(name)) continue
                    val displayName = displayEntry(workspace.sourcePrefix, name)
                    val replacement = rebuiltDex[displayName] ?: workspace.replacements[displayName]
                    val storedAlignment = requiredStoredAlignment(name, originalEntry.method, originalEntry.isDirectory)
                    if (replacement != null) {
                        // Preserve STORED vs DEFLATED semantics. In particular, resources.arsc for
                        // targetSdk >= 30 must remain uncompressed and 4-byte aligned, while modern
                        // uncompressed native libraries need 16 KiB zip alignment on 16 KiB devices.
                        val entry = if (storedAlignment != null) {
                            val size = replacement.length()
                            ZipEntry(name).apply {
                                time = originalEntry.time
                                method = ZipEntry.STORED
                                this.size = size
                                compressedSize = size
                                crc = crc32(replacement)
                                extra = alignedExtra(counting.count, name, originalEntry.extra, storedAlignment)
                            }
                        } else {
                            ZipEntry(name).apply {
                                time = originalEntry.time
                                method = ZipEntry.DEFLATED
                            }
                        }
                        out.putNextEntry(entry)
                        FileInputStream(replacement).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }
                        out.closeEntry()
                    } else {
                        val copy = ZipEntry(originalEntry)
                        if (storedAlignment != null) {
                            // ZipFile exposes the central-directory extra field, but Android build tools
                            // may put alignment padding only in the local header. Recompute it from the
                            // new local-header offset instead of assuming the old padding survived.
                            copy.extra = alignedExtra(counting.count, name, originalEntry.extra, storedAlignment)
                        }
                        out.putNextEntry(copy)
                        if (!originalEntry.isDirectory) {
                            source.getInputStream(originalEntry).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }
                        }
                        out.closeEntry()
                    }
                }
            }
        }
    }

    internal fun requiredStoredAlignment(entryName: String, method: Int, isDirectory: Boolean = false): Int? {
        if (isDirectory || method != ZipEntry.STORED) return null
        return if (entryName.lowercase(Locale.ROOT).endsWith(".so")) NATIVE_ALIGNMENT else APK_ALIGNMENT
    }

    internal fun alignedExtra(currentOffset: Long, entryName: String, originalExtra: ByteArray?, alignment: Int = NATIVE_ALIGNMENT): ByteArray? {
        require(alignment > 0 && alignment and (alignment - 1) == 0) { "alignment must be a power of two" }
        val baseExtra = originalExtra ?: ByteArray(0)
        val nameBytes = entryName.toByteArray(Charsets.UTF_8)
        val baseDataOffset = currentOffset + ZIP_LOCAL_HEADER_FIXED + nameBytes.size + baseExtra.size
        var padding = ((alignment - (baseDataOffset % alignment)) % alignment).toInt()
        if (padding == 0) return originalExtra
        if (padding < ZIP_EXTRA_HEADER_SIZE) padding += alignment
        require(baseExtra.size + padding <= 0xffff) { "ZIP extra field exceeds 64 KiB while aligning $entryName" }
        val added = ByteArray(padding)
        added[0] = (ALIGNMENT_EXTRA_ID and 0xff).toByte()
        added[1] = ((ALIGNMENT_EXTRA_ID ushr 8) and 0xff).toByte()
        val payload = padding - ZIP_EXTRA_HEADER_SIZE
        added[2] = (payload and 0xff).toByte()
        added[3] = ((payload ushr 8) and 0xff).toByte()
        return baseExtra + added
    }

    private fun crc32(file: File): Long {
        val crc = java.util.zip.CRC32()
        FileInputStream(file).buffered(COPY_BUFFER).use { input ->
            val buffer = ByteArray(COPY_BUFFER)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) crc.update(buffer, 0, read)
            }
        }
        return crc.value
    }

    private fun signTestApk(input: File, output: File, minSdk: Int) {
        val signer = ApkSigner.SignerConfig.Builder(
            "UNIREVLAB",
            testPrivateKey(),
            listOf(testCertificate()),
        ).build()
        ApkSigner.Builder(listOf(signer))
            .setInputApk(input)
            .setOutputApk(output)
            .setOtherSignersSignaturesPreserved(false)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setMinSdkVersion(minSdk)
            .build()
            .sign()
    }

    private fun testPrivateKey(): PrivateKey {
        val bytes = Base64.getDecoder().decode(TEST_KEY_PKCS8_BASE64)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(bytes))
    }

    private fun testCertificate(): X509Certificate {
        val bytes = Base64.getDecoder().decode(TEST_CERT_DER_BASE64)
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as X509Certificate
    }

    private fun methodRange(text: String, methodName: String, prototype: String): IntRange {
        val header = Regex("(?m)^\\.method[^\\n]*\\s${Regex.escape(methodName)}${Regex.escape(prototype)}\\s*$")
            .find(text) ?: error("Метод $methodName$prototype не найден в Smali-классе")
        val end = Regex("(?m)^\\.end method\\s*$").find(text, header.range.last + 1)
            ?: error("У метода $methodName$prototype нет .end method")
        return header.range.first..end.range.last
    }

    private fun classFile(workspace: Workspace, dexEntry: String, descriptor: String): File {
        require(descriptor.startsWith('L') && descriptor.endsWith(';')) { "Некорректный class descriptor" }
        val relative = descriptor.substring(1, descriptor.length - 1) + ".smali"
        return File(smaliDir(workspace, dexEntry), relative)
    }

    private fun smaliDir(workspace: Workspace, dexEntry: String): File =
        File(workspace.root, "smali/${safeEntryName(dexEntry).removeSuffix(".dex")}")

    private fun listClasses(dir: File): List<String> = dir.walkTopDown()
        .filter { it.isFile && it.extension == "smali" }
        .map { file ->
            val rel = file.relativeTo(dir).invariantSeparatorsPath.removeSuffix(".smali")
            "L$rel;"
        }
        .sorted()
        .toList()

    private fun safeEntryName(value: String): String = value.replace('/', '_').replace('\\', '_')

    private fun displayEntry(prefix: String?, rawName: String): String =
        if (prefix.isNullOrBlank()) rawName else "$prefix!/$rawName"

    private fun rawEntryName(workspace: Workspace, displayName: String): String {
        val prefix = workspace.sourcePrefix ?: return displayName
        val marker = "$prefix!/"
        require(displayName.startsWith(marker)) { "Entry относится к другому APK в наборе: $displayName" }
        return displayName.removePrefix(marker)
    }

    private fun dexOrdinal(value: String): Int {
        val name = value.substringAfterLast('/')
        if (name == "classes.dex") return 1
        return Regex("classes(\\d+)\\.dex").matchEntire(name)?.groupValues?.get(1)?.toIntOrNull() ?: Int.MAX_VALUE
    }

    private fun isSignatureEntry(name: String): Boolean {
        val upper = name.uppercase(Locale.ROOT)
        if (!upper.startsWith("META-INF/")) return false
        val leaf = upper.substringAfterLast('/')
        return leaf == "MANIFEST.MF" || leaf.endsWith(".SF") || leaf.endsWith(".RSA") || leaf.endsWith(".DSA") || leaf.endsWith(".EC")
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).buffered(COPY_BUFFER).use { input ->
            val buffer = ByteArray(COPY_BUFFER)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sha256Uri(context: Context, uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")
        context.contentResolver.openInputStream(uri).use { raw ->
            val input = BufferedInputStream(requireNotNull(raw), COPY_BUFFER)
            val buffer = ByteArray(COPY_BUFFER)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sha256Text(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun escapeSmaliString(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .take(220)

    private val DEX_ENTRY = Regex("classes(?:\\d+)?\\.dex", RegexOption.IGNORE_CASE)
    private val LOCALS = Regex("(?m)^(\\s*)\\.locals\\s+(\\d+)\\s*$")

    private class CountingOutputStream(private val delegate: OutputStream) : OutputStream() {
        var count: Long = 0L
            private set

        override fun write(b: Int) { delegate.write(b); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { delegate.write(b, off, len); count += len.toLong() }
        override fun flush() = delegate.flush()
        override fun close() = delegate.close()
    }

    private const val COPY_BUFFER = 128 * 1024
    internal const val APK_ALIGNMENT = 4
    internal const val NATIVE_ALIGNMENT = 16 * 1024
    private const val ZIP_LOCAL_HEADER_FIXED = 30L
    private const val ZIP_EXTRA_HEADER_SIZE = 4
    private const val ALIGNMENT_EXTRA_ID = 0xFEEF
    private const val MAX_EDITABLE_TEXT_BYTES = 4L * 1024L * 1024L

    // Fixed non-secret laboratory signer. It intentionally does not impersonate the original APK
    // signer and exists only so an explicitly modified build can be installed for authorized tests.
    private const val TEST_KEY_PKCS8_BASE64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCokD1mtAQTYTFzury/pFfMtQ5KFFhDEvOfH2AoQEunUN4IiSr6cWbKcxziEfwxmOYxDKCCMoDHSVkju3PD63LX6Ixkvhyqv8EzWW9K94H3t0cFmVR53pDW9DvmHdAL/ssTV0qdVlLMw/m4iHhBRqV2GoEqsolrLuPqGQJNU7aDqseDjz2LSa7Aj6SpzoUoIPgjTp/r3ve1DAViWCXXHKZcK8PwlqLy3Uvq7mdQTwxXk4Yv3Q2sLX17oRZuIlEBtfOkNIFHFSV4LN+rldAGdcupow1Ime6x1rlAMk9SirMe5o3u4TI7qLXciGM+ZmIF96FBi+KRK/lYreqtFi7knqI5AgMBAAECggEAAWWkpKJu+uF41p6LFu7b7W3ouZNz7Hu5Oi3j5EwtdFcMEre0UVFkSomWs9xLTKFESHl0JnAYYiPI/INUC8vP7rCA4rWH/kr1j8vjdhRuvCiwNYCA/eZAKWU/zoHxFKW0ICu+ihGflmPfa3icv98VMFE66ymB+w9EmKREFnOlqm9Z+DojOLlSSnlOOo7WxtGNo6DzU43zuXdseOCf/DPUiJHI7jQNyylymHbnGIOEjJhI2mpRVNHtnFczJPJqFJfOfieTd6JtpUG1GztgR6jqpL3cMeWTjq4XKQHha68mqMS2CpiW3L2zklwUlj19vhOzTmvnUppLUaP8C1EEUn66QwKBgQDXUZxBtSodeA2oRuKqoRKrroidO5lPSvH+lxWJjwdagbx4rLLX/jq69e146OgyiC9QJlVz9YVUCWUEVOgNgf97GNZ9Whl3zVmUAP7NC8V1RKjn1qQuiyHK3zgwK66r1qeHAIV9Gs2bjkbCF7Y4GLU/2pj8b1QZbTqzhMwcUd042wKBgQDIaTLy8mGzeJ1OEOGkLJDfGt45wD507EVCRdVo6Vu5euxFEK51J2w+hOlCQglEHbUQtaJtbInzv0380gg2nOif/uJlY0CsAlKdJy5gC8yNOj5Hzup19MG7Wkfr+++9e0mQaK4gvt8yeIYm2iRZk1gxvgrSGTndmArPzG8BSUlDewKBgA+sxkZWTPmWOtBMUMYBMd3Dt/hSVWfbWeCh2RSJkAx7s1/Jmr90p4viyWXq9rRvC5q3H7NwZUNn5624DKinFRU+CqdXftEk5ueKZwJAYCCYXf96tbsZr90YAPwowe+KkemXFSC1adBwPCB3H3HYAqHiZQ7DgAjV1dcpzL4nC4bPAoGBAK4xGdKmsBrxVDDdZXJwNf9leBBUMzUng89lqWeFpW8jE6e4Jxq3CFOS7Lflc+5br9x1M1fOxl0xQ1TjLbZiTaN7REaBrV2Uqz/jJWDgAIwkOqvpgkrCUX1JrEfF9AwK09cL1YWqwY85yMiORJgDBN4/Y2JYAL7Ff2g8NaO1klNvAoGAS4DfQhy5tJLjZ55obA1VXzw4+LXTKRmrYBCnqXfNU8MjR3SjI7/99TMBaEEJep23yog0iaRELy9qJfzqiHrxworM6coCskO58/mUR7lBTcwFnVnmvZOxcpe+Eslh3LY/LKG5C/7/IGqwzjL+F1pNjY4tG/LNLJHwMeh+nqphdl0="
    private const val TEST_CERT_DER_BASE64 = "MIIDaTCCAlGgAwIBAgIUUIaRs1uQiI5YOzbXh3g18RDeluAwDQYJKoZIhvcNAQELBQAwRDEhMB8GA1UEAwwYVW5pUmV2TGFiIFBhdGNoIExhYiBUZXN0MRIwEAYDVQQKDAlVbmlSZXZMYWIxCzAJBgNVBAYTAkRFMB4XDTI2MDgzMTEwMjY0M1oXDTM2MDgyODEwMjY0M1owRDEhMB8GA1UEAwwYVW5pUmV2TGFiIFBhdGNoIExhYiBUZXN0MRIwEAYDVQQKDAlVbmlSZXZMYWIxCzAJBgNVBAYTAkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA9ZrQEE2Exc7q8v6RXzLUOShRYQxLznx9gKEBLp1DeCIkq+nFmynMc4hH8MZjmMQyggjKAx0lZI7tzw+ty1+iMZL4cqr/BM1lvSveB97dHBZlUed6Q1vQ75h3QC/7LE1dKnVZSzMP5uIh4QUaldhqBKrKJay7j6hkCTVO2g6rHg489i0muwI+kqc6FKCD4I06f6973tQwFYlgl1xymXCvD8Jai8t1L6u5nUE8MV5OGL90NrC19e6EWbiJRAbXzpDSBRxUleCzfq5XQBnXLqaMNSJnusda5QDJPUoqzHuaN7uEyO6i13IhjPmZiBfehQYvikSv5WK3qrRYu5J6iOQIDAQABo1MwUTAdBgNVHQ4EFgQUBWV89a90LBSMvywf61f3K5YK1SIwHwYDVR0jBBgwFoAUBWV89a90LBSMvywf61f3K5YK1SIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFU8mAXoL1onaikEr5Yid3xoH4qcOpmVYa43b9Gvx3UQaXdbMYjqxRxXv5pCSSrnDZVMaM1T9u6X+XDkwogk93tftqfdcxrvS7uZHmlP4XxZUOZXUY4dvB5w1AArESI/UacuM14rwS0UrdNF/tgcwhmVswFW3lpMOKr6204pUP61lREs6NYfL1EuDTScU8Z3KGoBtkQ0UkAWDgUFwHYoMieyDFXCGnZPyTT/sv3TF8SHwHptm13YmKBS8kZm4RgOi1bAHIevn1U6f+MrCVwkoIzSxKR4FpOOb6EI0zSh6ygaBCxXqM5t5LmzpMOiDzivKf743CZykVWPegzEKDm8GAw=="
}
