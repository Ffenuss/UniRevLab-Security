#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text:
        print(f"already patched: {rel}")
        return
    if old not in text:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing:\n{old[:900]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


engine_rel = "app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt"
replace_once(engine_rel, "import java.io.InputStream\n", "import java.io.InputStream\nimport java.io.OutputStream\n")

replace_once(
    engine_rel,
    '''    fun replaceArchiveEntry(workspace: Workspace, entryName: String, replacement: File) {\n        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }\n        require(replacement.isFile) { "Файл замены не найден" }\n        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.bin").apply { parentFile?.mkdirs() }\n        replacement.inputStream().use { input -> stored.outputStream().use { output -> input.copyTo(output, COPY_BUFFER) } }\n        workspace.replacements[entryName] = stored\n    }\n''',
    '''    fun replaceArchiveEntry(workspace: Workspace, entryName: String, replacement: File) {\n        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }\n        require(replacement.isFile) { "Файл замены не найден" }\n        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.bin").apply { parentFile?.mkdirs() }\n        replacement.inputStream().use { input -> stored.outputStream().use { output -> input.copyTo(output, COPY_BUFFER) } }\n        require(stored.length() > 0L) { "Файл замены пуст" }\n        workspace.replacements[entryName] = stored\n    }\n\n    fun replaceArchiveEntry(context: Context, workspace: Workspace, entryName: String, replacementUri: Uri) {\n        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }\n        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.bin").apply { parentFile?.mkdirs() }\n        context.contentResolver.openInputStream(replacementUri).use { input ->\n            requireNotNull(input) { "Не удалось открыть файл замены" }\n            FileOutputStream(stored).buffered(COPY_BUFFER).use { output -> input.copyTo(output, COPY_BUFFER) }\n        }\n        require(stored.length() > 0L) { "Файл замены пуст" }\n        workspace.replacements[entryName] = stored\n    }\n''',
)

old_repack = '''    private fun repack(workspace: Workspace, rebuiltDex: Map<String, File>, outputApk: File) {\n        ZipFile(workspace.originalApk).use { source ->\n            ZipOutputStream(FileOutputStream(outputApk).buffered(COPY_BUFFER)).use { out ->\n                val entries = source.entries()\n                while (entries.hasMoreElements()) {\n                    val originalEntry = entries.nextElement()\n                    val name = originalEntry.name\n                    if (isSignatureEntry(name)) continue\n                    val replacement = rebuiltDex[name] ?: workspace.replacements[name]\n                    if (replacement != null) {\n                        val entry = ZipEntry(name).apply {\n                            time = originalEntry.time\n                            method = ZipEntry.DEFLATED\n                        }\n                        out.putNextEntry(entry)\n                        FileInputStream(replacement).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }\n                        out.closeEntry()\n                    } else {\n                        val copy = ZipEntry(originalEntry)\n                        out.putNextEntry(copy)\n                        if (!originalEntry.isDirectory) {\n                            source.getInputStream(originalEntry).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }\n                        }\n                        out.closeEntry()\n                    }\n                }\n            }\n        }\n    }\n'''
new_repack = '''    private fun repack(workspace: Workspace, rebuiltDex: Map<String, File>, outputApk: File) {\n        ZipFile(workspace.originalApk).use { source ->\n            val counting = CountingOutputStream(FileOutputStream(outputApk).buffered(COPY_BUFFER))\n            ZipOutputStream(counting).use { out ->\n                val entries = source.entries()\n                while (entries.hasMoreElements()) {\n                    val originalEntry = entries.nextElement()\n                    val name = originalEntry.name\n                    if (isSignatureEntry(name)) continue\n                    val replacement = rebuiltDex[name] ?: workspace.replacements[name]\n                    val isStoredNative = name.lowercase(Locale.ROOT).endsWith(".so") && originalEntry.method == ZipEntry.STORED\n                    if (replacement != null) {\n                        val entry = if (isStoredNative) {\n                            val size = replacement.length()\n                            ZipEntry(name).apply {\n                                time = originalEntry.time\n                                method = ZipEntry.STORED\n                                this.size = size\n                                compressedSize = size\n                                crc = crc32(replacement)\n                                extra = alignedExtra(counting.count, name, originalEntry.extra, NATIVE_ALIGNMENT)\n                            }\n                        } else {\n                            ZipEntry(name).apply {\n                                time = originalEntry.time\n                                method = ZipEntry.DEFLATED\n                            }\n                        }\n                        out.putNextEntry(entry)\n                        FileInputStream(replacement).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }\n                        out.closeEntry()\n                    } else {\n                        val copy = ZipEntry(originalEntry)\n                        if (isStoredNative) {\n                            // Modern APKs can load uncompressed native code directly from the APK. Repacking\n                            // changes every local-header offset, so preserve a 16 KiB-aligned data start.\n                            copy.extra = alignedExtra(counting.count, name, originalEntry.extra, NATIVE_ALIGNMENT)\n                        }\n                        out.putNextEntry(copy)\n                        if (!originalEntry.isDirectory) {\n                            source.getInputStream(originalEntry).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }\n                        }\n                        out.closeEntry()\n                    }\n                }\n            }\n        }\n    }\n\n    internal fun alignedExtra(currentOffset: Long, entryName: String, originalExtra: ByteArray?, alignment: Int = NATIVE_ALIGNMENT): ByteArray? {\n        require(alignment > 0 && alignment and (alignment - 1) == 0) { "alignment must be a power of two" }\n        val baseExtra = originalExtra ?: ByteArray(0)\n        val nameBytes = entryName.toByteArray(Charsets.UTF_8)\n        val baseDataOffset = currentOffset + ZIP_LOCAL_HEADER_FIXED + nameBytes.size + baseExtra.size\n        var padding = ((alignment - (baseDataOffset % alignment)) % alignment).toInt()\n        if (padding == 0) return originalExtra\n        if (padding < ZIP_EXTRA_HEADER_SIZE) padding += alignment\n        require(baseExtra.size + padding <= 0xffff) { "ZIP extra field exceeds 64 KiB while aligning $entryName" }\n        val added = ByteArray(padding)\n        added[0] = (ALIGNMENT_EXTRA_ID and 0xff).toByte()\n        added[1] = ((ALIGNMENT_EXTRA_ID ushr 8) and 0xff).toByte()\n        val payload = padding - ZIP_EXTRA_HEADER_SIZE\n        added[2] = (payload and 0xff).toByte()\n        added[3] = ((payload ushr 8) and 0xff).toByte()\n        return baseExtra + added\n    }\n\n    private fun crc32(file: File): Long {\n        val crc = java.util.zip.CRC32()\n        FileInputStream(file).buffered(COPY_BUFFER).use { input ->\n            val buffer = ByteArray(COPY_BUFFER)\n            while (true) {\n                val read = input.read(buffer)\n                if (read < 0) break\n                if (read > 0) crc.update(buffer, 0, read)\n            }\n        }\n        return crc.value\n    }\n'''
replace_once(engine_rel, old_repack, new_repack)

replace_once(
    engine_rel,
    '''    private val DEX_ENTRY = Regex("classes(?:\\\\d+)?\\\\.dex", RegexOption.IGNORE_CASE)\n    private val LOCALS = Regex("(?m)^(\\\\s*)\\\\.locals\\\\s+(\\\\d+)\\\\s*$")\n\n    private const val COPY_BUFFER = 128 * 1024\n''',
    '''    private val DEX_ENTRY = Regex("classes(?:\\\\d+)?\\\\.dex", RegexOption.IGNORE_CASE)\n    private val LOCALS = Regex("(?m)^(\\\\s*)\\\\.locals\\\\s+(\\\\d+)\\\\s*$")\n\n    private class CountingOutputStream(private val delegate: OutputStream) : OutputStream() {\n        var count: Long = 0L\n            private set\n\n        override fun write(b: Int) { delegate.write(b); count++ }\n        override fun write(b: ByteArray, off: Int, len: Int) { delegate.write(b, off, len); count += len.toLong() }\n        override fun flush() = delegate.flush()\n        override fun close() = delegate.close()\n    }\n\n    private const val COPY_BUFFER = 128 * 1024\n    internal const val NATIVE_ALIGNMENT = 16 * 1024\n    private const val ZIP_LOCAL_HEADER_FIXED = 30L\n    private const val ZIP_EXTRA_HEADER_SIZE = 4\n    private const val ALIGNMENT_EXTRA_ID = 0xFEEF\n''',
)

screen_rel = "app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt"
replace_once(
    screen_rel,
    '    var selectedPrototype by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.prototype) }\n',
    '    var selectedPrototype by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.prototype) }\n    var selectedReplacementEntry by remember(report.artifact.sha256) { mutableStateOf(initialTarget?.nativeEntry) }\n',
)

replace_once(
    screen_rel,
    '''    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->\n''',
    '''    val replacementPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->\n        val ws = workspace\n        val entry = selectedReplacementEntry\n        if (uri != null && ws != null && entry != null) {\n            scope.launch {\n                busy = true\n                error = null\n                val result = runCatching {\n                    withContext(Dispatchers.IO) { PatchLabEngine.replaceArchiveEntry(context, ws, entry, uri) }\n                }\n                if (result.isSuccess) {\n                    built = null\n                    status = "Файл замены сохранён: $entry"\n                }\n                error = result.exceptionOrNull()?.message\n                busy = false\n            }\n        }\n    }\n\n    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->\n''',
)

replace_once(
    screen_rel,
    '''                selectedPrototype = initialTarget?.prototype\n                status = "Workspace готов: DEX=${ws.dexEntries.size}, native=${ws.nativeEntries.size}."\n''',
    '''                selectedPrototype = initialTarget?.prototype\n                if (selectedReplacementEntry !in ws.archiveEntries) {\n                    selectedReplacementEntry = initialTarget?.nativeEntry?.takeIf { it in ws.archiveEntries } ?: ws.nativeEntries.firstOrNull()\n                }\n                status = "Workspace готов: DEX=${ws.dexEntries.size}, native=${ws.nativeEntries.size}."\n''',
)

replace_once(
    screen_rel,
    '''                if (ws.nativeEntries.isNotEmpty()) {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))) {\n                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {\n                            Text("Native workspace", fontWeight = FontWeight.SemiBold)\n                            Text("Найдено ELF/.so: ${ws.nativeEntries.size}. Замена .so уже поддержана engine; UI выбора replacement-файла будет следующим слоем.", style = MaterialTheme.typography.bodySmall)\n                            ws.nativeEntries.take(8).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }\n                        }\n                    }\n                }\n''',
    '''                if (ws.nativeEntries.isNotEmpty()) {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))) {\n                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {\n                            Text("Native / file replacement", fontWeight = FontWeight.SemiBold)\n                            Text("Найдено ELF/.so: ${ws.nativeEntries.size}. Несжатые .so при пересборке выравниваются на 16 KiB.", style = MaterialTheme.typography.bodySmall)\n                            ws.nativeEntries.take(20).forEach { entry ->\n                                OutlinedButton(\n                                    onClick = { selectedReplacementEntry = entry },\n                                    modifier = Modifier.fillMaxWidth(),\n                                ) {\n                                    Text(if (entry == selectedReplacementEntry) "✓ $entry" else entry)\n                                }\n                            }\n                            OutlinedTextField(\n                                value = selectedReplacementEntry.orEmpty(),\n                                onValueChange = { value -> selectedReplacementEntry = value.take(512) },\n                                modifier = Modifier.fillMaxWidth(),\n                                singleLine = true,\n                                label = { Text("Путь файла внутри APK") },\n                                supportingText = { Text("Можно указать любой существующий entry из APK, не только .so") },\n                            )\n                            Button(\n                                onClick = { replacementPicker.launch(arrayOf("*/*")) },\n                                enabled = selectedReplacementEntry in ws.archiveEntries && !busy,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text("Выбрать файл замены") }\n                            if (ws.replacements.isNotEmpty()) {\n                                Text("Запланированные замены:", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)\n                                ws.replacements.keys.sorted().forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }\n                            }\n                        }\n                    }\n                }\n''',
)

# Alignment regression test.
test_rel = "app/src/test/java/org/unirevlab/security/analysis/PatchLabEngineTest.kt"
test = read(test_rel)
if "nativeAlignmentPadsStoredSoTo16KiB" not in test:
    marker = "}\n"
    addition = '''\n    @Test\n    fun nativeAlignmentPadsStoredSoTo16KiB() {\n        val offset = 1_237L\n        val name = "lib/arm64-v8a/libsample.so"\n        val extra = PatchLabEngine.alignedExtra(offset, name, null)\n        val dataOffset = offset + 30L + name.toByteArray(Charsets.UTF_8).size + (extra?.size ?: 0)\n        assertTrue(dataOffset % PatchLabEngine.NATIVE_ALIGNMENT == 0L)\n    }\n'''
    pos = test.rfind(marker)
    if pos < 0:
        raise SystemExit("PatchLabEngineTest class terminator missing")
    test = test[:pos] + addition + test[pos:]
    write(test_rel, test)
    print(f"patched: {test_rel}")
else:
    print(f"already patched: {test_rel}")

# App version.
gradle_rel = "app/build.gradle.kts"
gradle = read(gradle_rel)
if 'versionName = "0.23.1-dev-patch-lab-native"' not in gradle:
    old = 'versionCode = 25\n        versionName = "0.23.0-dev-patch-lab"'
    new = 'versionCode = 26\n        versionName = "0.23.1-dev-patch-lab-native"'
    if old not in gradle:
        raise SystemExit("build.gradle v0.23.0 marker changed")
    write(gradle_rel, gradle.replace(old, new, 1))
    print(f"patched: {gradle_rel}")

print("v0.23.1 Patch Lab native alignment / replacement patch complete")
