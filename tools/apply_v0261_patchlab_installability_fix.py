from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt"
TEST = ROOT / "app/src/test/java/org/unirevlab/security/analysis/PatchLabEngineTest.kt"
AUTOMOD = ROOT / "app/src/main/java/org/unirevlab/security/ui/AutoModPanel.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


engine = ENGINE.read_text(encoding="utf-8")
if "internal const val APK_ALIGNMENT = 4" not in engine:
    old = '''                    val replacement = rebuiltDex[displayName] ?: workspace.replacements[displayName]
                    val isStoredNative = name.lowercase(Locale.ROOT).endsWith(".so") && originalEntry.method == ZipEntry.STORED
                    if (replacement != null) {
                        val entry = if (isStoredNative) {
                            val size = replacement.length()
                            ZipEntry(name).apply {
                                time = originalEntry.time
                                method = ZipEntry.STORED
                                this.size = size
                                compressedSize = size
                                crc = crc32(replacement)
                                extra = alignedExtra(counting.count, name, originalEntry.extra, NATIVE_ALIGNMENT)
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
                        if (isStoredNative) {
                            // Modern APKs can load uncompressed native code directly from the APK. Repacking
                            // changes every local-header offset, so preserve a 16 KiB-aligned data start.
                            copy.extra = alignedExtra(counting.count, name, originalEntry.extra, NATIVE_ALIGNMENT)
                        }
                        out.putNextEntry(copy)
                        if (!originalEntry.isDirectory) {
                            source.getInputStream(originalEntry).buffered(COPY_BUFFER).use { it.copyTo(out, COPY_BUFFER) }
                        }
                        out.closeEntry()
                    }
'''
    new = '''                    val replacement = rebuiltDex[displayName] ?: workspace.replacements[displayName]
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
'''
    engine = replace_once(engine, old, new, "repack stored-entry alignment")

    anchor = '''    internal fun alignedExtra(currentOffset: Long, entryName: String, originalExtra: ByteArray?, alignment: Int = NATIVE_ALIGNMENT): ByteArray? {
'''
    helper = '''    internal fun requiredStoredAlignment(entryName: String, method: Int, isDirectory: Boolean = false): Int? {
        if (isDirectory || method != ZipEntry.STORED) return null
        return if (entryName.lowercase(Locale.ROOT).endsWith(".so")) NATIVE_ALIGNMENT else APK_ALIGNMENT
    }

'''
    engine = replace_once(engine, anchor, helper + anchor, "stored alignment helper")
    engine = replace_once(
        engine,
        "    internal const val NATIVE_ALIGNMENT = 16 * 1024\n",
        "    internal const val APK_ALIGNMENT = 4\n    internal const val NATIVE_ALIGNMENT = 16 * 1024\n",
        "apk alignment constant",
    )
    ENGINE.write_text(engine, encoding="utf-8")


test = TEST.read_text(encoding="utf-8")
if "resourcesArscUsesFourByteStoredAlignment" not in test:
    anchor = '''    @Test
    fun nativeAlignmentPadsStoredSoTo16KiB() {
'''
    new_test = '''    @Test
    fun resourcesArscUsesFourByteStoredAlignment() {
        val alignment = PatchLabEngine.requiredStoredAlignment("resources.arsc", java.util.zip.ZipEntry.STORED)
        assertTrue(alignment == PatchLabEngine.APK_ALIGNMENT)

        val offset = 1_001L
        val name = "resources.arsc"
        val extra = PatchLabEngine.alignedExtra(offset, name, null, requireNotNull(alignment))
        val dataOffset = offset + 30L + name.toByteArray(Charsets.UTF_8).size + (extra?.size ?: 0)
        assertTrue(dataOffset % PatchLabEngine.APK_ALIGNMENT == 0L)
    }

    @Test
    fun compressedEntriesDoNotReceiveStoredAlignment() {
        val alignment = PatchLabEngine.requiredStoredAlignment("classes.dex", java.util.zip.ZipEntry.DEFLATED)
        assertTrue(alignment == null)
    }

'''
    test = replace_once(test, anchor, new_test + anchor, "Patch Lab alignment regression tests")
    TEST.write_text(test, encoding="utf-8")


automod = AUTOMOD.read_text(encoding="utf-8")
if "AutoMod: план применён; собираем DEX" not in automod:
    old = '''                            onStatus("AutoMod: применяем проверенный план → Smali → DEX → APK → тестовая подпись…")
                            val result = runCatching {
                                withContext(Dispatchers.IO) {
                                    AutoModEngine.apply(workspace, current, rightsConfirmed)
                                    PatchLabEngine.build(workspace)
                                }
                            }
                            result.getOrNull()?.let {
                                built = it
                                onStatus("AutoMod Demo готов: ${current.actions.size} точечных изменений, APK собран и подписан тестовым ключом.")
                            }
'''
    new = '''                            val startedAtMs = android.os.SystemClock.elapsedRealtime()
                            onStatus("AutoMod: применяем проверенный план к подготовленному Smali…")
                            val result = runCatching {
                                withContext(Dispatchers.IO) {
                                    AutoModEngine.apply(workspace, current, rightsConfirmed)
                                }
                                onStatus("AutoMod: план применён; собираем DEX → APK → ZIP alignment → тестовая подпись…")
                                withContext(Dispatchers.IO) {
                                    PatchLabEngine.build(workspace)
                                }
                            }
                            result.getOrNull()?.let {
                                built = it
                                val elapsedMs = android.os.SystemClock.elapsedRealtime() - startedAtMs
                                onStatus("AutoMod Demo готов за ${elapsedMs} мс: ${current.actions.size} точечных изменений, APK пересобран, выровнен и подписан тестовым ключом.")
                            }
'''
    automod = replace_once(automod, old, new, "AutoMod build stages and timing")

    old_install = '''                        runCatching {
                            val uri = FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                result.signedApk,
                            )
                            val intent = Intent(Intent.ACTION_VIEW)
                                .setDataAndType(uri, "application/vnd.android.package-archive")
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        }.onFailure { onError(it.message) }
'''
    new_install = '''                        runCatching {
                            if (!context.packageManager.canRequestPackageInstalls()) {
                                val settings = Intent(
                                    android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    android.net.Uri.parse("package:${context.packageName}"),
                                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                context.startActivity(settings)
                                onStatus("Разрешите установку приложений из UniRevLab, затем нажмите кнопку установки ещё раз.")
                                return@runCatching
                            }
                            val parsed = context.packageManager.getPackageArchiveInfo(result.signedApk.absolutePath, 0)
                            requireNotNull(parsed) { "Android PackageManager не распознаёт собранный APK" }
                            report.manifest?.packageName?.takeIf { it.isNotBlank() }?.let { expected ->
                                require(parsed.packageName == expected) {
                                    "Package после пересборки изменился: ${parsed.packageName} вместо $expected"
                                }
                            }
                            val uri = FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                result.signedApk,
                            )
                            val intent = Intent(Intent.ACTION_INSTALL_PACKAGE)
                                .setData(uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        }.onFailure { onError(it.message) }
'''
    automod = replace_once(automod, old_install, new_install, "AutoMod installer preflight")
    AUTOMOD.write_text(automod, encoding="utf-8")

print("Applied v0.26.1 Patch Lab installability fix")
