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
        raise SystemExit(f"patch state mismatch: {rel}\nmissing block:\n{old[:700]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


def replace_between(rel: str, start: str, end: str, replacement: str) -> None:
    text = read(rel)
    if replacement in text:
        print(f"already patched: {rel} :: {start.strip()[:64]}")
        return
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing start: {start}")
    j = text.find(end, i)
    if j < 0:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing end: {end}")
    write(rel, text[:i] + replacement + text[j:])
    print(f"patched: {rel} :: {start.strip()[:64]}")


# 1) Native/DEX discovery must use the complete ZIP classification counts. The archive* counters
# intentionally stop at 20k entries for cheap summary statistics, while *EntryCount traverses the
# entire central directory. Using archiveNativeLibraries as the gate could skip ELF scanning entirely.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''    private fun archiveStatsFromIndex(index: ApkArchiveIndex): ArchiveStats = ArchiveStats(\n        entries = index.archiveEntries,\n        dexFiles = index.archiveDexFiles,\n        nativeLibraries = index.archiveNativeLibraries,\n        hasAndroidManifest = index.archiveHasManifest,\n''',
    '''    private fun archiveStatsFromIndex(index: ApkArchiveIndex): ArchiveStats = ArchiveStats(\n        entries = index.archiveEntries,\n        // Discovery gates must use the complete central-directory counts. archive* counters are\n        // intentionally bounded to the first ARCHIVE_STATS_LIMIT entries for summary statistics.\n        dexFiles = index.dexEntryCount,\n        nativeLibraries = index.nativeEntryCount,\n        hasAndroidManifest = index.archiveHasManifest,\n''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '        const val ENGINE_VERSION = "0.22.4-dev-fast-dex"\n',
    '        const val ENGINE_VERSION = "0.22.5-dev-native-speed"\n',
)

# 2) DEX structural indexing repeatedly resolves the same method names, descriptors and prototypes.
# Keep a small thread-local LRU per RandomAccessFile. Large literals are deliberately not cached.
dex_rel = "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt"
replace_once(
    dex_rel,
    '''    private data class DecodedString(val value: String, val truncated: Boolean)\n\n''',
    '''    private data class DecodedString(val value: String, val truncated: Boolean)\n\n    private class BoundedLru<K, V>(private val limit: Int) : java.util.LinkedHashMap<K, V>(limit, 0.75f, true) {\n        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean = size > limit\n    }\n\n    private class MetadataCache {\n        var file: RandomAccessFile? = null\n        val strings = BoundedLru<Int, DecodedString>(4_096)\n        val types = BoundedLru<Int, String>(4_096)\n        val prototypes = BoundedLru<Int, String>(2_048)\n\n        fun use(raf: RandomAccessFile) {\n            if (file !== raf) {\n                file = raf\n                strings.clear()\n                types.clear()\n                prototypes.clear()\n            }\n        }\n    }\n\n    private val metadataCache = ThreadLocal.withInitial(::MetadataCache)\n\n''',
)
replace_between(
    dex_rel,
    "    private fun readStringByIndex(raf: RandomAccessFile, h: Header, index: Int, maxStringBytes: Int): DecodedString {\n",
    "    private fun readStringData(raf: RandomAccessFile, offset: Long, fileSize: Long, maxStringBytes: Int): DecodedString {",
    '''    private fun readStringByIndex(raf: RandomAccessFile, h: Header, index: Int, maxStringBytes: Int): DecodedString {\n        if (index !in 0 until h.stringIdsSize) throw DexFormatException("string_idx outside string_ids")\n        val cache = metadataCache.get().also { it.use(raf) }\n        cache.strings[index]?.let { return it }\n        val itemOffset = PositionalReadCache.u32Le(raf, h.stringIdsOff + index.toLong() * 4L, h.fileSize)\n        if (itemOffset >= h.fileSize) throw DexFormatException("string_data_off outside DEX")\n        val decoded = readStringData(raf, itemOffset, h.fileSize, maxStringBytes)\n        // Descriptors, names and prototype atoms are tiny and highly repetitive. Avoid retaining\n        // unusually large literals in the LRU merely for a possible second lookup.\n        if (decoded.value.length <= 2_048) cache.strings[index] = decoded\n        return decoded\n    }\n\n''',
)
replace_between(
    dex_rel,
    "    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {\n",
    "    private fun readMethod(raf: RandomAccessFile, h: Header, dexEntry: String, methodIndex: Int, limits: Limits): DexMethodReference {",
    '''    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {\n        if (typeIndex !in 0 until h.typeIdsSize) throw DexFormatException("type_idx outside type_ids")\n        val cache = metadataCache.get().also { it.use(raf) }\n        cache.types[typeIndex]?.let { return it }\n        val stringIndex = PositionalReadCache.u32Le(raf, h.typeIdsOff + typeIndex.toLong() * 4L, h.fileSize).toIntChecked("descriptor_idx")\n        val value = readStringByIndex(raf, h, stringIndex, maxStringBytes).value\n        if (value.length <= 2_048) cache.types[typeIndex] = value\n        return value\n    }\n\n''',
)
replace_between(
    dex_rel,
    "    private fun readPrototype(raf: RandomAccessFile, h: Header, protoIdx: Int, limits: Limits): String {\n",
    "    private fun readNativeMethodsFromClassData(\n",
    '''    private fun readPrototype(raf: RandomAccessFile, h: Header, protoIdx: Int, limits: Limits): String {\n        if (protoIdx !in 0 until h.protoIdsSize) throw DexFormatException("proto_idx outside proto_ids")\n        val cache = metadataCache.get().also { it.use(raf) }\n        cache.prototypes[protoIdx]?.let { return it }\n        val base = h.protoIdsOff + protoIdx.toLong() * 12L\n        val returnTypeIdx = readU32(raf, base + 4).toIntChecked("return_type_idx")\n        val parametersOff = readU32(raf, base + 8)\n        val returnType = typeDescriptor(raf, h, returnTypeIdx, limits.maxStringBytes)\n        val value = if (parametersOff == 0L) {\n            "()$returnType"\n        } else {\n            ensureRange(parametersOff, 4, h.fileSize, "type_list")\n            val countLong = readU32(raf, parametersOff)\n            if (countLong > limits.maxProtoParameters) throw DexFormatException("prototype parameter count exceeds limit")\n            ensureRange(parametersOff + 4, countLong.checkedMul(2), h.fileSize, "type_list items")\n            val params = buildString {\n                repeat(countLong.toInt()) { index ->\n                    val typeIdx = readU16(raf, parametersOff + 4 + index.toLong() * 2L)\n                    append(typeDescriptor(raf, h, typeIdx, limits.maxStringBytes))\n                }\n            }\n            "($params)$returnType"\n        }\n        if (value.length <= 4_096) cache.prototypes[protoIdx] = value\n        return value\n    }\n\n''',
)

# 3) ELF parser still used seek()+byte reads for every section/symbol/dynamic-field lookup. Reuse the
# same immutable-file positional window already proven by the DEX parser.
elf_rel = "app/src/main/java/org/unirevlab/security/analysis/ElfNativeScanner.kt"
replace_between(
    elf_rel,
    "    private fun u8(raf: RandomAccessFile, offset: Long): Int {\n",
    "    private fun u16(raf: RandomAccessFile, offset: Long): Int {",
    '''    private fun u8(raf: RandomAccessFile, offset: Long): Int {\n        ensureRange(offset, 1, raf.length(), "u8")\n        return PositionalReadCache.u8(raf, offset, raf.length())\n    }\n\n''',
)
replace_between(
    elf_rel,
    "    private fun u16(raf: RandomAccessFile, offset: Long): Int {\n",
    "    private fun u32(raf: RandomAccessFile, offset: Long): Long {",
    '''    private fun u16(raf: RandomAccessFile, offset: Long): Int {\n        ensureRange(offset, 2, raf.length(), "u16")\n        return PositionalReadCache.u16Le(raf, offset, raf.length())\n    }\n\n''',
)
replace_between(
    elf_rel,
    "    private fun u32(raf: RandomAccessFile, offset: Long): Long {\n",
    "    private fun u64(raf: RandomAccessFile, offset: Long): Long {",
    '''    private fun u32(raf: RandomAccessFile, offset: Long): Long {\n        ensureRange(offset, 4, raf.length(), "u32")\n        return PositionalReadCache.u32Le(raf, offset, raf.length())\n    }\n\n''',
)

# 4) Version bump. This also makes the result cache reject reports created by 0.22.4, which is
# necessary because a cached report may contain the old false "no native libraries" result.
replace_once(
    "app/build.gradle.kts",
    '''        versionCode = 22\n        versionName = "0.22.4-dev-fast-dex"\n''',
    '''        versionCode = 23\n        versionName = "0.22.5-dev-native-speed"\n''',
)

print("v0.22.5 native discovery / metadata speed patch complete")
