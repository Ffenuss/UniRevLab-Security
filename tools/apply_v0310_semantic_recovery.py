#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt"
DEX = ROOT / "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt"
FULL = ROOT / "app/src/main/java/org/unirevlab/security/analysis/FullMappingEngine.kt"
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/AutomaticDeobfuscationPanel.kt"
BUILD = ROOT / "app/build.gradle.kts"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_model() -> None:
    text = MODEL.read_text(encoding="utf-8")
    old = '''data class DexClassReference(
    val dexEntry: String,
    val classIndex: Int,
    val descriptor: String,
    val superDescriptor: String?,
    val accessFlags: Long,
) : java.io.Serializable
'''
    new = '''data class DexClassReference(
    val dexEntry: String,
    val classIndex: Int,
    val descriptor: String,
    val superDescriptor: String?,
    val accessFlags: Long,
    /** DEX class_def interfaces, retained for semantic deobfuscation/recovery. */
    val interfaces: List<String> = emptyList(),
    /** Surviving class_def source_file string when present; not treated as an exact class name. */
    val sourceFile: String? = null,
) : java.io.Serializable
'''
    text = replace_once(text, old, new, "DexClassReference semantic metadata")
    MODEL.write_text(text, encoding="utf-8")


def patch_dex() -> None:
    text = DEX.read_text(encoding="utf-8")
    old = '''                val accessFlags = readU32(raf, base + 4)
                val superIdxLong = readU32(raf, base + 8)
                val classDataOff = readU32(raf, base + 24)
                if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException("class_idx outside type_ids")
                val descriptor = typeDescriptor(raf, h, classIdx, limits.maxStringBytes)
                val superDescriptor = if (superIdxLong == NO_INDEX) null else {
                    val superIdx = superIdxLong.toIntChecked("superclass_idx")
                    if (superIdx !in 0 until h.typeIdsSize) throw DexFormatException("superclass_idx outside type_ids")
                    typeDescriptor(raf, h, superIdx, limits.maxStringBytes)
                }
                val classRef = DexClassReference(dexEntry, classDefIndex, descriptor, superDescriptor, accessFlags)
'''
    new = '''                val accessFlags = readU32(raf, base + 4)
                val superIdxLong = readU32(raf, base + 8)
                val interfacesOff = readU32(raf, base + 12)
                val sourceFileIdxLong = readU32(raf, base + 16)
                val classDataOff = readU32(raf, base + 24)
                if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException("class_idx outside type_ids")
                val descriptor = typeDescriptor(raf, h, classIdx, limits.maxStringBytes)
                val superDescriptor = if (superIdxLong == NO_INDEX) null else {
                    val superIdx = superIdxLong.toIntChecked("superclass_idx")
                    if (superIdx !in 0 until h.typeIdsSize) throw DexFormatException("superclass_idx outside type_ids")
                    typeDescriptor(raf, h, superIdx, limits.maxStringBytes)
                }
                val interfaces = if (interfacesOff == 0L) {
                    emptyList()
                } else {
                    ensureRange(interfacesOff, 4, h.fileSize, "class interfaces type_list")
                    val countLong = readU32(raf, interfacesOff)
                    if (countLong > limits.maxProtoParameters) throw DexFormatException("class interface count exceeds limit")
                    ensureRange(interfacesOff + 4, countLong.checkedMul(2), h.fileSize, "class interfaces")
                    buildList {
                        repeat(countLong.toInt()) { interfaceIndex ->
                            val typeIdx = readU16(raf, interfacesOff + 4 + interfaceIndex.toLong() * 2L)
                            if (typeIdx !in 0 until h.typeIdsSize) throw DexFormatException("interface type_idx outside type_ids")
                            add(typeDescriptor(raf, h, typeIdx, limits.maxStringBytes))
                        }
                    }
                }
                val sourceFile = if (sourceFileIdxLong == NO_INDEX) {
                    null
                } else {
                    val sourceFileIdx = sourceFileIdxLong.toIntChecked("source_file_idx")
                    if (sourceFileIdx !in 0 until h.stringIdsSize) throw DexFormatException("source_file_idx outside string_ids")
                    readStringByIndex(raf, h, sourceFileIdx, limits.maxStringBytes).value.take(512)
                }
                val classRef = DexClassReference(
                    dexEntry = dexEntry,
                    classIndex = classDefIndex,
                    descriptor = descriptor,
                    superDescriptor = superDescriptor,
                    accessFlags = accessFlags,
                    interfaces = interfaces,
                    sourceFile = sourceFile,
                )
'''
    text = replace_once(text, old, new, "DEX source/interfaces metadata")
    DEX.write_text(text, encoding="utf-8")


def patch_full_mapping() -> None:
    text = FULL.read_text(encoding="utf-8")
    old = '''        val automatic = AnalystMappingEngine.generate(report, maxEntries = maxSymbols)
        val automaticBySymbol = automatic.entries.associateBy { it.obfuscatedSymbol }
        val exact = officialMapping?.let { MappingDeobfuscator.resolve(report, it, limit = maxSymbols) }.orEmpty()
'''
    new = '''        val automatic = AnalystMappingEngine.generate(report, maxEntries = maxSymbols)
        val semanticRecovery = SemanticRecoveryEngine.generate(report, maxEntries = maxSymbols)
        val automaticBySymbol = automatic.entries.associateBy { it.obfuscatedSymbol }.toMutableMap().apply {
            semanticRecovery.entries.forEach { recovered ->
                val candidate = AnalystMappingEngine.Entry(
                    kind = recovered.kind,
                    obfuscatedSymbol = recovered.obfuscatedSymbol,
                    alias = recovered.alias,
                    confidence = recovered.confidence,
                    basis = AnalystMappingEngine.Basis.SEMANTIC,
                    evidence = recovered.evidence,
                )
                val current = get(recovered.obfuscatedSymbol)
                if (current == null || candidate.confidence.ordinal <= current.confidence.ordinal) {
                    put(recovered.obfuscatedSymbol, candidate)
                }
            }
        }
        val exact = officialMapping?.let { MappingDeobfuscator.resolve(report, it, limit = maxSymbols) }.orEmpty()
'''
    text = replace_once(text, old, new, "FullMapping semantic fusion")
    text = text.replace("# UniRevLab Security full analyst mapping v2", "# UniRevLab Security full analyst mapping v3")
    text = text.replace(
        "# IMPORTANT: only EXACT entries claim developer-original names.\\n",
        "# IMPORTANT: only EXACT entries claim developer-original names.\\n# SEMANTIC entries may fuse source_file, inheritance, resources, call graph and JNI evidence.\\n",
    )
    FULL.write_text(text, encoding="utf-8")


def patch_ui() -> None:
    text = UI.read_text(encoding="utf-8")
    if "import org.unirevlab.security.analysis.SemanticRecoveryEngine\n" not in text:
        text = text.replace(
            "import org.unirevlab.security.analysis.MappingDeobfuscator\n",
            "import org.unirevlab.security.analysis.MappingDeobfuscator\nimport org.unirevlab.security.analysis.SemanticRecoveryEngine\n",
            1,
        )

    anchor = '''    val fullMapping by produceState<FullMappingEngine.Result?>(
        initialValue = null,
'''
    block = '''    val semanticRecovery by produceState<SemanticRecoveryEngine.Result?>(
        initialValue = null,
        key1 = report.artifact.sha256,
        key2 = report.dex?.methodsIndexed,
    ) {
        value = withContext(Dispatchers.Default) { SemanticRecoveryEngine.generate(report) }
    }

    val fullMapping by produceState<FullMappingEngine.Result?>(
        initialValue = null,
'''
    text = replace_once(text, anchor, block, "semantic recovery UI state")

    old = '''                    Text(
                        "DEX coverage: ${if (result.dexCoverageComplete) "complete" else "partial / bounded"} · field inventory: ${if (result.fieldInventoryComplete) "complete" else "referenced fields only"}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(
'''
    new = '''                    Text(
                        "DEX coverage: ${if (result.dexCoverageComplete) "complete" else "partial / bounded"} · field inventory: ${if (result.fieldInventoryComplete) "complete" else "referenced fields only"}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    semanticRecovery?.let { recovery ->
                        Text(
                            "Semantic recovery: HIGH ${recovery.highConfidence} · MEDIUM ${recovery.mediumConfidence} · source ${recovery.sourceMetadataHits} · inheritance ${recovery.inheritanceHits} · resources ${recovery.resourceHits} · graph ${recovery.callGraphHits} · JNI/runtime ${recovery.jniHits + recovery.crossRuntimeHits}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    Button(
'''
    text = replace_once(text, old, new, "semantic recovery UI metrics")
    UI.write_text(text, encoding="utf-8")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    text = text.replace("versionCode = 41", "versionCode = 42")
    text = text.replace('versionName = "0.30.0-preview-full-mapping"', 'versionName = "0.31.0-preview-semantic-recovery"')
    BUILD.write_text(text, encoding="utf-8")


def main() -> None:
    patch_model()
    patch_dex()
    patch_full_mapping()
    patch_ui()
    patch_build()
    print("v0.31.0 semantic recovery quality migration applied")


if __name__ == "__main__":
    main()
