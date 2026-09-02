#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"v0300: anchor not found for {label}")
    return text.replace(old, new, 1)


# 1) Model: expose the complete field_ids inventory to later analysis stages.
rel = "app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt"
s = read(rel)
s = replace_once(
    s,
    "data class DexMethodReference(\n",
    "data class DexFieldReference(\n"
    "    val dexEntry: String,\n"
    "    val fieldIndex: Int,\n"
    "    val declaringClass: String,\n"
    "    val name: String,\n"
    "    val type: String,\n"
    ") : java.io.Serializable\n\n"
    "data class DexMethodReference(\n",
    "DexFieldReference model",
)
s = replace_once(
    s,
    "    val methodsIndexed: Long = 0,\n",
    "    val methodsIndexed: Long = 0,\n"
    "    val fieldsDeclared: Long = 0,\n"
    "    val fieldsIndexed: Long = 0,\n"
    "    val fields: List<DexFieldReference> = emptyList(),\n",
    "DexSummary field inventory",
)
write(rel, s)


# 2) DEX structural inventory: enumerate field_ids just like method_ids.
rel = "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt"
s = read(rel)
s = replace_once(
    s,
    "import org.unirevlab.security.model.DexClassReference\n",
    "import org.unirevlab.security.model.DexClassReference\nimport org.unirevlab.security.model.DexFieldReference\n",
    "DexStringScanner field import",
)
s = replace_once(
    s,
    "        val maxMethods: Int = 150_000,\n",
    "        val maxMethods: Int = 150_000,\n        val maxFields: Int = 150_000,\n",
    "DexStringScanner max fields",
)
s = replace_once(
    s,
    "        val maxReportedMethods: Int = 8_000,\n",
    "        val maxReportedMethods: Int = 8_000,\n        val maxReportedFields: Int = 24_000,\n",
    "DexStringScanner reported fields",
)
s = replace_once(
    s,
    "        val methodsDeclared: Int,\n        val methodsIndexed: Int,\n        val classes: List<DexClassReference>,\n",
    "        val methodsDeclared: Int,\n        val methodsIndexed: Int,\n        val fieldsDeclared: Int = 0,\n        val fieldsIndexed: Int = 0,\n        val fields: List<DexFieldReference> = emptyList(),\n        val classes: List<DexClassReference>,\n",
    "DexStringScanner FileResult fields",
)
s = replace_once(
    s,
    "        val protoIdsSize: Int,\n        val protoIdsOff: Long,\n        val methodIdsSize: Int,\n",
    "        val protoIdsSize: Int,\n        val protoIdsOff: Long,\n        val fieldIdsSize: Int,\n        val fieldIdsOff: Long,\n        val methodIdsSize: Int,\n",
    "DexStringScanner Header fields",
)
s = replace_once(
    s,
    "            val methods = mutableListOf<DexMethodReference>()\n",
    "            val fields = mutableListOf<DexFieldReference>()\n"
    "            val toIndexFields = minOf(h.fieldIdsSize, limits.maxFields)\n"
    "            if (h.fieldIdsSize > toIndexFields) truncated = true\n"
    "            repeat(toIndexFields) { fieldIndex ->\n"
    "                if ((fieldIndex and 0xff) == 0) {\n"
    "                    checkCancelled()\n"
    "                    onProgress?.invoke(scaleProgress(45, 53, fieldIndex, toIndexFields), \"Поля DEX\", fieldIndex, toIndexFields)\n"
    "                }\n"
    "                val field = readField(raf, h, dexEntry, fieldIndex, limits)\n"
    "                if (fields.size < limits.maxReportedFields) fields += field else truncated = true\n"
    "            }\n"
    "            onProgress?.invoke(53, \"Поля DEX готовы\", toIndexFields, toIndexFields)\n\n"
    "            val methods = mutableListOf<DexMethodReference>()\n",
    "DexStringScanner field scan",
)
s = s.replace("scaleProgress(45, 65, methodIndex, toIndexMethods)", "scaleProgress(53, 68, methodIndex, toIndexMethods)")
s = s.replace("onProgress?.invoke(65, \"Методы DEX готовы\"", "onProgress?.invoke(68, \"Методы DEX готовы\"")
s = s.replace("scaleProgress(65, 100, classDefIndex, toIndexClasses)", "scaleProgress(68, 100, classDefIndex, toIndexClasses)")
s = replace_once(
    s,
    "                methodsDeclared = h.methodIdsSize,\n                methodsIndexed = toIndexMethods,\n                classes = classes,\n",
    "                methodsDeclared = h.methodIdsSize,\n                methodsIndexed = toIndexMethods,\n                fieldsDeclared = h.fieldIdsSize,\n                fieldsIndexed = toIndexFields,\n                fields = fields,\n                classes = classes,\n",
    "DexStringScanner return fields",
)
s = replace_once(
    s,
    "        table(0x50, 0x54, 8, \"field_ids\")\n        val methods = table(0x58, 0x5c, 8, \"method_ids\")\n",
    "        val fields = table(0x50, 0x54, 8, \"field_ids\")\n        val methods = table(0x58, 0x5c, 8, \"method_ids\")\n",
    "DexStringScanner readHeader field table",
)
s = replace_once(
    s,
    "        return Header(fileSize, strings.first, strings.second, types.first, types.second, protos.first, protos.second, methods.first, methods.second, classes.first, classes.second)\n",
    "        return Header(fileSize, strings.first, strings.second, types.first, types.second, protos.first, protos.second, fields.first, fields.second, methods.first, methods.second, classes.first, classes.second)\n",
    "DexStringScanner Header constructor",
)
s = replace_once(
    s,
    "    private fun readMethod(raf: RandomAccessFile, h: Header, dexEntry: String, methodIndex: Int, limits: Limits): DexMethodReference {\n",
    "    private fun readField(raf: RandomAccessFile, h: Header, dexEntry: String, fieldIndex: Int, limits: Limits): DexFieldReference {\n"
    "        if (fieldIndex !in 0 until h.fieldIdsSize) throw DexFormatException(\"field_idx outside field_ids\")\n"
    "        val base = h.fieldIdsOff + fieldIndex.toLong() * 8L\n"
    "        val classIdx = readU16(raf, base)\n"
    "        val typeIdx = readU16(raf, base + 2)\n"
    "        val nameIdx = readU32(raf, base + 4).toIntChecked(\"field name_idx\")\n"
    "        if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException(\"field class_idx outside type_ids\")\n"
    "        if (typeIdx !in 0 until h.typeIdsSize) throw DexFormatException(\"field type_idx outside type_ids\")\n"
    "        return DexFieldReference(\n"
    "            dexEntry = dexEntry,\n"
    "            fieldIndex = fieldIndex,\n"
    "            declaringClass = typeDescriptor(raf, h, classIdx, limits.maxStringBytes),\n"
    "            name = readStringByIndex(raf, h, nameIdx, limits.maxStringBytes).value,\n"
    "            type = typeDescriptor(raf, h, typeIdx, limits.maxStringBytes),\n"
    "        )\n"
    "    }\n\n"
    "    private fun readMethod(raf: RandomAccessFile, h: Header, dexEntry: String, methodIndex: Int, limits: Limits): DexMethodReference {\n",
    "DexStringScanner readField",
)
write(rel, s)


# 3) Carry the field inventory through per-APK and installed split aggregation.
rel = "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt"
s = read(rel)
s = replace_once(
    s,
    "import org.unirevlab.security.model.DexFieldXref\n",
    "import org.unirevlab.security.model.DexFieldXref\nimport org.unirevlab.security.model.DexFieldReference\n",
    "LocalArtifactInspector field import",
)
s = replace_once(
    s,
    "        methods = value.methods.map { it.copy(dexEntry = dexEntry) },\n",
    "        methods = value.methods.map { it.copy(dexEntry = dexEntry) },\n        fields = value.fields.map { it.copy(dexEntry = dexEntry) },\n",
    "rebase field inventory",
)
s = replace_once(
    s,
    "        val methods = BoundedCollector<DexMethodReference>(MAX_REPORTED_DEX_METHODS)\n",
    "        val methods = BoundedCollector<DexMethodReference>(MAX_REPORTED_DEX_METHODS)\n        val fields = BoundedCollector<DexFieldReference>(MAX_REPORTED_DEX_FIELDS)\n",
    "merge field collector",
)
s = replace_once(
    s,
    "            methods.addAll(value.methods)\n",
    "            methods.addAll(value.methods)\n            fields.addAll(value.fields)\n",
    "merge field addAll",
)
s = replace_once(
    s,
    "            classes.overflowed, methods.overflowed, nativeMethods.overflowed, codeMethods.overflowed,\n",
    "            classes.overflowed, methods.overflowed, fields.overflowed, nativeMethods.overflowed, codeMethods.overflowed,\n",
    "merge field overflow",
)
s = replace_once(
    s,
    "            methodsIndexed = values.sumOf { it.methodsIndexed },\n            classes = classes.toList(),\n",
    "            methodsIndexed = values.sumOf { it.methodsIndexed },\n            fieldsDeclared = values.sumOf { it.fieldsDeclared },\n            fieldsIndexed = values.sumOf { it.fieldsIndexed },\n            fields = fields.toList(),\n            classes = classes.toList(),\n",
    "merge field summary",
)
s = replace_once(
    s,
    "        var methodsDeclared = 0L\n        var methodsIndexed = 0L\n",
    "        var methodsDeclared = 0L\n        var methodsIndexed = 0L\n        var fieldsDeclared = 0L\n        var fieldsIndexed = 0L\n",
    "inspect field counters",
)
s = replace_once(
    s,
    "        val methods = BoundedDistinctCollector<DexMethodReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }\n",
    "        val methods = BoundedDistinctCollector<DexMethodReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_METHODS) { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }\n        val fields = BoundedDistinctCollector<DexFieldReference, Triple<String, Int, String>>(MAX_REPORTED_DEX_FIELDS) { Triple(it.dexEntry, it.fieldIndex, it.declaringClass) }\n",
    "inspect field collector",
)
s = replace_once(
    s,
    "                                methodsDeclared += scan.methodsDeclared.toLong()\n                                methodsIndexed += scan.methodsIndexed.toLong()\n                                classes.addAll(scan.classes)\n                                methods.addAll(scan.methods)\n",
    "                                methodsDeclared += scan.methodsDeclared.toLong()\n                                methodsIndexed += scan.methodsIndexed.toLong()\n                                fieldsDeclared += scan.fieldsDeclared.toLong()\n                                fieldsIndexed += scan.fieldsIndexed.toLong()\n                                classes.addAll(scan.classes)\n                                methods.addAll(scan.methods)\n                                fields.addAll(scan.fields)\n",
    "inspect field accumulation",
)
s = replace_once(
    s,
    "            methodsIndexed = methodsIndexed,\n            classes = classes.toList(),\n",
    "            methodsIndexed = methodsIndexed,\n            fieldsDeclared = fieldsDeclared,\n            fieldsIndexed = fieldsIndexed,\n            fields = fields.toList(),\n            classes = classes.toList(),\n",
    "inspect field summary",
)
s = replace_once(
    s,
    "                classes.overflowed, methods.overflowed, nativeMethods.overflowed, codeMethods.overflowed,\n",
    "                classes.overflowed, methods.overflowed, fields.overflowed, nativeMethods.overflowed, codeMethods.overflowed,\n",
    "inspect field overflow",
)
s = replace_once(
    s,
    "        private const val MAX_REPORTED_DEX_METHODS = 16_000\n",
    "        private const val MAX_REPORTED_DEX_METHODS = 16_000\n        private const val MAX_REPORTED_DEX_FIELDS = 48_000\n",
    "reported field cap",
)
write(rel, s)


# 4) Full mapping engine: use the complete structural field inventory with xref fallback.
rel = "app/src/main/java/org/unirevlab/security/analysis/FullMappingEngine.kt"
s = read(rel)
s = replace_once(
    s,
    "import org.unirevlab.security.model.DexFieldXref\n",
    "import org.unirevlab.security.model.DexFieldReference\n",
    "FullMappingEngine field import",
)
old = """        dex.fieldXrefs.asSequence()
            .filter { it.declaringClass in classDescriptors }
            .distinctBy { Triple(it.dexEntry, it.fieldIndex, it.declaringClass) }
            .forEach { field ->
                if (out.size >= maxSymbols) return@forEach
                val key = fieldSymbol(field)
                val exactAlias = exactBySymbol[key]
                val automaticAlias = automaticBySymbol[key]
                val readable = !looksObfuscatedSimpleName(field.fieldName)
                val reconstructedName = when {
                    exactAlias != null -> extractExactFieldName(exactAlias.originalSymbol, field.fieldName)
                    automaticAlias != null -> automaticAlias.alias
                    readable -> field.fieldName
                    else -> \"field_f${field.fieldIndex}\"
                }
                add(
                    Symbol(
                        kind = \"FIELD\",
                        ownerDescriptor = field.declaringClass,
                        obfuscatedSymbol = key,
                        reconstructedName = reconstructedName,
                        origin = when {
                            exactAlias != null -> Origin.EXACT
                            automaticAlias?.basis == AnalystMappingEngine.Basis.SEMANTIC -> Origin.SEMANTIC
                            readable -> Origin.PRESERVED
                            else -> Origin.STRUCTURAL
                        },
                        confidence = when {
                            exactAlias != null -> AnalystMappingEngine.Confidence.HIGH
                            automaticAlias != null -> automaticAlias.confidence
                            readable -> AnalystMappingEngine.Confidence.HIGH
                            else -> AnalystMappingEngine.Confidence.LOW
                        },
                        evidence = when {
                            exactAlias != null -> listOf(exactAlias.evidence)
                            automaticAlias != null -> automaticAlias.evidence
                            readable -> listOf(\"Readable DEX field name preserved\")
                            else -> listOf(\"Deterministic field alias from DEX field index\")
                        },
                    ),
                )
            }
"""
new = """        val fieldInventory = if (dex.fields.isNotEmpty()) {
            dex.fields.asSequence()
        } else {
            dex.fieldXrefs.asSequence().map { xref ->
                DexFieldReference(
                    dexEntry = xref.dexEntry,
                    fieldIndex = xref.fieldIndex,
                    declaringClass = xref.declaringClass,
                    name = xref.fieldName,
                    type = xref.fieldType,
                )
            }
        }
        fieldInventory
            .filter { it.declaringClass in classDescriptors }
            .distinctBy { Triple(it.dexEntry, it.fieldIndex, it.declaringClass) }
            .forEach { field ->
                if (out.size >= maxSymbols) return@forEach
                val key = fieldSymbol(field)
                val exactAlias = exactBySymbol[key]
                val automaticAlias = automaticBySymbol[key]
                val readable = !looksObfuscatedSimpleName(field.name)
                val reconstructedName = when {
                    exactAlias != null -> extractExactFieldName(exactAlias.originalSymbol, field.name)
                    automaticAlias != null -> automaticAlias.alias
                    readable -> field.name
                    else -> \"field_f${field.fieldIndex}\"
                }
                add(
                    Symbol(
                        kind = \"FIELD\",
                        ownerDescriptor = field.declaringClass,
                        obfuscatedSymbol = key,
                        reconstructedName = reconstructedName,
                        origin = when {
                            exactAlias != null -> Origin.EXACT
                            automaticAlias?.basis == AnalystMappingEngine.Basis.SEMANTIC -> Origin.SEMANTIC
                            readable -> Origin.PRESERVED
                            else -> Origin.STRUCTURAL
                        },
                        confidence = when {
                            exactAlias != null -> AnalystMappingEngine.Confidence.HIGH
                            automaticAlias != null -> automaticAlias.confidence
                            readable -> AnalystMappingEngine.Confidence.HIGH
                            else -> AnalystMappingEngine.Confidence.LOW
                        },
                        evidence = when {
                            exactAlias != null -> listOf(exactAlias.evidence)
                            automaticAlias != null -> automaticAlias.evidence
                            readable -> listOf(\"Readable DEX field name preserved\")
                            else -> listOf(\"Deterministic field alias from DEX field index\")
                        },
                    ),
                )
            }
"""
s = replace_once(s, old, new, "FullMappingEngine field inventory")
s = replace_once(
    s,
    "            // Current report model exposes field references, not the entire field_ids declaration table.\n            // This flag deliberately remains false until the structural DEX inventory is extended.\n            fieldInventoryComplete = false,\n",
    "            fieldInventoryComplete = dex.parseErrors == 0 && dex.fieldsIndexed >= dex.fieldsDeclared,\n",
    "FullMappingEngine field completeness",
)
s = replace_once(
    s,
    "    private fun fieldSymbol(field: DexFieldXref): String =\n        \"${field.declaringClass}->${field.fieldName}:${field.fieldType}\"\n",
    "    private fun fieldSymbol(field: DexFieldReference): String =\n        \"${field.declaringClass}->${field.name}:${field.type}\"\n",
    "FullMappingEngine field symbol",
)
write(rel, s)


# 5) Test full field coverage rather than the old referenced-field limitation.
rel = "app/src/test/java/org/unirevlab/security/analysis/FullMappingEngineTest.kt"
s = read(rel)
s = replace_once(
    s,
    "import org.unirevlab.security.model.DexFieldXref\n",
    "import org.unirevlab.security.model.DexFieldReference\n",
    "FullMappingEngineTest field import",
)
s = replace_once(
    s,
    "            methodsDeclared = 3,\n            methodsIndexed = 3,\n",
    "            methodsDeclared = 3,\n            methodsIndexed = 3,\n            fieldsDeclared = 1,\n            fieldsIndexed = 1,\n            fields = listOf(\n                DexFieldReference(\"classes.dex\", 7, \"La/b;\", \"d\", \"I\"),\n            ),\n",
    "FullMappingEngineTest field stats",
)
start = s.find("            fieldXrefs = listOf(\n")
if start >= 0:
    end = s.find("            httpUrls = emptyList(),\n", start)
    if end < 0:
        raise SystemExit("v0300: fieldXrefs test end not found")
    s = s[:start] + s[end:]
s = s.replace("        assertFalse(result.fieldInventoryComplete)\n", "        assertTrue(result.fieldInventoryComplete)\n")
s = s.replace("import org.junit.Assert.assertFalse\n", "")
write(rel, s)


# 6) Version the preview build.
rel = "app/build.gradle.kts"
s = read(rel)
s = s.replace('versionCode = 40', 'versionCode = 41')
s = s.replace('versionName = "0.29.0-preview"', 'versionName = "0.30.0-preview-full-mapping"')
write(rel, s)

print("v0.30.0 full mapping migration applied")
