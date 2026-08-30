package org.unirevlab.security.analysis

import java.io.ByteArrayOutputStream
import java.io.InputStream
import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.*

/** Bounded Android-side parser for coordinator/worker Ghidra result schemas 1.1-1.3. */
object GhidraResultJsonParser {
    data class Limits(
        val maxBytes: Int = 64 * 1024 * 1024,
        val maxFunctions: Int = 100_000,
        val maxCfg: Int = 100_000,
        val maxXrefs: Int = 500_000,
        val maxRegistrations: Int = 100_000,
        val maxWarnings: Int = 1_000,
    )

    fun parse(input: InputStream, limits: Limits = Limits()): List<GhidraLibraryAnalysis> {
        val bytes = readBounded(input, limits.maxBytes)
        val text = bytes.toString(Charsets.UTF_8).trim()
        require(text.isNotEmpty()) { "Empty Ghidra result JSON" }
        return when (text.first()) {
            '{' -> listOf(parseResult(JSONObject(text), limits))
            '[' -> {
                val array = JSONArray(text)
                require(array.length() <= 256) { "Too many Ghidra library results" }
                List(array.length()) { index -> parseResult(array.getJSONObject(index), limits) }
            }
            else -> error("Ghidra result must be a JSON object or array")
        }
    }

    private fun parseResult(json: JSONObject, limits: Limits): GhidraLibraryAnalysis {
        val schemaVersion = json.getString("schemaVersion")
        require(schemaVersion in setOf("1.1", "1.2", "1.3")) { "Unsupported Ghidra result schema" }
        val engine = json.getJSONObject("engine")
        val coverage = json.getJSONObject("coverage")
        val functionsJson = json.getJSONArray("functions").checked(limits.maxFunctions, "functions")
        val cfgJson = json.getJSONArray("cfg").checked(limits.maxCfg, "cfg")
        val xrefsJson = json.getJSONArray("xrefs").checked(limits.maxXrefs, "xrefs")
        val jniJson = json.getJSONArray("jniRegistrations").checked(limits.maxRegistrations, "jniRegistrations")
        val il2cppJson = json.getJSONArray("il2cppRegistrations").checked(limits.maxRegistrations, "il2cppRegistrations")
        val codegenJson = json.optJSONArray("il2cppCodegenCalls")?.checked(limits.maxRegistrations, "il2cppCodegenCalls")
        val pointerTablesJson = json.optJSONArray("il2cppPointerTables")?.checked(limits.maxRegistrations, "il2cppPointerTables")
        val codegenModulesJson = json.optJSONArray("il2cppCodegenModules")?.checked(256, "il2cppCodegenModules")
        val warningsJson = json.getJSONArray("warnings").checked(limits.maxWarnings, "warnings")
        val architectureJson = json.optJSONObject("architecture")

        return GhidraLibraryAnalysis(
            schemaVersion = schemaVersion,
            assessmentId = json.getString("assessmentId"),
            artifactSha256 = json.getString("artifactSha256").lowercase(),
            libraryEntry = json.getString("libraryEntry"),
            status = json.getString("status"),
            engine = GhidraEngineSummary(
                name = engine.getString("name"),
                version = engine.getString("version"),
                pyGhidra = engine.getBoolean("pyGhidra"),
                analysisProfile = engine.getString("analysisProfile"),
            ),
            architecture = architectureJson?.let { value ->
                GhidraArchitectureSummary(
                    processor = value.getString("processor"),
                    pointerSize = value.getInt("pointerSize"),
                    endian = value.getString("endian"),
                )
            },
            coverage = GhidraCoverageSummary(
                functionsDiscovered = coverage.getInt("functionsDiscovered"),
                functionsReported = coverage.getInt("functionsReported"),
                cfgBlocksReported = coverage.getInt("cfgBlocksReported"),
                xrefsReported = coverage.getInt("xrefsReported"),
                decompilerFunctionsReported = coverage.getInt("decompilerFunctionsReported"),
                truncated = coverage.getBoolean("truncated"),
            ),
            functions = List(functionsJson.length()) { i ->
                functionsJson.getJSONObject(i).let { value ->
                    GhidraFunctionSummary(
                        rva = value.getLong("rva"),
                        name = value.getString("name"),
                        namespace = value.getString("namespace"),
                        signature = value.getString("signature"),
                        sizeBytes = value.getLong("sizeBytes"),
                        isThunk = value.getBoolean("isThunk"),
                        decompilerPreview = value.optNullableString("decompilerPreview"),
                    )
                }
            },
            cfg = List(cfgJson.length()) { i ->
                cfgJson.getJSONObject(i).let { value ->
                    val blocks = value.getJSONArray("blocks").checked(20_000, "cfg.blocks")
                    val edges = value.getJSONArray("edges").checked(50_000, "cfg.edges")
                    GhidraFunctionCfg(
                        functionRva = value.getLong("functionRva"),
                        blocks = List(blocks.length()) { bi ->
                            blocks.getJSONObject(bi).let { block ->
                                GhidraCfgBlock(block.getLong("startRva"), block.getLong("endRva"), block.getString("flowType"))
                            }
                        },
                        edges = List(edges.length()) { ei ->
                            edges.getJSONObject(ei).let { edge ->
                                GhidraCfgEdge(edge.getLong("fromRva"), edge.getLong("toRva"), edge.getString("kind"))
                            }
                        },
                    )
                }
            },
            xrefs = List(xrefsJson.length()) { i ->
                xrefsJson.getJSONObject(i).let { value ->
                    GhidraXref(value.getLong("fromRva"), value.getLong("toRva"), value.getString("kind"))
                }
            },
            jniRegistrations = List(jniJson.length()) { i ->
                jniJson.getJSONObject(i).let { value ->
                    GhidraJniRegistration(
                        source = value.getString("source"),
                        className = value.getString("className"),
                        methodName = value.getString("methodName"),
                        signature = value.getString("signature"),
                        functionRva = value.getLong("functionRva"),
                        confidence = value.getString("confidence"),
                        tableRva = value.optNullableLong("tableRva"),
                        registerNativesCallsiteRva = value.optNullableLong("registerNativesCallsiteRva"),
                        findClassCallsiteRva = value.optNullableLong("findClassCallsiteRva"),
                        classEvidence = value.optNullableString("classEvidence"),
                    )
                }
            },
            il2cppRegistrations = List(il2cppJson.length()) { i ->
                il2cppJson.getJSONObject(i).let { value ->
                    GhidraIl2CppRegistration(
                        kind = value.getString("kind"),
                        rva = value.getLong("rva"),
                        symbolName = value.getString("symbolName"),
                        evidence = value.getString("evidence"),
                        confidence = value.getString("confidence"),
                    )
                }
            },
            il2cppCodegenCalls = codegenJson?.let { array -> List(array.length()) { i ->
                array.getJSONObject(i).let { value ->
                    GhidraIl2CppCodegenCall(
                        callsiteRva = value.getLong("callsiteRva"),
                        codeRegistrationRva = value.optNullableLong("codeRegistrationRva"),
                        metadataRegistrationRva = value.optNullableLong("metadataRegistrationRva"),
                        codegenOptionsRva = value.optNullableLong("codegenOptionsRva"),
                        evidence = value.getString("evidence"),
                        confidence = value.getString("confidence"),
                    )
                }
            } } ?: emptyList(),
            il2cppPointerTables = pointerTablesJson?.let { array -> List(array.length()) { i ->
                array.getJSONObject(i).let { value ->
                    val samples = value.getJSONArray("sampleFunctionRvas").checked(256, "sampleFunctionRvas")
                    GhidraIl2CppPointerTable(
                        ownerRva = value.getLong("ownerRva"),
                        fieldOffsetBytes = value.getInt("fieldOffsetBytes"),
                        entryCount = value.getLong("entryCount"),
                        tableRva = value.getLong("tableRva"),
                        sampledEntries = value.getInt("sampledEntries"),
                        executableEntries = value.getInt("executableEntries"),
                        sampleFunctionRvas = List(samples.length()) { si -> samples.getLong(si) },
                        confidence = value.getString("confidence"),
                    )
                }
            } } ?: emptyList(),
            il2cppCodegenModules = codegenModulesJson?.let { array -> List(array.length()) { i ->
                array.getJSONObject(i).let { value ->
                    val slots = value.getJSONArray("sampledMethodPointers").checked(4096, "sampledMethodPointers")
                    GhidraIl2CppCodegenModule(
                        ownerCodeRegistrationRva = value.getLong("ownerCodeRegistrationRva"),
                        moduleRva = value.getLong("moduleRva"),
                        moduleName = value.getString("moduleName"),
                        methodPointerCount = value.getInt("methodPointerCount"),
                        methodPointersRva = value.getLong("methodPointersRva"),
                        sampledMethodPointers = List(slots.length()) { si ->
                            slots.getJSONObject(si).let { slot -> GhidraIl2CppMethodPointerSlot(slot.getInt("slotIndex"), slot.getLong("functionRva")) }
                        },
                        evidence = value.getString("evidence"),
                        confidence = value.getString("confidence"),
                    )
                }
            } } ?: emptyList(),
            warnings = List(warningsJson.length()) { i -> warningsJson.getString(i) },
        )
    }

    private fun JSONArray.checked(max: Int, label: String): JSONArray {
        require(length() <= max) { "$label exceeds parser limit" }
        return this
    }

    private fun JSONObject.optNullableString(name: String): String? =
        if (!has(name) || isNull(name)) null else getString(name)

    private fun JSONObject.optNullableLong(name: String): Long? =
        if (!has(name) || isNull(name)) null else getLong(name)

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= maxBytes) { "Ghidra result exceeds ${maxBytes} byte import limit" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
