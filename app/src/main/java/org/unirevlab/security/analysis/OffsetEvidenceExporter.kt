package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.StaticAnalysisReport

/** Exports reproducible static RVA/token evidence without generating executable hooks. */
object OffsetEvidenceExporter {
    fun export(report: StaticAnalysisReport): String {
        val nativeLibraries = report.native?.libraries.orEmpty()
        val symbolCatalogs = nativeLibraries.map { library ->
            (library.exportedSymbols + library.importedSymbols)
                .asSequence()
                .filter { it.defined && it.virtualAddress != null }
                .distinctBy { it.name to it.virtualAddress }
                .sortedWith(compareBy({ it.virtualAddress }, { it.name }))
                .toList()
        }
        val selectedSymbols = fairSelectSymbols(symbolCatalogs)
        val libraries = nativeLibraries.mapIndexed { index, library ->
            val symbols = selectedSymbols[index]
            JSONObject()
                .put("entry", library.entryName)
                .put("abi", library.abi)
                .put("machine", library.machine)
                .put("buildId", library.buildId ?: JSONObject.NULL)
                .put("availableSymbolCount", symbolCatalogs[index].size)
                .put("exportedSymbolCount", symbols.size)
                .put("symbolsTruncated", symbols.size < symbolCatalogs[index].size)
                .put("symbols", JSONArray(symbols.map { symbol ->
                    JSONObject()
                        .put("name", symbol.name)
                        .put("rvaDecimal", symbol.virtualAddress)
                        .put("rvaHex", symbol.virtualAddress?.let(::hex) ?: JSONObject.NULL)
                        .put("sizeBytes", symbol.sizeBytes ?: JSONObject.NULL)
                        .put("type", symbol.symbolType)
                }))
        }

        val il2cpp = report.il2cpp?.let { summary ->
            JSONObject()
                .put("detected", summary.detected)
                .put("confidence", summary.confidence)
                .put("libraries", JSONArray(summary.libil2cppLibraries))
                .put("metadataEntry", summary.metadata?.entryName ?: JSONObject.NULL)
                .put("metadataVersion", summary.metadata?.metadataVersion ?: JSONObject.NULL)
                .put("layoutProfile", summary.metadata?.layoutProfile ?: JSONObject.NULL)
                .put("metadataTables", JSONArray(summary.metadata?.tableRanges.orEmpty().map { table ->
                    JSONObject()
                        .put("name", table.name)
                        .put("fileOffsetDecimal", table.offset)
                        .put("fileOffsetHex", hex(table.offset))
                        .put("sizeBytes", table.sizeBytes)
                }))
                .put("registrationCandidates", JSONArray(summary.registrationCandidates.map { candidate ->
                    JSONObject()
                        .put("kind", candidate.kind)
                        .put("library", candidate.libraryEntry)
                        .put("symbol", candidate.symbolName)
                        .put("rvaDecimal", candidate.virtualAddress ?: JSONObject.NULL)
                        .put("rvaHex", candidate.virtualAddress?.let(::hex) ?: JSONObject.NULL)
                        .put("validatedDefinedSymbol", candidate.validatedDefinedSymbol)
                }))
                .put("managedMethods", JSONArray(summary.metadata?.methodDefinitions.orEmpty().take(MAX_IL2CPP_METHODS).map { method ->
                    JSONObject()
                        .put("metadataIndex", method.index)
                        .put("declaringType", method.declaringType)
                        .put("name", method.name)
                        .put("tokenDecimal", method.token)
                        .put("tokenHex", hex(method.token))
                        .put("parameterCount", method.parameterCount)
                }))
        }

        val ghidra = JSONArray(report.ghidra.map { analysis ->
            JSONObject()
                .put("library", analysis.libraryEntry)
                .put("processor", analysis.architecture?.processor ?: JSONObject.NULL)
                .put("pointerSize", analysis.architecture?.pointerSize ?: JSONObject.NULL)
                .put("registrations", JSONArray(analysis.il2cppRegistrations.map { registration ->
                    JSONObject()
                        .put("kind", registration.kind)
                        .put("rvaDecimal", registration.rva)
                        .put("rvaHex", hex(registration.rva))
                        .put("confidence", registration.confidence)
                        .put("evidence", registration.evidence)
                }))
                .put("codegenCalls", JSONArray(analysis.il2cppCodegenCalls.map { call ->
                    JSONObject()
                        .put("callsiteRvaHex", hex(call.callsiteRva))
                        .put("codeRegistrationRvaHex", call.codeRegistrationRva?.let(::hex) ?: JSONObject.NULL)
                        .put("metadataRegistrationRvaHex", call.metadataRegistrationRva?.let(::hex) ?: JSONObject.NULL)
                        .put("confidence", call.confidence)
                }))
                .put("codegenModules", JSONArray(analysis.il2cppCodegenModules.map { module ->
                    JSONObject()
                        .put("module", module.moduleName)
                        .put("moduleRvaHex", hex(module.moduleRva))
                        .put("methodPointerCount", module.methodPointerCount)
                        .put("methodPointersRvaHex", hex(module.methodPointersRva))
                        .put("confidence", module.confidence)
                }))
        })

        val il2cppMethodCorrelations = report.correlations?.il2cppMethods.orEmpty()
            .sortedWith(compareBy({ it.libraryEntry }, { it.functionRva }, { it.methodIndex }))
            .take(MAX_METHOD_CORRELATIONS)
        val jniMethodCorrelations = report.correlations?.jniNative.orEmpty()
            .sortedWith(compareBy({ it.libraryEntry }, { it.functionRva }, { it.dexMethodIndex }))
            .take(MAX_JNI_CORRELATIONS)

        return JSONObject()
            .put("schemaVersion", "1.1")
            .put("engineVersion", report.engineVersion)
            .put("assessmentId", report.assessment.assessmentId)
            .put("artifactSha256", report.artifact.sha256)
            .put("addressSemantics", "RVA values are static evidence relative to a library image base; they are not live runtime addresses.")
            .put("safety", "Evidence export only. No executable hook, patch, injection, or bypass code is generated.")
            .put(
                "truncated",
                symbolCatalogs.sumOf { it.size } > selectedSymbols.sumOf { it.size } ||
                    (report.il2cpp?.metadata?.methodDefinitions?.size ?: 0) > MAX_IL2CPP_METHODS ||
                    report.correlations?.il2cppMethods.orEmpty().size > MAX_METHOD_CORRELATIONS ||
                    report.correlations?.jniNative.orEmpty().size > MAX_JNI_CORRELATIONS,
            )
            .put("nativeLibraries", JSONArray(libraries))
            .put(
                "nativeSymbolCoverage",
                JSONObject()
                    .put("selection", "fair-per-library")
                    .put("available", symbolCatalogs.sumOf { it.size })
                    .put("exported", selectedSymbols.sumOf { it.size })
                    .put("maxTotal", MAX_SYMBOLS)
                    .put("minimumPerLibraryWhenAvailable", MIN_SYMBOLS_PER_LIBRARY),
            )
            .put("il2cpp", il2cpp ?: JSONObject.NULL)
            .put("il2cppMethodCorrelations", JSONArray(il2cppMethodCorrelations.map { method ->
                JSONObject()
                    .put("metadataEntry", method.metadataEntry)
                    .put("methodIndex", method.methodIndex)
                    .put("declaringType", method.declaringType)
                    .put("methodName", method.methodName)
                    .put("tokenDecimal", method.token)
                    .put("tokenHex", hex(method.token))
                    .put("library", method.libraryEntry)
                    .put("functionRvaDecimal", method.functionRva)
                    .put("functionRvaHex", hex(method.functionRva))
                    .put("functionName", method.functionName)
                    .put("confidence", method.confidence)
                    .put("evidence", method.evidence)
            }))
            .put("jniMethodCorrelations", JSONArray(jniMethodCorrelations.map { method ->
                JSONObject()
                    .put("dexEntry", method.dexEntry)
                    .put("dexMethodIndex", method.dexMethodIndex)
                    .put("declaringClass", method.declaringClass)
                    .put("methodName", method.methodName)
                    .put("prototype", method.prototype)
                    .put("library", method.libraryEntry)
                    .put("functionRvaDecimal", method.functionRva)
                    .put("functionRvaHex", hex(method.functionRva))
                    .put("functionName", method.functionName ?: JSONObject.NULL)
                    .put("source", method.source)
                    .put("confidence", method.confidence)
                    .put("evidence", method.evidence)
            }))
            .put("ghidra", ghidra)
            .toString(2)
    }

    private fun hex(value: Long): String = "0x" + value.toString(16)

    private fun fairSelectSymbols(
        catalogs: List<List<NativeSymbolReference>>,
    ): List<List<NativeSymbolReference>> {
        if (catalogs.isEmpty()) return emptyList()
        val guaranteed = minOf(MIN_SYMBOLS_PER_LIBRARY, MAX_SYMBOLS / catalogs.size)
        val selected = catalogs.map { it.take(guaranteed).toMutableList() }
        var remaining = (MAX_SYMBOLS - selected.sumOf { it.size }).coerceAtLeast(0)
        val order = catalogs.indices.sortedWith(
            compareBy<Int>(
                { libraryPriority(catalogs[it]) },
                { it },
            ),
        )
        while (remaining > 0) {
            var added = false
            for (index in order) {
                val next = selected[index].size
                val allowed = minOf(catalogs[index].size, MAX_SYMBOLS_PER_LIBRARY)
                if (next >= allowed) continue
                selected[index] += catalogs[index][next]
                remaining--
                added = true
                if (remaining == 0) break
            }
            if (!added) break
        }
        return selected
    }

    private fun libraryPriority(symbols: List<NativeSymbolReference>): Int = when {
        symbols.any { it.name.startsWith("il2cpp_") || it.name.contains("CodeRegistration", ignoreCase = true) } -> 0
        else -> 1
    }

    private const val MAX_SYMBOLS = 12_000
    private const val MIN_SYMBOLS_PER_LIBRARY = 64
    private const val MAX_SYMBOLS_PER_LIBRARY = 2_000
    private const val MAX_IL2CPP_METHODS = 20_000
    private const val MAX_METHOD_CORRELATIONS = 20_000
    private const val MAX_JNI_CORRELATIONS = 8_000
}
