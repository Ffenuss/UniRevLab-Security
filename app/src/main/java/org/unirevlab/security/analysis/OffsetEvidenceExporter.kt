package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.StaticAnalysisReport

/** Exports reproducible static RVA/token evidence without generating executable hooks. */
object OffsetEvidenceExporter {
    fun export(report: StaticAnalysisReport): String {
        var remainingSymbols = MAX_SYMBOLS
        val libraries = report.native?.libraries.orEmpty().map { library ->
            val symbols = (library.exportedSymbols + library.importedSymbols)
                .asSequence()
                .filter { it.defined && it.virtualAddress != null }
                .distinctBy { it.name to it.virtualAddress }
                .sortedWith(compareBy({ it.virtualAddress }, { it.name }))
                .take(remainingSymbols.coerceAtLeast(0))
                .toList()
            remainingSymbols -= symbols.size
            JSONObject()
                .put("entry", library.entryName)
                .put("abi", library.abi)
                .put("machine", library.machine)
                .put("buildId", library.buildId ?: JSONObject.NULL)
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

        return JSONObject()
            .put("schemaVersion", "1.0")
            .put("engineVersion", report.engineVersion)
            .put("assessmentId", report.assessment.assessmentId)
            .put("artifactSha256", report.artifact.sha256)
            .put("addressSemantics", "RVA values are static evidence relative to a library image base; they are not live runtime addresses.")
            .put("safety", "Evidence export only. No executable hook, patch, injection, or bypass code is generated.")
            .put("truncated", remainingSymbols <= 0 || (report.il2cpp?.metadata?.methodDefinitions?.size ?: 0) > MAX_IL2CPP_METHODS)
            .put("nativeLibraries", JSONArray(libraries))
            .put("il2cpp", il2cpp ?: JSONObject.NULL)
            .put("ghidra", ghidra)
            .toString(2)
    }

    private fun hex(value: Long): String = "0x" + value.toString(16)

    private const val MAX_SYMBOLS = 8_000
    private const val MAX_IL2CPP_METHODS = 20_000
}
