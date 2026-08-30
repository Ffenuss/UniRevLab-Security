package org.unirevlab.security.model

data class GhidraEngineSummary(
    val name: String,
    val version: String,
    val pyGhidra: Boolean,
    val analysisProfile: String,
) : java.io.Serializable

data class GhidraArchitectureSummary(
    val processor: String,
    val pointerSize: Int,
    val endian: String,
) : java.io.Serializable

data class GhidraCoverageSummary(
    val functionsDiscovered: Int,
    val functionsReported: Int,
    val cfgBlocksReported: Int,
    val xrefsReported: Int,
    val decompilerFunctionsReported: Int,
    val truncated: Boolean,
) : java.io.Serializable

data class GhidraFunctionSummary(
    val rva: Long,
    val name: String,
    val namespace: String,
    val signature: String,
    val sizeBytes: Long,
    val isThunk: Boolean,
    val decompilerPreview: String? = null,
) : java.io.Serializable

data class GhidraCfgBlock(
    val startRva: Long,
    val endRva: Long,
    val flowType: String,
) : java.io.Serializable

data class GhidraCfgEdge(
    val fromRva: Long,
    val toRva: Long,
    val kind: String,
) : java.io.Serializable

data class GhidraFunctionCfg(
    val functionRva: Long,
    val blocks: List<GhidraCfgBlock>,
    val edges: List<GhidraCfgEdge>,
) : java.io.Serializable

data class GhidraXref(
    val fromRva: Long,
    val toRva: Long,
    val kind: String,
) : java.io.Serializable

data class GhidraJniRegistration(
    val source: String,
    val className: String,
    val methodName: String,
    val signature: String,
    val functionRva: Long,
    val confidence: String,
    val tableRva: Long? = null,
    val registerNativesCallsiteRva: Long? = null,
    val findClassCallsiteRva: Long? = null,
    val classEvidence: String? = null,
) : java.io.Serializable

data class GhidraIl2CppRegistration(
    val kind: String,
    val rva: Long,
    val symbolName: String,
    val evidence: String,
    val confidence: String,
) : java.io.Serializable

/** P-code recovered call arguments to il2cpp_codegen_register. */
data class GhidraIl2CppCodegenCall(
    val callsiteRva: Long,
    val codeRegistrationRva: Long? = null,
    val metadataRegistrationRva: Long? = null,
    val codegenOptionsRva: Long? = null,
    val evidence: String,
    val confidence: String,
) : java.io.Serializable

/**
 * Structural executable pointer-array candidate discovered inside CodeRegistration.
 * The worker does not claim that its slots map one-to-one to metadata methods.
 */
data class GhidraIl2CppPointerTable(
    val ownerRva: Long,
    val fieldOffsetBytes: Int,
    val entryCount: Long,
    val tableRva: Long,
    val sampledEntries: Int,
    val executableEntries: Int,
    val sampleFunctionRvas: List<Long>,
    val confidence: String,
) : java.io.Serializable

data class GhidraIl2CppMethodPointerSlot(
    val slotIndex: Int,
    val functionRva: Long,
) : java.io.Serializable

data class GhidraIl2CppCodegenModule(
    val ownerCodeRegistrationRva: Long,
    val moduleRva: Long,
    val moduleName: String,
    val methodPointerCount: Int,
    val methodPointersRva: Long,
    val sampledMethodPointers: List<GhidraIl2CppMethodPointerSlot>,
    val evidence: String,
    val confidence: String,
) : java.io.Serializable

data class GhidraLibraryAnalysis(
    val schemaVersion: String = "1.3",
    val assessmentId: String,
    val artifactSha256: String,
    val libraryEntry: String,
    val status: String,
    val engine: GhidraEngineSummary,
    val architecture: GhidraArchitectureSummary? = null,
    val coverage: GhidraCoverageSummary,
    val functions: List<GhidraFunctionSummary>,
    val cfg: List<GhidraFunctionCfg>,
    val xrefs: List<GhidraXref>,
    val jniRegistrations: List<GhidraJniRegistration>,
    val il2cppRegistrations: List<GhidraIl2CppRegistration>,
    val il2cppCodegenCalls: List<GhidraIl2CppCodegenCall> = emptyList(),
    val il2cppPointerTables: List<GhidraIl2CppPointerTable> = emptyList(),
    val il2cppCodegenModules: List<GhidraIl2CppCodegenModule> = emptyList(),
    val warnings: List<String>,
) : java.io.Serializable
