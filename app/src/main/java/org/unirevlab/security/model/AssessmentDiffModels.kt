package org.unirevlab.security.model

data class DiffItem(
    val category: String,
    val key: String,
    val change: String,
    val before: String? = null,
    val after: String? = null,
    val severityHint: Severity? = null,
) : java.io.Serializable

data class AssessmentDiff(
    val packageName: String?,
    val fromVersion: String?,
    val toVersion: String?,
    val signerChanged: Boolean,
    val items: List<DiffItem>,
) : java.io.Serializable {
    val addedCount: Int get() = items.count { it.change == "ADDED" }
    val removedCount: Int get() = items.count { it.change == "REMOVED" }
    val changedCount: Int get() = items.count { it.change == "CHANGED" }
}

data class ReMethodNode(
    val dexEntry: String,
    val methodIndex: Int,
    val classDescriptor: String,
    val name: String,
    val prototype: String,
    val callers: List<String>,
    val callees: List<String>,
    val strings: List<String>,
    val fields: List<String>,
    val types: List<String>,
    val basicBlockCount: Int,
    val nativeTargets: List<String> = emptyList(),
) : java.io.Serializable

data class ReClassNode(
    val descriptor: String,
    val superDescriptor: String?,
    val methods: List<ReMethodNode>,
) : java.io.Serializable

data class RePackageNode(
    val name: String,
    val classes: List<ReClassNode>,
) : java.io.Serializable

data class DexReIndex(
    val packages: List<RePackageNode>,
    val methodCount: Int,
    val xrefCount: Int,
) : java.io.Serializable

data class NativeSymbolNode(
    val library: String,
    val name: String,
    val kind: String,
    val defined: Boolean,
    val virtualAddress: Long?,
    val sizeBytes: Long?,
) : java.io.Serializable

data class NativeReIndex(
    val libraries: List<String>,
    val symbols: List<NativeSymbolNode>,
    val jniBridges: List<JniBridgeReference>,
) : java.io.Serializable


data class GhidraFunctionNode(
    val libraryEntry: String,
    val rva: Long,
    val name: String,
    val namespace: String,
    val signature: String,
    val sizeBytes: Long,
    val cfgBlockCount: Int,
    val incomingXrefs: Int,
    val outgoingXrefs: Int,
    val jniRegistrations: List<String>,
    val il2cppRegistrations: List<String>,
    val crossRuntimeLinks: List<String> = emptyList(),
    val decompilerPreview: String?,
) : java.io.Serializable

data class GhidraReIndex(
    val libraries: List<String>,
    val functions: List<GhidraFunctionNode>,
    val xrefCount: Int,
    val jniRegistrationCount: Int,
    val il2cppRegistrationCount: Int,
    val il2cppCodegenCallCount: Int = 0,
    val il2cppPointerTableCount: Int = 0,
    val il2cppCodegenModuleCount: Int = 0,
) : java.io.Serializable
