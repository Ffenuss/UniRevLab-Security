package org.unirevlab.security.model

/** Bounded resources.arsc resolution evidence for a compiled Android resource ID. */
data class ResourceResolutionSummary(
    val resourceId: Long,
    val packageId: Int,
    val typeId: Int,
    val entryId: Int,
    val packageName: String?,
    val typeName: String?,
    val entryName: String?,
    val dataType: Int,
    val dataValue: Long,
    val stringValue: String? = null,
    val fileEntry: String? = null,
    val complex: Boolean = false,
    val parentResourceId: Long? = null,
    val mapEntryCount: Int = 0,
    /** APK/split that supplied this compiled resource variant. */
    val sourceArchive: String = "resources.arsc",
    /** SHA-256 of the raw ResTable_config bytes; stable without pretending to decode every qualifier. */
    val configurationSha256: String? = null,
) : java.io.Serializable

data class ResourceReferenceHop(
    val resourceId: Long,
    val dataType: Int,
    val dataValue: Long,
    val typeName: String? = null,
    val entryName: String? = null,
    val stringValue: String? = null,
    val fileEntry: String? = null,
    val sourceArchive: String? = null,
    val configurationSha256: String? = null,
) : java.io.Serializable

data class ResourceReferenceChain(
    val requestedResourceId: Long,
    val hops: List<ResourceReferenceHop>,
    val terminalResourceId: Long?,
    val terminalFileEntry: String? = null,
    val cycleDetected: Boolean = false,
    val depthExceeded: Boolean = false,
    val unresolved: Boolean = false,
    val ambiguousVariant: Boolean = false,
    val sourceArchive: String? = null,
    val configurationSha256: String? = null,
) : java.io.Serializable

data class ResourceTableSourceSummary(
    val sourceArchive: String,
    val packages: List<String> = emptyList(),
    val resolutionCount: Int = 0,
    val configurationCount: Int = 0,
    val parseErrors: Int = 0,
    val truncated: Boolean = false,
) : java.io.Serializable

data class ResourceTableSummary(
    val packages: List<String> = emptyList(),
    val resolutions: List<ResourceResolutionSummary> = emptyList(),
    val referenceChains: List<ResourceReferenceChain> = emptyList(),
    val sources: List<ResourceTableSourceSummary> = emptyList(),
    val parseErrors: Int = 0,
    val truncated: Boolean = false,
) : java.io.Serializable
