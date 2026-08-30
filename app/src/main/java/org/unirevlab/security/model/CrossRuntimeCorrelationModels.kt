package org.unirevlab.security.model

/** Evidence-backed link from a DEX native declaration to a Ghidra recovered native function. */
data class JniNativeCorrelation(
    val dexEntry: String,
    val dexMethodIndex: Int,
    val declaringClass: String,
    val methodName: String,
    val prototype: String,
    val libraryEntry: String,
    val functionRva: Long,
    val functionName: String?,
    val source: String,
    val confidence: String,
    val evidence: String,
) : java.io.Serializable

/** Cross-check between the bounded ELF/IL2CPP scanner and Ghidra registration evidence. */
data class Il2CppRegistrationCorrelation(
    val kind: String,
    val libraryEntry: String,
    val staticSymbolName: String,
    val staticVirtualAddress: Long?,
    val ghidraSymbolName: String,
    val ghidraRva: Long,
    val evidence: String,
    val confidence: String,
) : java.io.Serializable

/**
 * Conservative IL2CPP managed-method to native-function correlation.
 *
 * No mapping is emitted from ordering assumptions alone. A result requires either an explicit
 * metadata token literal in a recovered function identity or a unique type+method identity match.
 */
data class Il2CppMethodNativeCorrelation(
    val metadataEntry: String,
    val methodIndex: Int,
    val declaringType: String,
    val methodName: String,
    val token: Long,
    val libraryEntry: String,
    val functionRva: Long,
    val functionName: String,
    val evidence: String,
    val confidence: String,
) : java.io.Serializable

data class CrossRuntimeCorrelationSummary(
    val jniNative: List<JniNativeCorrelation> = emptyList(),
    val il2cppRegistrations: List<Il2CppRegistrationCorrelation> = emptyList(),
    val il2cppMethods: List<Il2CppMethodNativeCorrelation> = emptyList(),
    val dexNativeMethodsConsidered: Int = 0,
    val dexNativeMethodsResolved: Int = 0,
    val il2cppMethodsConsidered: Int = 0,
    val il2cppMethodsResolved: Int = 0,
    val truncated: Boolean = false,
) : java.io.Serializable
