package org.unirevlab.security.model

enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL }
enum class Confidence { CONFIRMED, HIGH, MEDIUM, LOW }

data class Evidence(
    val source: String,
    val location: String,
    val value: String,
) : java.io.Serializable

data class SecurityReference(
    val standard: String,
    val id: String,
) : java.io.Serializable

data class Finding(
    val id: String,
    val title: String,
    val severity: Severity,
    val confidence: Confidence,
    val category: String,
    val description: String,
    val evidence: List<Evidence>,
    val remediation: String,
    val references: List<SecurityReference> = emptyList(),
    val requiresManualReview: Boolean = false,
) : java.io.Serializable

data class ComponentExposure(
    val kind: String,
    val name: String,
    val exported: Boolean,
    val permissions: List<String> = emptyList(),
) : java.io.Serializable

data class DeclaredPermission(
    val name: String,
    /** Android base protection level normalized to NORMAL/DANGEROUS/SIGNATURE/OTHER/UNKNOWN. */
    val protectionLevel: String,
) : java.io.Serializable

data class DeepLinkDeclaration(
    val componentName: String,
    val schemes: List<String>,
    val hosts: List<String>,
    val autoVerify: Boolean,
    val browsable: Boolean,
    val viewAction: Boolean,
    val ports: List<String> = emptyList(),
    val paths: List<String> = emptyList(),
    val pathPrefixes: List<String> = emptyList(),
    val pathPatterns: List<String> = emptyList(),
    val mimeTypes: List<String> = emptyList(),
) : java.io.Serializable

data class ProviderPathPermissionSummary(
    val path: String? = null,
    val pathPrefix: String? = null,
    val pathPattern: String? = null,
    val readPermission: String? = null,
    val writePermission: String? = null,
) : java.io.Serializable

data class ProviderDeclaration(
    val name: String,
    val authorities: List<String>,
    val exported: Boolean?,
    val grantUriPermissions: Boolean,
    val readPermission: String? = null,
    val writePermission: String? = null,
    val pathPermissions: List<ProviderPathPermissionSummary> = emptyList(),
) : java.io.Serializable



data class ComponentDexReachability(
    val componentKind: String,
    val componentName: String,
    val classDescriptor: String,
    val exported: Boolean,
    val externallyAddressable: Boolean,
    val classPresent: Boolean,
    val entryMethodIndexes: List<Int>,
    val reachableMethodIndexes: List<Int>,
    val reachableMethodCount: Int,
    val maxDepthReached: Int,
    val truncated: Boolean,
) : java.io.Serializable

data class ManifestDexReachabilitySummary(
    val components: List<ComponentDexReachability>,
    val externallyAddressableComponents: Int,
    val reachableMethods: Int,
    val truncated: Boolean,
) : java.io.Serializable

data class DexStringReference(
    val dexEntry: String,
    val stringIndex: Int,
    /** Sanitized value; query/fragment data are removed from URLs before reporting. */
    val value: String,
) : java.io.Serializable

data class SecretCandidate(
    val kind: String,
    val dexEntry: String,
    val stringIndex: Int,
    /** SHA-256 of the original candidate. Raw candidate material is intentionally not exported. */
    val valueSha256: String,
    val redactedPreview: String,
) : java.io.Serializable


data class DexClassReference(
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

data class DexFieldReference(
    val dexEntry: String,
    val fieldIndex: Int,
    val declaringClass: String,
    val name: String,
    val type: String,
) : java.io.Serializable

data class DexMethodReference(
    val dexEntry: String,
    val methodIndex: Int,
    val declaringClass: String,
    val name: String,
    val prototype: String,
) : java.io.Serializable

data class DexNativeMethodDeclaration(
    val dexEntry: String,
    val methodIndex: Int,
    val declaringClass: String,
    val name: String,
    val prototype: String,
    val accessFlags: Long,
) : java.io.Serializable



data class DexMethodCodeReference(
    val dexEntry: String,
    val methodIndex: Int,
    val declaringClass: String,
    val name: String,
    val prototype: String,
    val codeOffset: Long,
    val registersSize: Int,
    val insSize: Int,
    val outsSize: Int,
    val triesSize: Int,
    val instructionUnits: Int,
) : java.io.Serializable

data class DexMethodCallXref(
    val dexEntry: String,
    val callerMethodIndex: Int,
    val callerClass: String,
    val callerName: String,
    val calleeMethodIndex: Int,
    val calleeClass: String,
    val calleeName: String,
    val calleePrototype: String,
    val instructionOffsetCodeUnits: Int,
) : java.io.Serializable

data class DexStringXref(
    val dexEntry: String,
    val callerMethodIndex: Int,
    val callerClass: String,
    val callerName: String,
    val stringIndex: Int,
    val value: String,
    val instructionOffsetCodeUnits: Int,
) : java.io.Serializable

data class DexTypeXref(
    val dexEntry: String,
    val callerMethodIndex: Int,
    val callerClass: String,
    val callerName: String,
    val typeIndex: Int,
    val descriptor: String,
    val kind: String,
    val instructionOffsetCodeUnits: Int,
) : java.io.Serializable



data class DexFieldXref(
    val dexEntry: String,
    val callerMethodIndex: Int,
    val callerClass: String,
    val callerName: String,
    val fieldIndex: Int,
    val declaringClass: String,
    val fieldName: String,
    val fieldType: String,
    val kind: String,
    val instructionOffsetCodeUnits: Int,
) : java.io.Serializable

data class DexBasicBlock(
    val dexEntry: String,
    val methodIndex: Int,
    val blockIndex: Int,
    val startCodeUnit: Int,
    val endCodeUnitExclusive: Int,
    /** Successor block start offsets in code units. */
    val successorCodeUnits: List<Int>,
    val terminalKind: String,
) : java.io.Serializable

data class DexInvokeArgument(
    val argumentIndex: Int,
    val register: Int,
    /** INT, LONG, STRING, TYPE, NULL, or UNKNOWN. */
    val kind: String,
    /** Sanitized/redacted representation. */
    val value: String,
) : java.io.Serializable

data class DexInvokeObservation(
    val dexEntry: String,
    val callerMethodIndex: Int,
    val callerClass: String,
    val callerName: String,
    val calleeMethodIndex: Int,
    val calleeClass: String,
    val calleeName: String,
    val calleePrototype: String,
    val instructionOffsetCodeUnits: Int,
    val arguments: List<DexInvokeArgument>,
) : java.io.Serializable


data class DexConstantReference(
    val dexEntry: String,
    val methodIndex: Int,
    val register: Int,
    val kind: String,
    val value: String,
    val instructionOffsetCodeUnits: Int,
) : java.io.Serializable

data class DexSummary(
    val dexFilesDiscovered: Int,
    val dexFilesScanned: Int,
    val stringsDeclared: Long,
    val stringsScanned: Long,
    val typesDeclared: Long = 0,
    val typesIndexed: Long = 0,
    val classesDeclared: Long = 0,
    val classesIndexed: Long = 0,
    val methodsDeclared: Long = 0,
    val methodsIndexed: Long = 0,
    val fieldsDeclared: Long = 0,
    val fieldsIndexed: Long = 0,
    val fields: List<DexFieldReference> = emptyList(),
    val classes: List<DexClassReference> = emptyList(),
    val methods: List<DexMethodReference> = emptyList(),
    val nativeMethods: List<DexNativeMethodDeclaration> = emptyList(),
    val codeMethods: List<DexMethodCodeReference> = emptyList(),
    val callXrefs: List<DexMethodCallXref> = emptyList(),
    val stringXrefs: List<DexStringXref> = emptyList(),
    val typeXrefs: List<DexTypeXref> = emptyList(),
    val fieldXrefs: List<DexFieldXref> = emptyList(),
    val basicBlocks: List<DexBasicBlock> = emptyList(),
    val constants: List<DexConstantReference> = emptyList(),
    val invokeObservations: List<DexInvokeObservation> = emptyList(),
    val httpUrls: List<DexStringReference>,
    val httpsUrls: List<DexStringReference>,
    val secretCandidates: List<SecretCandidate>,
    val parseErrors: Int,
    val truncated: Boolean,
    val parseErrorDetails: List<String> = emptyList(),
) : java.io.Serializable

data class NetworkTrustAnchorSummary(
    val source: String,
    val inDebugOverrides: Boolean,
    val overridePins: Boolean? = null,
) : java.io.Serializable

data class NetworkDomainConfigSummary(
    val cleartextTrafficPermitted: Boolean?,
    val domains: List<String>,
    val includeSubdomains: Boolean,
) : java.io.Serializable

data class NetworkSecurityConfigSummary(
    val manifestReference: String?,
    val resolvedManifestEntry: String? = null,
    val configEntries: List<String>,
    val baseCleartextTrafficPermitted: Boolean?,
    val domainConfigs: List<NetworkDomainConfigSummary>,
    val trustAnchors: List<NetworkTrustAnchorSummary>,
    val debugOverridesPresent: Boolean,
    val pinSetPresent: Boolean,
    val parseErrors: Int,
    val truncated: Boolean,
) : java.io.Serializable

data class SigningCertificateSummary(
    val sha256: String,
    val subjectDn: String?,
    val issuerDn: String?,
    val serialNumberHex: String?,
    val notBeforeEpochMs: Long?,
    val notAfterEpochMs: Long?,
    val signatureAlgorithm: String?,
    val publicKeyAlgorithm: String?,
    val publicKeySizeBits: Int?,
    val currentSigner: Boolean,
    val lineageIndex: Int?,
) : java.io.Serializable

data class ManifestSummary(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val debuggable: Boolean,
    val allowBackup: Boolean,
    val fullBackupContentConfigured: Boolean?,
    val dataExtractionRulesConfigured: Boolean?,
    val usesCleartextTraffic: Boolean,
    val networkSecurityConfigConfigured: Boolean?,
    val requestedPermissions: List<String>,
    val dangerousPermissions: List<String>,
    val declaredPermissions: List<DeclaredPermission> = emptyList(),
    val components: List<ComponentExposure>,
    val deepLinks: List<DeepLinkDeclaration> = emptyList(),
    val providers: List<ProviderDeclaration> = emptyList(),
    val signingCertificateSha256: List<String>,
    val signingCertificates: List<SigningCertificateSummary> = emptyList(),
    val signingSchemes: List<String> = emptyList(),
    val signingBlockIds: List<String> = emptyList(),
    val v1SignatureFiles: List<String> = emptyList(),
    val signingParseError: String? = null,
    val networkSecurity: NetworkSecurityConfigSummary? = null,
) : java.io.Serializable





data class Il2CppTableRange(
    val name: String,
    val offset: Long,
    val sizeBytes: Long,
) : java.io.Serializable

data class Il2CppTypeDefinitionSummary(
    val index: Int,
    val namespace: String,
    val name: String,
    val fullName: String,
    val methodStart: Int,
    val methodCount: Int,
    val fieldStart: Int,
    val fieldCount: Int,
    val token: Long,
) : java.io.Serializable

data class Il2CppMethodDefinitionSummary(
    val index: Int,
    val declaringTypeIndex: Int,
    val declaringType: String,
    val name: String,
    val parameterCount: Int,
    val token: Long,
    val flags: Int,
) : java.io.Serializable

data class Il2CppFieldDefinitionSummary(
    val index: Int,
    val declaringTypeIndex: Int,
    val declaringType: String,
    val name: String,
    val typeIndex: Int,
    val token: Long,
) : java.io.Serializable

data class Il2CppMetadataSummary(
    val entryName: String,
    val sizeBytes: Long,
    val magicValid: Boolean,
    val metadataVersion: Int?,
    val headerPairsScanned: Int,
    val assemblyNameCandidates: List<String>,
    val managedNameCandidates: List<String>,
    val unityVersionCandidates: List<String>,
    val layoutProfile: String? = null,
    val tableRanges: List<Il2CppTableRange> = emptyList(),
    val typeDefinitions: List<Il2CppTypeDefinitionSummary> = emptyList(),
    val methodDefinitions: List<Il2CppMethodDefinitionSummary> = emptyList(),
    val fieldDefinitions: List<Il2CppFieldDefinitionSummary> = emptyList(),
    val reconstructionTruncated: Boolean = false,
    val parseError: String? = null,
    val truncated: Boolean = false,
) : java.io.Serializable

data class Il2CppRegistrationCandidate(
    val kind: String,
    val libraryEntry: String,
    val symbolName: String,
    val virtualAddress: Long? = null,
    val sizeBytes: Long? = null,
    val validatedDefinedSymbol: Boolean = false,
) : java.io.Serializable

data class Il2CppSummary(
    val detected: Boolean,
    val confidence: String,
    val metadata: Il2CppMetadataSummary?,
    val libil2cppLibraries: List<String>,
    val il2cppApiSymbols: List<String>,
    val registrationIndicators: List<String>,
    val registrationCandidates: List<Il2CppRegistrationCandidate> = emptyList(),
    val parseErrors: Int,
    val truncated: Boolean,
) : java.io.Serializable



data class RuntimeProfileDetection(
    val kind: String,
    val confidence: String,
    val indicators: List<String>,
) : java.io.Serializable

data class RuntimeSummary(
    val profiles: List<RuntimeProfileDetection>,
) : java.io.Serializable



data class RuntimeFileReference(
    val entryName: String,
    val sizeBytes: Long,
) : java.io.Serializable

data class RuntimeArtifactFingerprint(
    val entryName: String,
    val kind: String,
    val sizeBytes: Long,
    val sha256: String,
) : java.io.Serializable

data class FlutterRuntimeSummary(
    val detected: Boolean,
    val confidence: String,
    val flutterLibraries: List<String>,
    val appLibraries: List<String>,
    val engineBuildIds: List<String>,
    val assetCount: Int,
    val representativeAssets: List<RuntimeFileReference>,
    val manifestEntries: List<String>,
    val snapshotEntries: List<String>,
    val kernelBlobEntries: List<String>,
    val aotLikely: Boolean,
    val artifactFingerprints: List<RuntimeArtifactFingerprint> = emptyList(),
    val truncated: Boolean,
) : java.io.Serializable

data class HermesFunctionSummary(
    val index: Int,
    val bytecodeOffset: Long?,
    val bytecodeSizeBytes: Long?,
    val parameterCount: Int?,
    val loopDepth: Int?,
    val functionNameId: Int?,
    val frameSize: Int?,
    val strictMode: Boolean?,
    val hasExceptionHandler: Boolean?,
    val hasDebugInfo: Boolean?,
    val overflowed: Boolean,
    val largeHeaderOffset: Long? = null,
) : java.io.Serializable

data class HermesBytecodeSummary(
    val entryName: String,
    val sizeBytes: Long,
    val magicValid: Boolean,
    val bytecodeVersion: Int?,
    val declaredFileLength: Long?,
    val globalCodeIndex: Long?,
    val functionCount: Long?,
    val stringKindCount: Long? = null,
    val identifierCount: Long?,
    val stringCount: Long?,
    val overflowStringCount: Long? = null,
    val stringStorageSize: Long? = null,
    val bigIntCount: Long? = null,
    val regExpCount: Long? = null,
    val literalValueBufferSize: Long? = null,
    val objKeyBufferSize: Long? = null,
    val objShapeTableCount: Long? = null,
    val segmentId: Long? = null,
    val cjsModuleCount: Long? = null,
    val functionSourceCount: Long? = null,
    val debugInfoOffset: Long? = null,
    val staticBuiltins: Boolean? = null,
    val structuredPrefixBytes: Long? = null,
    val functionsScanned: Int = 0,
    val functions: List<HermesFunctionSummary> = emptyList(),
    val sourceHashSha1: String?,
    val parseError: String? = null,
    val truncated: Boolean = false,
) : java.io.Serializable

data class HermesRuntimeSummary(
    val detected: Boolean,
    val confidence: String,
    val hermesLibraries: List<String>,
    val bytecodeFiles: List<HermesBytecodeSummary>,
    val javascriptBundles: List<RuntimeFileReference>,
    val truncated: Boolean,
) : java.io.Serializable

data class ManagedMetadataStreamSummary(
    val name: String,
    val offset: Long,
    val sizeBytes: Long,
) : java.io.Serializable

data class ManagedMetadataTableSummary(
    val tableId: Int,
    val name: String,
    val rowCount: Long,
) : java.io.Serializable

data class ManagedTypeReferenceSummary(
    val index: Int,
    val namespace: String,
    val name: String,
    val fullName: String,
    val resolutionScopeToken: Long?,
) : java.io.Serializable

data class ManagedTypeDefinitionSummary(
    val index: Int,
    val namespace: String,
    val name: String,
    val fullName: String,
    val flags: Long,
    val extendsToken: Long?,
    val fieldStart: Int,
    val fieldCount: Int,
    val methodStart: Int,
    val methodCount: Int,
) : java.io.Serializable

data class ManagedMethodDefinitionSummary(
    val index: Int,
    val declaringType: String,
    val rva: Long,
    val implFlags: Int,
    val flags: Int,
    val name: String,
    val signatureBlobIndex: Long,
    val paramStart: Int,
) : java.io.Serializable

data class ManagedMemberReferenceSummary(
    val index: Int,
    val parentToken: Long?,
    val name: String,
    val signatureBlobIndex: Long,
) : java.io.Serializable

data class ManagedAssemblyReferenceSummary(
    val index: Int,
    val name: String,
    val version: String,
    val culture: String?,
    val flags: Long,
) : java.io.Serializable

data class ManagedAssemblySummary(
    val entryName: String,
    val sizeBytes: Long,
    val peValid: Boolean,
    val cliMetadataPresent: Boolean,
    val metadataVersion: String?,
    val nameCandidates: List<String>,
    val metadataStreams: List<ManagedMetadataStreamSummary> = emptyList(),
    val metadataTables: List<ManagedMetadataTableSummary> = emptyList(),
    val assemblyName: String? = null,
    val assemblyVersion: String? = null,
    val typeReferences: List<ManagedTypeReferenceSummary> = emptyList(),
    val typeDefinitions: List<ManagedTypeDefinitionSummary> = emptyList(),
    val methodDefinitions: List<ManagedMethodDefinitionSummary> = emptyList(),
    val memberReferences: List<ManagedMemberReferenceSummary> = emptyList(),
    val assemblyReferences: List<ManagedAssemblyReferenceSummary> = emptyList(),
    val reconstructionTruncated: Boolean = false,
    val parseError: String? = null,
    val truncated: Boolean = false,
) : java.io.Serializable

data class UnityMonoRuntimeSummary(
    val detected: Boolean,
    val confidence: String,
    val monoLibraries: List<String>,
    val unityLibraries: List<String>,
    val assemblies: List<ManagedAssemblySummary>,
    val truncated: Boolean,
) : java.io.Serializable

data class UnrealContainerSummary(
    val entryName: String,
    val kind: String,
    val sizeBytes: Long,
    val probeSha256: String? = null,
    val probeBytes: Int = 0,
) : java.io.Serializable

data class UnrealRuntimeSummary(
    val detected: Boolean,
    val confidence: String,
    val engineLibraries: List<String>,
    val containers: List<UnrealContainerSummary>,
    val obbEntries: List<RuntimeFileReference>,
    val commandLineEntries: List<String>,
    val truncated: Boolean,
) : java.io.Serializable

data class RuntimeArtifactSummary(
    val flutter: FlutterRuntimeSummary? = null,
    val hermes: HermesRuntimeSummary? = null,
    val unityMono: UnityMonoRuntimeSummary? = null,
    val unreal: UnrealRuntimeSummary? = null,
) : java.io.Serializable

data class DependencyComponentSummary(
    val id: String,
    val name: String,
    val ecosystem: String,
    val version: String? = null,
    val purl: String? = null,
    val confidence: String,
    val evidence: List<String>,
    val versionEvidence: String? = null,
) : java.io.Serializable

data class AdvisoryFeedProvenance(
    val schemaVersion: String,
    val feedId: String,
    val source: String,
    val generatedAt: String,
    val sha256: String,
    val advisoryCount: Int,
    val format: String = "UNIREVLAB_NORMALIZED",
    val adapterVersion: String? = null,
    val skippedAdvisoryCount: Int = 0,
    val signatureVerified: Boolean = false,
    val signingKeyId: String? = null,
    val signatureAlgorithm: String? = null,
    val envelopeSha256: String? = null,
) : java.io.Serializable

data class VulnerabilityAdvisoryMatch(
    val advisoryId: String,
    val aliases: List<String> = emptyList(),
    val componentId: String,
    val componentVersion: String,
    val severity: String,
    val summary: String,
    val source: String,
    /** Exact version or a conservative ecosystem-specific range resolver evidence string. */
    val matchBasis: String = "EXACT_COMPONENT_VERSION",
) : java.io.Serializable

data class SupplyChainSummary(
    val components: List<DependencyComponentSummary>,
    val nativeDependencies: List<String>,
    val advisoryFeed: AdvisoryFeedProvenance? = null,
    val vulnerabilities: List<VulnerabilityAdvisoryMatch> = emptyList(),
    val truncated: Boolean,
) : java.io.Serializable

data class StaticAnalysisReport(
    val schemaVersion: String = "1.19",
    val engineVersion: String,
    val assessment: AssessmentScope,
    val artifact: ArtifactSummary,
    val manifest: ManifestSummary?,
    val resources: ResourceTableSummary? = null,
    val dex: DexSummary? = null,
    val native: NativeSummary? = null,
    val il2cpp: Il2CppSummary? = null,
    val ghidra: List<GhidraLibraryAnalysis> = emptyList(),
    val correlations: CrossRuntimeCorrelationSummary? = null,
    val manifestDexReachability: ManifestDexReachabilitySummary? = null,
    val runtimes: RuntimeSummary? = null,
    val runtimeArtifacts: RuntimeArtifactSummary? = null,
    val supplyChain: SupplyChainSummary? = null,
    val findings: List<Finding>,
) : java.io.Serializable

data class NativeSymbolReference(
    val libraryEntry: String,
    val name: String,
    val binding: String,
    val symbolType: String,
    val defined: Boolean,
    val virtualAddress: Long? = null,
    val sizeBytes: Long? = null,
) : java.io.Serializable


data class NativeSecretCandidate(
    val kind: String,
    val libraryEntry: String,
    val valueSha256: String,
    val redactedPreview: String,
) : java.io.Serializable

data class NativeLibrarySummary(
    val entryName: String,
    val abi: String,
    val elfClass: String,
    val machine: String,
    val fileType: String,
    val sizeBytes: Long,
    val buildId: String?,
    val neededLibraries: List<String>,
    val importedSymbols: List<NativeSymbolReference>,
    val exportedSymbols: List<NativeSymbolReference>,
    val jniSymbols: List<String>,
    val hasJniOnLoad: Boolean,
    val registerNativesIndicator: Boolean,
    val executableStack: Boolean?,
    val hasGnuRelro: Boolean,
    val bindNow: Boolean,
    val hasStackCanaryImport: Boolean,
    val stripped: Boolean?,
    val httpUrls: List<String>,
    val secretCandidates: List<NativeSecretCandidate> = emptyList(),
    val parseError: String? = null,
    val truncated: Boolean = false,
) : java.io.Serializable


data class JniBridgeReference(
    val dexEntry: String,
    val declaringClass: String,
    val methodName: String,
    val prototype: String,
    val resolution: String,
    val libraryEntry: String? = null,
    val nativeSymbol: String? = null,
) : java.io.Serializable

data class NativeSummary(
    val librariesDiscovered: Int,
    val librariesScanned: Int,
    val libraries: List<NativeLibrarySummary>,
    val jniBridges: List<JniBridgeReference> = emptyList(),
    val parseErrors: Int,
    val truncated: Boolean,
) : java.io.Serializable
