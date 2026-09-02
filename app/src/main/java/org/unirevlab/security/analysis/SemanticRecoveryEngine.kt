package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexFieldReference
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Evidence-fusion layer for analyst deobfuscation.
 *
 * This engine never executes target code and never claims inferred aliases are developer-original
 * identifiers. It combines independent static signals already recovered by UniRevLab: surviving
 * source metadata, inheritance/interfaces, Android component identity, resource IDs, call/type
 * xrefs, and JNI/native correlations. The strongest deterministic alias is emitted with provenance.
 */
object SemanticRecoveryEngine {
    enum class EvidenceKind {
        SOURCE_METADATA,
        INHERITANCE,
        ANDROID_COMPONENT,
        RESOURCE,
        CALL_GRAPH,
        TYPE_FLOW,
        JNI_NATIVE,
        CROSS_RUNTIME,
    }

    data class Entry(
        val kind: String,
        val obfuscatedSymbol: String,
        val alias: String,
        val confidence: AnalystMappingEngine.Confidence,
        val score: Int,
        val evidenceKinds: Set<EvidenceKind>,
        val evidence: List<String>,
    )

    data class Result(
        val entries: List<Entry>,
        val highConfidence: Int,
        val mediumConfidence: Int,
        val lowConfidence: Int,
        val sourceMetadataHits: Int,
        val inheritanceHits: Int,
        val componentHits: Int,
        val resourceHits: Int,
        val callGraphHits: Int,
        val typeFlowHits: Int,
        val jniHits: Int,
        val crossRuntimeHits: Int,
        val coverageComplete: Boolean,
    )

    private data class MethodKey(val dexEntry: String, val methodIndex: Int)
    private data class Candidate(
        val aliasBase: String,
        val score: Int,
        val kind: EvidenceKind,
        val evidence: String,
    )

    fun generate(report: StaticAnalysisReport, maxEntries: Int = 20_000): Result {
        val dex = report.dex ?: return emptyResult()
        if (maxEntries <= 0) return emptyResult()

        val classByDescriptor = dex.classes.associateBy { it.descriptor }
        val methodsByClass = dex.methods.groupBy { it.declaringClass }
        val outgoing = dex.callXrefs.groupBy { MethodKey(it.dexEntry, it.callerMethodIndex) }
        val incoming = dex.callXrefs.groupBy { MethodKey(it.dexEntry, it.calleeMethodIndex) }
        val typeXrefs = dex.typeXrefs.groupBy { MethodKey(it.dexEntry, it.callerMethodIndex) }
        val constants = dex.constants.groupBy { MethodKey(it.dexEntry, it.methodIndex) }
        val resources = report.resources?.resolutions.orEmpty()
            .asSequence()
            .filter { !it.entryName.isNullOrBlank() }
            .groupBy { it.resourceId }

        val componentKinds = componentKinds(report)
        val jniBridges = report.native?.jniBridges.orEmpty().groupBy {
            Triple(it.declaringClass, it.methodName, it.prototype)
        }
        val jniCorrelations = report.correlations?.jniNative.orEmpty().groupBy {
            Triple(it.declaringClass, it.methodName, it.prototype)
        }

        val entries = ArrayList<Entry>()
        fun add(entry: Entry?) {
            if (entry != null && entries.size < maxEntries) entries += entry
        }

        dex.classes.asSequence()
            .filterNot { isFrameworkDescriptor(it.descriptor) || isGeneratedDescriptor(it.descriptor) }
            .filter { looksObfuscatedSimpleName(simpleClassName(it.descriptor)) }
            .forEach { cls ->
                val candidates = mutableListOf<Candidate>()

                plausibleSourceBase(cls.sourceFile)?.let { sourceBase ->
                    candidates += Candidate(
                        aliasBase = sourceBase,
                        score = 94,
                        kind = EvidenceKind.SOURCE_METADATA,
                        evidence = "Surviving DEX source_file: ${cls.sourceFile}",
                    )
                }

                componentKinds[cls.descriptor]?.let { kind ->
                    candidates += Candidate(
                        aliasBase = componentAlias(kind),
                        score = 96,
                        kind = EvidenceKind.ANDROID_COMPONENT,
                        evidence = "AndroidManifest component kind: $kind",
                    )
                }

                inheritanceAlias(cls)?.let { (alias, evidence) ->
                    candidates += Candidate(
                        aliasBase = alias,
                        score = 78,
                        kind = EvidenceKind.INHERITANCE,
                        evidence = evidence,
                    )
                }

                val classResourceNames = methodsByClass[cls.descriptor].orEmpty()
                    .asSequence()
                    .flatMap { method -> resourceNamesFor(method, constants, resources).asSequence() }
                    .distinct()
                    .take(6)
                    .toList()
                classResourceNames.firstOrNull()?.let { resource ->
                    candidates += Candidate(
                        aliasBase = "${resource.toPascalIdentifier()}Screen",
                        score = 64,
                        kind = EvidenceKind.RESOURCE,
                        evidence = "Compiled Android resource used by class: $resource",
                    )
                }

                val semanticMethods = methodsByClass[cls.descriptor].orEmpty().mapNotNull { method ->
                    inferMethodCandidate(
                        method = method,
                        outgoing = outgoing,
                        incoming = incoming,
                        typeXrefs = typeXrefs,
                        constants = constants,
                        resources = resources,
                        jniBridges = jniBridges,
                        jniCorrelations = jniCorrelations,
                        classByDescriptor = classByDescriptor,
                    )
                }
                semanticMethods.maxByOrNull { it.score }?.let { best ->
                    candidates += Candidate(
                        aliasBase = best.aliasBase.toPascalIdentifier() + "Class",
                        score = (best.score - 12).coerceAtLeast(45),
                        kind = best.kind,
                        evidence = "Class contains semantically recovered method: ${best.evidence}",
                    )
                }

                add(toEntry("CLASS", cls.descriptor, candidates, suffix = "c${cls.classIndex}"))
            }

        dex.methods.asSequence()
            .filterNot { isFrameworkDescriptor(it.declaringClass) }
            .filterNot { it.name == "<init>" || it.name == "<clinit>" }
            .filter { looksObfuscatedSimpleName(it.name) }
            .forEach { method ->
                val candidate = inferMethodCandidate(
                    method = method,
                    outgoing = outgoing,
                    incoming = incoming,
                    typeXrefs = typeXrefs,
                    constants = constants,
                    resources = resources,
                    jniBridges = jniBridges,
                    jniCorrelations = jniCorrelations,
                    classByDescriptor = classByDescriptor,
                )
                add(candidate?.let {
                    toEntry(
                        kind = "METHOD",
                        symbol = methodSymbol(method),
                        candidates = listOf(it),
                        suffix = "m${method.methodIndex}",
                    )
                })
            }

        val fields = if (dex.fields.isNotEmpty()) dex.fields else dex.fieldXrefs.map {
            DexFieldReference(it.dexEntry, it.fieldIndex, it.declaringClass, it.fieldName, it.fieldType)
        }
        fields.asSequence()
            .filterNot { isFrameworkDescriptor(it.declaringClass) }
            .filter { looksObfuscatedSimpleName(it.name) }
            .distinctBy { Triple(it.dexEntry, it.declaringClass, it.fieldIndex) }
            .forEach { field ->
                val type = field.type
                val simple = simpleClassName(type)
                if (!isFrameworkDescriptor(type) && !looksObfuscatedSimpleName(simple) && simple.length >= 4) {
                    add(
                        toEntry(
                            kind = "FIELD",
                            symbol = fieldSymbol(field),
                            candidates = listOf(
                                Candidate(
                                    aliasBase = simple.toLowerCamelIdentifier(),
                                    score = 67,
                                    kind = EvidenceKind.TYPE_FLOW,
                                    evidence = "Readable field type survived obfuscation: ${descriptorToDotName(type)}",
                                ),
                            ),
                            suffix = "f${field.fieldIndex}",
                        ),
                    )
                }
            }

        val ordered = entries
            .distinctBy { "${it.kind}|${it.obfuscatedSymbol}" }
            .sortedWith(compareBy<Entry>({ confidenceOrder(it.confidence) }, { -it.score }, { it.kind }, { it.obfuscatedSymbol }))
            .take(maxEntries)

        return Result(
            entries = ordered,
            highConfidence = ordered.count { it.confidence == AnalystMappingEngine.Confidence.HIGH },
            mediumConfidence = ordered.count { it.confidence == AnalystMappingEngine.Confidence.MEDIUM },
            lowConfidence = ordered.count { it.confidence == AnalystMappingEngine.Confidence.LOW },
            sourceMetadataHits = ordered.count { EvidenceKind.SOURCE_METADATA in it.evidenceKinds },
            inheritanceHits = ordered.count { EvidenceKind.INHERITANCE in it.evidenceKinds },
            componentHits = ordered.count { EvidenceKind.ANDROID_COMPONENT in it.evidenceKinds },
            resourceHits = ordered.count { EvidenceKind.RESOURCE in it.evidenceKinds },
            callGraphHits = ordered.count { EvidenceKind.CALL_GRAPH in it.evidenceKinds },
            typeFlowHits = ordered.count { EvidenceKind.TYPE_FLOW in it.evidenceKinds },
            jniHits = ordered.count { EvidenceKind.JNI_NATIVE in it.evidenceKinds },
            crossRuntimeHits = ordered.count { EvidenceKind.CROSS_RUNTIME in it.evidenceKinds },
            coverageComplete = !dex.truncated && dex.parseErrors == 0 &&
                dex.classesIndexed >= dex.classesDeclared && dex.methodsIndexed >= dex.methodsDeclared,
        )
    }

    private fun inferMethodCandidate(
        method: DexMethodReference,
        outgoing: Map<MethodKey, List<org.unirevlab.security.model.DexMethodCallXref>>,
        incoming: Map<MethodKey, List<org.unirevlab.security.model.DexMethodCallXref>>,
        typeXrefs: Map<MethodKey, List<org.unirevlab.security.model.DexTypeXref>>,
        constants: Map<MethodKey, List<org.unirevlab.security.model.DexConstantReference>>,
        resources: Map<Long, List<org.unirevlab.security.model.ResourceResolutionSummary>>,
        jniBridges: Map<Triple<String, String, String>, List<org.unirevlab.security.model.JniBridgeReference>>,
        jniCorrelations: Map<Triple<String, String, String>, List<org.unirevlab.security.model.JniNativeCorrelation>>,
        classByDescriptor: Map<String, DexClassReference>,
    ): Candidate? {
        val key = MethodKey(method.dexEntry, method.methodIndex)
        val candidates = mutableListOf<Candidate>()
        val jniKey = Triple(method.declaringClass, method.name, method.prototype)

        jniCorrelations[jniKey].orEmpty().firstOrNull { !it.functionName.isNullOrBlank() }?.let { correlation ->
            val name = correlation.functionName?.let(::nativeSemanticName)
            if (!name.isNullOrBlank()) {
                candidates += Candidate(
                    aliasBase = name,
                    score = 98,
                    kind = EvidenceKind.CROSS_RUNTIME,
                    evidence = "DEX↔native correlation: ${correlation.libraryEntry}!${correlation.functionName} (${correlation.confidence})",
                )
            }
        }

        jniBridges[jniKey].orEmpty().firstOrNull { !it.nativeSymbol.isNullOrBlank() }?.let { bridge ->
            val name = bridge.nativeSymbol?.let(::nativeSemanticName)
            if (!name.isNullOrBlank()) {
                candidates += Candidate(
                    aliasBase = name,
                    score = 92,
                    kind = EvidenceKind.JNI_NATIVE,
                    evidence = "Resolved JNI bridge: ${bridge.libraryEntry ?: "native"}!${bridge.nativeSymbol}",
                )
            }
        }

        resourceNamesFor(method, constants, resources).firstOrNull()?.let { resource ->
            candidates += Candidate(
                aliasBase = resource.toLowerCamelIdentifier() + "Flow",
                score = 72,
                kind = EvidenceKind.RESOURCE,
                evidence = "Method references compiled Android resource: $resource",
            )
        }

        outgoing[key].orEmpty()
            .asSequence()
            .filter { !isFrameworkDescriptor(it.calleeClass) }
            .map { it.calleeName }
            .firstOrNull { readableSemanticMember(it) }
            ?.let { callee ->
                candidates += Candidate(
                    aliasBase = callee.toLowerCamelIdentifier() + "Flow",
                    score = 68,
                    kind = EvidenceKind.CALL_GRAPH,
                    evidence = "Calls readable application method: $callee",
                )
            }

        outgoing[key].orEmpty()
            .asSequence()
            .filter { isFrameworkDescriptor(it.calleeClass) }
            .mapNotNull { apiRole(it.calleeClass, it.calleeName) }
            .firstOrNull()
            ?.let { role ->
                candidates += Candidate(
                    aliasBase = role,
                    score = 74,
                    kind = EvidenceKind.CALL_GRAPH,
                    evidence = "Framework API role recovered from outgoing call graph: $role",
                )
            }

        incoming[key].orEmpty()
            .asSequence()
            .map { it.callerName }
            .firstOrNull { readableSemanticMember(it) }
            ?.let { caller ->
                candidates += Candidate(
                    aliasBase = caller.toLowerCamelIdentifier() + "Delegate",
                    score = 63,
                    kind = EvidenceKind.CALL_GRAPH,
                    evidence = "Invoked by readable method: $caller",
                )
            }

        typeXrefs[key].orEmpty()
            .asSequence()
            .map { it.descriptor }
            .filter { !isFrameworkDescriptor(it) }
            .map { descriptor -> classByDescriptor[descriptor]?.let { simpleClassName(it.descriptor) } ?: simpleClassName(descriptor) }
            .firstOrNull { !looksObfuscatedSimpleName(it) && it.length >= 4 }
            ?.let { typeName ->
                candidates += Candidate(
                    aliasBase = typeName.toLowerCamelIdentifier() + "Flow",
                    score = 61,
                    kind = EvidenceKind.TYPE_FLOW,
                    evidence = "Readable application type xref: $typeName",
                )
            }

        return candidates.maxWithOrNull(compareBy<Candidate>({ it.score }, { it.aliasBase }))
    }

    private fun toEntry(kind: String, symbol: String, candidates: List<Candidate>, suffix: String): Entry? {
        if (candidates.isEmpty()) return null
        val ordered = candidates.sortedWith(compareByDescending<Candidate> { it.score }.thenBy { it.aliasBase })
        val best = ordered.first()
        val corroborating = ordered.filter { it.kind != best.kind }.take(3)
        val independentKinds = (listOf(best) + corroborating).mapTo(linkedSetOf()) { it.kind }
        val boosted = (best.score + (independentKinds.size - 1).coerceAtLeast(0) * 4).coerceAtMost(100)
        val confidence = when {
            boosted >= 88 -> AnalystMappingEngine.Confidence.HIGH
            boosted >= 66 -> AnalystMappingEngine.Confidence.MEDIUM
            else -> AnalystMappingEngine.Confidence.LOW
        }
        val alias = sanitizeAlias("${best.aliasBase}_$suffix")
        return Entry(
            kind = kind,
            obfuscatedSymbol = symbol,
            alias = alias,
            confidence = confidence,
            score = boosted,
            evidenceKinds = independentKinds,
            evidence = (listOf(best) + corroborating).map { it.evidence }.distinct().take(5),
        )
    }

    private fun resourceNamesFor(
        method: DexMethodReference,
        constants: Map<MethodKey, List<org.unirevlab.security.model.DexConstantReference>>,
        resources: Map<Long, List<org.unirevlab.security.model.ResourceResolutionSummary>>,
    ): List<String> {
        val key = MethodKey(method.dexEntry, method.methodIndex)
        return constants[key].orEmpty().asSequence()
            .mapNotNull { parseIntegralConstant(it.value) }
            .flatMap { value -> resources[value].orEmpty().asSequence() }
            .mapNotNull { resolution ->
                val entry = resolution.entryName?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val type = resolution.typeName?.takeIf { it.isNotBlank() }
                if (type == null) entry else "${type}_$entry"
            }
            .distinct()
            .take(6)
            .toList()
    }

    private fun inheritanceAlias(cls: DexClassReference): Pair<String, String>? {
        val descriptors = buildList {
            cls.superDescriptor?.let(::add)
            addAll(cls.interfaces)
        }
        descriptors.forEach { descriptor ->
            val simple = simpleClassName(descriptor)
            val role = inheritanceRole(simple) ?: return@forEach
            return role to "Inheritance/interface evidence: ${descriptorToDotName(descriptor)}"
        }
        return null
    }

    private fun inheritanceRole(simple: String): String? {
        val normalized = simple.lowercase()
        return when {
            normalized.endsWith("activity") -> "Activity"
            normalized.endsWith("fragment") -> "Fragment"
            normalized.endsWith("viewmodel") -> "ViewModel"
            normalized.endsWith("service") -> "Service"
            normalized.endsWith("receiver") -> "Receiver"
            normalized.endsWith("provider") -> "Provider"
            normalized.endsWith("repository") -> "Repository"
            normalized.endsWith("adapter") -> "Adapter"
            normalized.endsWith("worker") -> "Worker"
            normalized.endsWith("listener") -> "Listener"
            normalized.endsWith("callback") -> "Callback"
            normalized.endsWith("application") -> "Application"
            else -> null
        }
    }

    private fun componentKinds(report: StaticAnalysisReport): Map<String, String> {
        val manifest = report.manifest ?: return emptyMap()
        return buildMap {
            manifest.components.forEach { component ->
                componentDescriptor(manifest.packageName, component.name)?.let { put(it, component.kind) }
            }
        }
    }

    private fun componentAlias(kind: String): String = when (kind.lowercase()) {
        "activity" -> "Activity"
        "service" -> "Service"
        "receiver" -> "Receiver"
        "provider" -> "Provider"
        else -> "AndroidComponent"
    }

    private fun componentDescriptor(packageName: String, rawName: String): String? {
        val name = rawName.trim()
        if (name.isBlank()) return null
        val fqcn = when {
            name.startsWith('.') -> packageName + name
            '.' !in name -> "$packageName.$name"
            else -> name
        }
        return "L${fqcn.replace('.', '/')};"
    }

    private fun apiRole(owner: String, name: String): String? {
        val text = "$owner->$name".lowercase()
        return when {
            "json" in text && name.lowercase() in setOf("fromjson", "parse", "optstring", "getstring") -> "parseJson"
            "cipher" in text || "messagedigest" in text || "mac" in text -> "cryptoOperation"
            "sharedpreferences" in text -> "preferencesAccess"
            "sqlite" in text || "room" in text -> "databaseAccess"
            "urlconnection" in text || "okhttp" in text || "retrofit" in text -> "networkRequest"
            "objectinputstream" in text && name.equals("readObject", ignoreCase = true) -> "deserializeObject"
            "packageinfo" in text || "signinginfo" in text || "signature" in text -> "signatureInspection"
            "debug" in text && name.lowercase().contains("debug") -> "debugCheck"
            else -> null
        }
    }

    private fun nativeSemanticName(symbol: String): String? {
        val clean = symbol.substringAfterLast("::")
            .substringAfterLast('/')
            .replace(Regex("[^A-Za-z0-9_$]"), "_")
            .trim('_')
        if (clean.isBlank() || clean.lowercase() in GENERIC_NATIVE_NAMES) return null
        val tail = if (clean.startsWith("Java_")) clean.substringAfterLast('_') else clean
        if (tail.length < 3 || tail.all { it.isDigit() }) return null
        return "native${tail.toPascalIdentifier()}"
    }

    private fun plausibleSourceBase(sourceFile: String?): String? {
        val raw = sourceFile?.trim()?.substringAfterLast('/') ?: return null
        val base = raw.substringBeforeLast('.', raw).trim()
        if (base.length < 3) return null
        if (base.lowercase() in GENERIC_SOURCE_FILES) return null
        if (looksObfuscatedSimpleName(base)) return null
        return base.toPascalIdentifier().takeIf { it.length >= 3 }
    }

    private fun readableSemanticMember(name: String): Boolean {
        if (name.length < 4 || looksObfuscatedSimpleName(name)) return false
        if (name in GENERIC_METHOD_NAMES) return false
        return name.any(Char::isLetter)
    }

    private fun parseIntegralConstant(value: String): Long? {
        val clean = value.trim().removeSuffix("L").removeSuffix("l")
        return when {
            clean.startsWith("0x", ignoreCase = true) -> clean.substring(2).toLongOrNull(16)
            clean.startsWith("-0x", ignoreCase = true) -> clean.substring(3).toLongOrNull(16)?.let { -it }
            else -> clean.toLongOrNull()
        }
    }

    private fun methodSymbol(method: DexMethodReference): String =
        "${method.declaringClass}->${method.name}${method.prototype}"

    private fun fieldSymbol(field: DexFieldReference): String =
        "${field.declaringClass}->${field.name}:${field.type}"

    private fun simpleClassName(descriptor: String): String = descriptor
        .removePrefix("L")
        .removeSuffix(";")
        .substringAfterLast('/')
        .substringAfterLast('$')

    private fun descriptorToDotName(descriptor: String): String = descriptor
        .removePrefix("L")
        .removeSuffix(";")
        .replace('/', '.')

    private fun looksObfuscatedSimpleName(name: String): Boolean {
        if (name.isBlank()) return false
        if (name in SAFE_SHORT_NAMES) return false
        return (name.length <= 2 && name.all { it.isLetterOrDigit() || it == '_' || it == '$' }) ||
            OPAQUE_NAME.matches(name)
    }

    private fun isFrameworkDescriptor(descriptor: String): Boolean = FRAMEWORK_PREFIXES.any(descriptor::startsWith)

    private fun isGeneratedDescriptor(descriptor: String): Boolean {
        val simple = descriptor.removeSuffix(";").substringAfterLast('/')
        return simple == "R" || simple.startsWith("R$") || simple == "BuildConfig"
    }

    private fun sanitizeAlias(value: String): String = value
        .map { if (it.isLetterOrDigit() || it == '_' || it == '$') it else '_' }
        .joinToString("")
        .trim('_')
        .take(120)
        .ifBlank { "RecoveredSymbol" }

    private fun String.toPascalIdentifier(): String {
        val pieces = split(Regex("[^A-Za-z0-9]+"))
            .filter { it.isNotBlank() }
        val joined = pieces.joinToString("") { piece ->
            piece.replaceFirstChar { ch -> if (ch.isLowerCase()) ch.titlecase() else ch.toString() }
        }
        return joined.ifBlank { "Recovered" }.take(80)
    }

    private fun String.toLowerCamelIdentifier(): String {
        val pascal = toPascalIdentifier()
        return pascal.replaceFirstChar { ch -> if (ch.isUpperCase()) ch.lowercase() else ch.toString() }
    }

    private fun confidenceOrder(value: AnalystMappingEngine.Confidence): Int = when (value) {
        AnalystMappingEngine.Confidence.HIGH -> 0
        AnalystMappingEngine.Confidence.MEDIUM -> 1
        AnalystMappingEngine.Confidence.LOW -> 2
    }

    private fun emptyResult() = Result(
        entries = emptyList(),
        highConfidence = 0,
        mediumConfidence = 0,
        lowConfidence = 0,
        sourceMetadataHits = 0,
        inheritanceHits = 0,
        componentHits = 0,
        resourceHits = 0,
        callGraphHits = 0,
        typeFlowHits = 0,
        jniHits = 0,
        crossRuntimeHits = 0,
        coverageComplete = false,
    )

    private val OPAQUE_NAME = Regex("^[a-zA-Z]{1,2}[0-9]{0,2}$")
    private val FRAMEWORK_PREFIXES = listOf(
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Lorg/json/", "Lokhttp3/", "Lretrofit2/", "Lcom/google/", "Lcom/android/",
    )
    private val SAFE_SHORT_NAMES = setOf("R", "id", "x", "y", "z")
    private val GENERIC_METHOD_NAMES = setOf(
        "invoke", "run", "call", "apply", "accept", "get", "set", "put", "add", "remove", "create", "build",
    )
    private val GENERIC_SOURCE_FILES = setOf(
        "sourcefile", "unknown", "r8", "proguard", "synthetic", "lambda", "generated", "buildconfig",
    )
    private val GENERIC_NATIVE_NAMES = setOf(
        "jni_onload", "register_natives", "registernatives", "sub", "func", "function", "unknown",
    )
}
