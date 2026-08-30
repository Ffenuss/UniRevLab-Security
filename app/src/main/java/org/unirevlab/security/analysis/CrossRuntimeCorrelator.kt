package org.unirevlab.security.analysis

import org.unirevlab.security.model.*

/**
 * Evidence-backed cross-runtime correlation. This code never executes target code and deliberately
 * refuses ambiguous mappings instead of guessing native addresses.
 */
object CrossRuntimeCorrelator {
    data class Limits(
        val maxJniMethods: Int = 20_000,
        val maxIl2CppMethods: Int = 100_000,
        val maxCorrelations: Int = 20_000,
    )

    fun correlate(
        dex: DexSummary?,
        il2cpp: Il2CppSummary?,
        ghidra: List<GhidraLibraryAnalysis>,
        limits: Limits = Limits(),
    ): CrossRuntimeCorrelationSummary {
        if (ghidra.isEmpty()) return CrossRuntimeCorrelationSummary(
            dexNativeMethodsConsidered = dex?.nativeMethods?.size ?: 0,
            il2cppMethodsConsidered = il2cpp?.metadata?.methodDefinitions?.size ?: 0,
        )

        val jniMethods = dex?.nativeMethods.orEmpty().take(limits.maxJniMethods)
        val jni = correlateJni(jniMethods, ghidra, limits.maxCorrelations)
        val registrations = correlateIl2CppRegistrations(il2cpp, ghidra, limits.maxCorrelations)
        val managedMethods = il2cpp?.metadata?.methodDefinitions.orEmpty().take(limits.maxIl2CppMethods)
        val il2cppMethods = correlateIl2CppMethods(
            metadataEntry = il2cpp?.metadata?.entryName,
            assemblyNames = il2cpp?.metadata?.assemblyNameCandidates.orEmpty(),
            methods = managedMethods,
            analyses = ghidra,
            maxCorrelations = limits.maxCorrelations,
        )

        val truncated = (dex?.nativeMethods?.size ?: 0) > jniMethods.size ||
            (il2cpp?.metadata?.methodDefinitions?.size ?: 0) > managedMethods.size ||
            jni.size >= limits.maxCorrelations || registrations.size >= limits.maxCorrelations ||
            il2cppMethods.size >= limits.maxCorrelations

        return CrossRuntimeCorrelationSummary(
            jniNative = jni,
            il2cppRegistrations = registrations,
            il2cppMethods = il2cppMethods,
            dexNativeMethodsConsidered = jniMethods.size,
            dexNativeMethodsResolved = jni.map { it.dexEntry to it.dexMethodIndex }.distinct().size,
            il2cppMethodsConsidered = managedMethods.size,
            il2cppMethodsResolved = il2cppMethods.map { it.methodIndex }.distinct().size,
            truncated = truncated,
        )
    }

    private fun correlateJni(
        methods: List<DexNativeMethodDeclaration>,
        analyses: List<GhidraLibraryAnalysis>,
        maxCorrelations: Int,
    ): List<JniNativeCorrelation> {
        if (methods.isEmpty()) return emptyList()
        val results = mutableListOf<JniNativeCorrelation>()
        val methodsByNameAndProto = methods.groupBy { it.name to it.prototype }
        val methodsByClassAndName = methods.groupBy { normalizeClass(it.declaringClass) to it.name }

        for (analysis in analyses.sortedBy { it.libraryEntry }) {
            val functionsByRva = analysis.functions.associateBy { it.rva }
            for (registration in analysis.jniRegistrations.sortedWith(compareBy({ it.functionRva }, { it.methodName }, { it.signature }))) {
                if (results.size >= maxCorrelations) break
                val candidates: List<DexNativeMethodDeclaration>
                val evidence: String
                val confidence: String
                val normalizedClass = normalizeClass(registration.className)

                if (registration.className == "<dynamic>") {
                    if (registration.signature.isBlank()) continue
                    val global = methodsByNameAndProto[registration.methodName to registration.signature].orEmpty()
                    if (global.size != 1) continue
                    candidates = global
                    evidence = "REGISTER_NATIVES_UNIQUE_NAME_SIGNATURE"
                    confidence = registration.confidence
                } else {
                    val sameClassName = methodsByClassAndName[normalizedClass to registration.methodName].orEmpty()
                    if (registration.signature.isNotBlank()) {
                        val exact = sameClassName.filter { it.prototype == registration.signature }
                        if (exact.size != 1) continue
                        candidates = exact
                        evidence = "EXACT_CLASS_METHOD_SIGNATURE"
                        confidence = registration.confidence
                    } else {
                        // Static JNI exports do not encode the full prototype unless the long JNI name is present.
                        // Only accept the short-name export when the DEX declaration is unambiguous.
                        if (sameClassName.size != 1) continue
                        candidates = sameClassName
                        evidence = "UNIQUE_STATIC_EXPORT_CLASS_METHOD"
                        confidence = minConfidence(registration.confidence, "MEDIUM")
                    }
                }

                val fn = functionsByRva[registration.functionRva]
                candidates.forEach { method ->
                    if (results.size < maxCorrelations) {
                        results += JniNativeCorrelation(
                            dexEntry = method.dexEntry,
                            dexMethodIndex = method.methodIndex,
                            declaringClass = method.declaringClass,
                            methodName = method.name,
                            prototype = method.prototype,
                            libraryEntry = analysis.libraryEntry,
                            functionRva = registration.functionRva,
                            functionName = fn?.name,
                            source = registration.source,
                            confidence = confidence,
                            evidence = evidence,
                        )
                    }
                }
            }
        }
        return results.distinctBy {
            listOf(it.dexEntry, it.dexMethodIndex.toString(), it.libraryEntry, it.functionRva.toString())
        }.sortedWith(compareBy({ it.dexEntry }, { it.dexMethodIndex }, { it.libraryEntry }, { it.functionRva }))
    }

    private fun correlateIl2CppRegistrations(
        il2cpp: Il2CppSummary?,
        analyses: List<GhidraLibraryAnalysis>,
        maxCorrelations: Int,
    ): List<Il2CppRegistrationCorrelation> {
        val staticCandidates = il2cpp?.registrationCandidates.orEmpty()
        if (staticCandidates.isEmpty()) return emptyList()
        val out = mutableListOf<Il2CppRegistrationCorrelation>()
        for (static in staticCandidates.sortedWith(compareBy({ it.libraryEntry }, { it.kind }, { it.symbolName }))) {
            val analysis = analyses.firstOrNull { sameLibrary(it.libraryEntry, static.libraryEntry) } ?: continue
            val matches = analysis.il2cppRegistrations.filter { g ->
                g.kind == static.kind && (
                    (static.virtualAddress != null && static.virtualAddress == g.rva) ||
                        normalizeSymbol(static.symbolName) == normalizeSymbol(g.symbolName)
                    )
            }
            if (matches.size != 1) continue
            val match = matches.single()
            val exactAddress = static.virtualAddress != null && static.virtualAddress == match.rva
            out += Il2CppRegistrationCorrelation(
                kind = static.kind,
                libraryEntry = analysis.libraryEntry,
                staticSymbolName = static.symbolName,
                staticVirtualAddress = static.virtualAddress,
                ghidraSymbolName = match.symbolName,
                ghidraRva = match.rva,
                evidence = if (exactAddress) "STATIC_AND_GHIDRA_RVA_MATCH" else "UNIQUE_SYMBOL_IDENTITY_MATCH",
                confidence = if (exactAddress && static.validatedDefinedSymbol) "HIGH" else minConfidence(match.confidence, "MEDIUM"),
            )
            if (out.size >= maxCorrelations) break
        }
        return out.distinctBy { listOf(it.kind, it.libraryEntry, it.ghidraRva.toString()) }
            .sortedWith(compareBy({ it.libraryEntry }, { it.kind }, { it.ghidraRva }))
    }

    private fun correlateIl2CppMethods(
        metadataEntry: String?,
        assemblyNames: List<String>,
        methods: List<Il2CppMethodDefinitionSummary>,
        analyses: List<GhidraLibraryAnalysis>,
        maxCorrelations: Int,
    ): List<Il2CppMethodNativeCorrelation> {
        if (metadataEntry == null || methods.isEmpty()) return emptyList()
        data class IndexedFunction(
            val library: String,
            val function: GhidraFunctionSummary,
            val lowerIdentity: String,
            val normalizedIdentity: String,
        )
        val functions = ArrayList<IndexedFunction>()
        for (analysis in analyses) {
            if (!analysis.libraryEntry.lowercase().contains("il2cpp")) continue
            for (fn in analysis.functions) {
                val rawIdentity = fn.name + " " + fn.signature
                functions += IndexedFunction(
                    library = analysis.libraryEntry,
                    function = fn,
                    lowerIdentity = rawIdentity.lowercase(),
                    normalizedIdentity = normalizeIdentifier(fn.namespace + " " + rawIdentity),
                )
            }
        }
        if (functions.isEmpty()) return emptyList()

        fun uniqueFunction(predicate: (IndexedFunction) -> Boolean): IndexedFunction? {
            var found: IndexedFunction? = null
            for (candidate in functions) {
                if (!predicate(candidate)) continue
                if (found != null) return null
                found = candidate
            }
            return found
        }

        val moduleCandidates = analyses
            .filter { it.libraryEntry.lowercase().contains("il2cpp") }
            .flatMap { analysis -> analysis.il2cppCodegenModules.map { Triple(analysis.libraryEntry, analysis, it) } }
        val normalizedAssemblies = assemblyNames.map(::normalizeAssemblyName).filter { it.isNotBlank() }.toSet()
        val matchingModules = moduleCandidates.filter { normalizeAssemblyName(it.third.moduleName) in normalizedAssemblies }

        val out = mutableListOf<Il2CppMethodNativeCorrelation>()
        for (method in methods.sortedBy { it.index }) {
            if (out.size >= maxCorrelations) break
            val tokenRid = (method.token and 0x00ff_ffffL).toInt()
            val tokenTable = ((method.token ushr 24) and 0xff).toInt()
            if (tokenTable == 0x06 && tokenRid > 0 && matchingModules.size == 1) {
                val (library, analysis, module) = matchingModules.single()
                val slotIndex = tokenRid - 1
                if (slotIndex < module.methodPointerCount) {
                    val slot = module.sampledMethodPointers.singleOrNull { it.slotIndex == slotIndex }
                    if (slot != null) {
                        val fn = analysis.functions.firstOrNull { it.rva == slot.functionRva }
                        out += Il2CppMethodNativeCorrelation(
                            metadataEntry = metadataEntry, methodIndex = method.index, declaringType = method.declaringType,
                            methodName = method.name, token = method.token, libraryEntry = library, functionRva = slot.functionRva,
                            functionName = fn?.name ?: "sub_%x".format(slot.functionRva),
                            evidence = "CODEGEN_MODULE_METHOD_TOKEN_SLOT", confidence = module.confidence,
                        )
                        continue
                    }
                }
            }
            val tokenHex = method.token.takeIf { it > 0 }?.toString(16)?.lowercase()
            val simpleType = method.declaringType.substringAfterLast('.').substringAfterLast('/').substringAfterLast('+')
            val methodName = method.name
            val tokenMatch = if (tokenHex != null) uniqueFunction { candidate ->
                val identity = candidate.lowerIdentity
                identity.contains("0x$tokenHex") || identity.contains("token_$tokenHex") || identity.contains("token$tokenHex")
            } else null

            val chosen: IndexedFunction
            val evidence: String
            val confidence: String
            if (tokenMatch != null) {
                chosen = tokenMatch
                evidence = "UNIQUE_METADATA_TOKEN_LITERAL"
                confidence = "HIGH"
            } else {
                if (!isSpecificName(simpleType) || !isSpecificName(methodName)) continue
                val typeKey = normalizeIdentifier(simpleType)
                val methodKey = normalizeIdentifier(methodName)
                val identityMatch = uniqueFunction { candidate ->
                    candidate.normalizedIdentity.contains(typeKey) && candidate.normalizedIdentity.contains(methodKey)
                } ?: continue
                chosen = identityMatch
                evidence = "UNIQUE_TYPE_METHOD_IDENTITY"
                confidence = "MEDIUM"
            }
            val library = chosen.library
            val fn = chosen.function
            out += Il2CppMethodNativeCorrelation(
                metadataEntry = metadataEntry,
                methodIndex = method.index,
                declaringType = method.declaringType,
                methodName = method.name,
                token = method.token,
                libraryEntry = library,
                functionRva = fn.rva,
                functionName = fn.name,
                evidence = evidence,
                confidence = confidence,
            )
        }
        return out.distinctBy { it.methodIndex to it.libraryEntry }
            .sortedWith(compareBy({ it.methodIndex }, { it.libraryEntry }, { it.functionRva }))
    }

    private fun normalizeClass(value: String): String = value.trim()
        .removePrefix("L").removeSuffix(";").replace('.', '/').lowercase()

    private fun normalizeSymbol(value: String): String = value.trim().removePrefix("_").lowercase()

    private fun sameLibrary(a: String, b: String): Boolean = a == b || a.substringAfterLast('/') == b.substringAfterLast('/')

    private fun normalizeIdentifier(value: String): String = value.lowercase().filter { it.isLetterOrDigit() }

    private fun normalizeAssemblyName(value: String): String = value.substringAfterLast('/').substringAfterLast('\\')
        .removeSuffix(".dll").removeSuffix(".exe").lowercase().filter { it.isLetterOrDigit() }

    private fun isSpecificName(value: String): Boolean {
        val normalized = normalizeIdentifier(value)
        return normalized.length >= 4 && normalized !in setOf("ctor", "cctor", "get", "set", "main", "invoke")
    }

    private fun minConfidence(a: String, ceiling: String): String {
        val rank = mapOf("LOW" to 0, "MEDIUM" to 1, "HIGH" to 2)
        val value = minOf(rank[a] ?: 0, rank[ceiling] ?: 0)
        return when (value) { 2 -> "HIGH"; 1 -> "MEDIUM"; else -> "LOW" }
    }
}
