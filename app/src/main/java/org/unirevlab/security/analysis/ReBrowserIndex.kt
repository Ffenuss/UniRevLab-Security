package org.unirevlab.security.analysis

import org.unirevlab.security.model.*

object ReBrowserIndex {
    fun buildDex(dex: DexSummary, correlations: CrossRuntimeCorrelationSummary? = null): DexReIndex {
        val callsByCaller = dex.callXrefs.groupBy { it.dexEntry to it.callerMethodIndex }
        val callsByCallee = dex.callXrefs.groupBy { it.dexEntry to it.calleeMethodIndex }
        val stringsByMethod = dex.stringXrefs.groupBy { it.dexEntry to it.callerMethodIndex }
        val fieldsByMethod = dex.fieldXrefs.groupBy { it.dexEntry to it.callerMethodIndex }
        val typesByMethod = dex.typeXrefs.groupBy { it.dexEntry to it.callerMethodIndex }
        val blocksByMethod = dex.basicBlocks.groupBy { it.dexEntry to it.methodIndex }

        val nativeTargets = correlations?.jniNative.orEmpty().groupBy { it.dexEntry to it.dexMethodIndex }
        val methodsByClass = dex.methods.groupBy { it.dexEntry to it.declaringClass }
        val classes = dex.classes.map { cls ->
            val methods = methodsByClass[cls.dexEntry to cls.descriptor].orEmpty().map { method ->
                val key = method.dexEntry to method.methodIndex
                ReMethodNode(
                    dexEntry = method.dexEntry,
                    methodIndex = method.methodIndex,
                    classDescriptor = method.declaringClass,
                    name = method.name,
                    prototype = method.prototype,
                    callers = callsByCallee[key].orEmpty().map { "${it.callerClass}->${it.callerName}" }.distinct().sorted(),
                    callees = callsByCaller[key].orEmpty().map { "${it.calleeClass}->${it.calleeName}${it.calleePrototype}" }.distinct().sorted(),
                    strings = stringsByMethod[key].orEmpty().map { it.value }.distinct().sorted(),
                    fields = fieldsByMethod[key].orEmpty().map { "${it.declaringClass}->${it.fieldName}:${it.fieldType} [${it.kind}]" }.distinct().sorted(),
                    types = typesByMethod[key].orEmpty().map { "${it.descriptor} [${it.kind}]" }.distinct().sorted(),
                    basicBlockCount = blocksByMethod[key].orEmpty().size,
                    nativeTargets = nativeTargets[key].orEmpty().map { target ->
                        "${target.libraryEntry}@0x${target.functionRva.toString(16)} ${target.functionName ?: target.methodName} [${target.evidence}/${target.confidence}]"
                    }.sorted(),
                )
            }.sortedWith(compareBy({ it.name }, { it.prototype }))
            ReClassNode(cls.descriptor, cls.superDescriptor, methods)
        }.sortedBy { it.descriptor }

        val packages = classes.groupBy { packageName(it.descriptor) }.map { (pkg, grouped) ->
            RePackageNode(pkg, grouped.sortedBy { it.descriptor })
        }.sortedBy { it.name }

        return DexReIndex(packages, dex.methods.size, dex.callXrefs.size + dex.stringXrefs.size + dex.typeXrefs.size + dex.fieldXrefs.size)
    }

    fun buildNative(native: NativeSummary): NativeReIndex {
        val symbols = native.libraries.flatMap { lib ->
            buildList {
                lib.importedSymbols.forEach { add(NativeSymbolNode(lib.entryName, it.name, "IMPORT", it.defined, it.virtualAddress, it.sizeBytes)) }
                lib.exportedSymbols.forEach { add(NativeSymbolNode(lib.entryName, it.name, "EXPORT", it.defined, it.virtualAddress, it.sizeBytes)) }
                lib.jniSymbols.forEach { add(NativeSymbolNode(lib.entryName, it, "JNI", true, lib.exportedSymbols.firstOrNull { s -> s.name == it }?.virtualAddress, null)) }
            }
        }.distinctBy { listOf(it.library, it.name, it.kind) }.sortedWith(compareBy({ it.library }, { it.name }, { it.kind }))
        return NativeReIndex(native.libraries.map { it.entryName }.sorted(), symbols, native.jniBridges)
    }

    fun searchDex(index: DexReIndex, query: String, limit: Int = 100): List<String> {
        val q = query.trim().lowercase()
        if (q.length < 2 || limit <= 0) return emptyList()
        val results = LinkedHashSet<String>(minOf(limit * 2, 256))
        fun emit(value: String): Boolean {
            results += value
            return results.size >= limit
        }
        for (pkg in index.packages) {
            if (pkg.name.lowercase().contains(q) && emit("PACKAGE ${pkg.name}")) return results.toList()
            for (cls in pkg.classes) {
                if (cls.descriptor.lowercase().contains(q) && emit("CLASS ${cls.descriptor}")) return results.toList()
                for (m in cls.methods) {
                    val signature = "${m.classDescriptor}->${m.name}${m.prototype}"
                    if (signature.lowercase().contains(q) && emit("METHOD $signature")) return results.toList()
                    if ((m.callers.any { it.lowercase().contains(q) } || m.callees.any { it.lowercase().contains(q) }) && emit("XREF $signature")) {
                        return results.toList()
                    }
                }
            }
        }
        return results.toList()
    }


    fun buildGhidra(values: List<GhidraLibraryAnalysis>, correlations: CrossRuntimeCorrelationSummary? = null): GhidraReIndex {
        val jniLinks = correlations?.jniNative.orEmpty().groupBy { it.libraryEntry to it.functionRva }
        val il2cppMethodLinks = correlations?.il2cppMethods.orEmpty().groupBy { it.libraryEntry to it.functionRva }
        val functions = values.flatMap { analysis ->
            val cfgByFunction = analysis.cfg.associateBy { it.functionRva }
            val incoming = analysis.xrefs.groupingBy { it.toRva }.eachCount()
            val outgoing = analysis.xrefs.groupingBy { it.fromRva }.eachCount()
            val jni = analysis.jniRegistrations.groupBy { it.functionRva }
            val il2cpp = analysis.il2cppRegistrations.groupBy { it.rva }
            val pointerTablesByFunction = buildMap<Long, MutableList<GhidraIl2CppPointerTable>> {
                analysis.il2cppPointerTables.forEach { table ->
                    table.sampleFunctionRvas.forEach { rva -> getOrPut(rva) { mutableListOf() }.add(table) }
                }
            }
            val codegenSlotsByFunction = buildMap<Long, MutableList<Pair<GhidraIl2CppCodegenModule, GhidraIl2CppMethodPointerSlot>>> {
                analysis.il2cppCodegenModules.forEach { module ->
                    module.sampledMethodPointers.forEach { slot ->
                        getOrPut(slot.functionRva) { mutableListOf() }.add(module to slot)
                    }
                }
            }
            analysis.functions.map { fn ->
                GhidraFunctionNode(
                    libraryEntry = analysis.libraryEntry,
                    rva = fn.rva,
                    name = fn.name,
                    namespace = fn.namespace,
                    signature = fn.signature,
                    sizeBytes = fn.sizeBytes,
                    cfgBlockCount = cfgByFunction[fn.rva]?.blocks?.size ?: 0,
                    incomingXrefs = incoming[fn.rva] ?: 0,
                    outgoingXrefs = outgoing[fn.rva] ?: 0,
                    jniRegistrations = jni[fn.rva].orEmpty().map {
                        val evidence = it.classEvidence?.let { value -> "/$value" }.orEmpty()
                        "${it.className}->${it.methodName}${it.signature} [${it.confidence}$evidence]"
                    }.sorted(),
                    il2cppRegistrations = il2cpp[fn.rva].orEmpty().map {
                        "${it.kind}:${it.symbolName} [${it.evidence}/${it.confidence}]"
                    }.sorted(),
                    crossRuntimeLinks = buildList {
                        jniLinks[analysis.libraryEntry to fn.rva].orEmpty().forEach { link ->
                            add("DEX ${link.declaringClass}->${link.methodName}${link.prototype} [${link.confidence}]")
                        }
                        il2cppMethodLinks[analysis.libraryEntry to fn.rva].orEmpty().forEach { link ->
                            add("IL2CPP ${link.declaringType}->${link.methodName} token=0x${link.token.toString(16)} [${link.confidence}]")
                        }
                        pointerTablesByFunction[fn.rva].orEmpty().forEach { table ->
                            add("IL2CPP_PTR_TABLE owner=0x${table.ownerRva.toString(16)} table=0x${table.tableRva.toString(16)} entries=${table.entryCount} [${table.confidence}]")
                        }
                        codegenSlotsByFunction[fn.rva].orEmpty().forEach { (module, slot) ->
                            add("IL2CPP_MODULE ${module.moduleName} slot=${slot.slotIndex} table=0x${module.methodPointersRva.toString(16)} [${module.confidence}]")
                        }
                    }.sorted(),
                    decompilerPreview = fn.decompilerPreview,
                )
            }
        }.sortedWith(compareBy({ it.libraryEntry }, { it.rva }, { it.name }))

        return GhidraReIndex(
            libraries = values.map { it.libraryEntry }.distinct().sorted(),
            functions = functions,
            xrefCount = values.sumOf { it.xrefs.size },
            jniRegistrationCount = values.sumOf { it.jniRegistrations.size },
            il2cppRegistrationCount = values.sumOf { it.il2cppRegistrations.size },
            il2cppCodegenCallCount = values.sumOf { it.il2cppCodegenCalls.size },
            il2cppPointerTableCount = values.sumOf { it.il2cppPointerTables.size },
            il2cppCodegenModuleCount = values.sumOf { it.il2cppCodegenModules.size },
        )
    }

    fun searchGhidra(index: GhidraReIndex, query: String, limit: Int = 100): List<GhidraFunctionNode> {
        val q = query.trim().lowercase()
        if (q.length < 2) return emptyList()
        return index.functions.asSequence().filter { fn ->
            (
                fn.libraryEntry + " " + fn.name + " " + fn.namespace + " " + fn.signature + " " +
                    fn.jniRegistrations.joinToString(" ") + " " + fn.il2cppRegistrations.joinToString(" ") + " " + fn.crossRuntimeLinks.joinToString(" ")
                ).lowercase().contains(q)
        }.take(limit).toList()
    }

    private fun packageName(descriptor: String): String {
        val clean = descriptor.removePrefix("L").removeSuffix(";")
        val slash = clean.lastIndexOf('/')
        return if (slash <= 0) "<default>" else clean.substring(0, slash).replace('/', '.')
    }
}
