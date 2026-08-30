package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.JniBridgeReference
import org.unirevlab.security.model.NativeSummary

/** Static correlation only. No library loading, symbol invocation, or process instrumentation occurs here. */
object JniBridgeCorrelator {
    fun correlate(dex: DexSummary?, native: NativeSummary, maxBridges: Int = 4_000): NativeSummary {
        if (dex == null || dex.nativeMethods.isEmpty()) return native
        val symbols = native.libraries.flatMap { lib -> lib.jniSymbols.map { lib.entryName to it } }
        val dynamicRegistrationLibraries = native.libraries.filter { it.hasJniOnLoad || it.registerNativesIndicator }

        val bridges = dex.nativeMethods.take(maxBridges).map { method ->
            val base = staticJniBase(method.declaringClass, method.name)
            val static = symbols.firstOrNull { (_, symbol) -> symbol == base || symbol.startsWith("${base}__") }
            when {
                static != null -> JniBridgeReference(
                    dexEntry = method.dexEntry,
                    declaringClass = method.declaringClass,
                    methodName = method.name,
                    prototype = method.prototype,
                    resolution = "STATIC_SYMBOL_MATCH",
                    libraryEntry = static.first,
                    nativeSymbol = static.second,
                )
                dynamicRegistrationLibraries.size == 1 -> JniBridgeReference(
                    dexEntry = method.dexEntry,
                    declaringClass = method.declaringClass,
                    methodName = method.name,
                    prototype = method.prototype,
                    resolution = "DYNAMIC_REGISTRATION_POSSIBLE",
                    libraryEntry = dynamicRegistrationLibraries.single().entryName,
                )
                else -> JniBridgeReference(
                    dexEntry = method.dexEntry,
                    declaringClass = method.declaringClass,
                    methodName = method.name,
                    prototype = method.prototype,
                    resolution = if (dynamicRegistrationLibraries.isNotEmpty()) "DYNAMIC_REGISTRATION_POSSIBLE" else "UNRESOLVED",
                )
            }
        }
        return native.copy(jniBridges = bridges)
    }

    internal fun staticJniBase(classDescriptor: String, methodName: String): String {
        val binaryClass = classDescriptor.removePrefix("L").removeSuffix(";")
        return "Java_${jniEncode(binaryClass)}_${jniEncode(methodName)}"
    }

    private fun jniEncode(value: String): String = buildString(value.length + 16) {
        value.forEach { ch ->
            when (ch) {
                '_' -> append("_1")
                '/' -> append('_')
                ';' -> append("_2")
                '[' -> append("_3")
                else -> if (ch.code in 0x20..0x7e) append(ch) else append("_0%04x".format(ch.code))
            }
        }
    }
}
