package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/** Resolves exact names from a developer-supplied ProGuard/R8 mapping.txt against indexed DEX data. */
object MappingDeobfuscator {
    data class ResolvedAlias(
        val kind: String,
        val obfuscatedSymbol: String,
        val originalSymbol: String,
        val evidence: String,
    )

    fun resolve(
        report: StaticAnalysisReport,
        mapping: DeobfuscationEngine.MappingSummary,
        limit: Int = 500,
    ): List<ResolvedAlias> {
        val dex = report.dex ?: return emptyList()
        if (limit <= 0) return emptyList()

        val classDescriptors = dex.classes.mapTo(HashSet()) { it.descriptor }
        val obfuscatedClassByOriginal = mapping.classes.associate { it.originalName to it.obfuscatedName }
        val out = LinkedHashMap<String, ResolvedAlias>()

        fun add(alias: ResolvedAlias) {
            if (out.size >= limit) return
            out.putIfAbsent("${alias.kind}|${alias.obfuscatedSymbol}|${alias.originalSymbol}", alias)
        }

        mapping.classes.forEach { cls ->
            val descriptor = descriptorOf(cls.obfuscatedName)
            if (descriptor in classDescriptors) {
                add(
                    ResolvedAlias(
                        kind = "CLASS",
                        obfuscatedSymbol = descriptor,
                        originalSymbol = cls.originalName,
                        evidence = "Exact class entry from mapping.txt",
                    ),
                )
            }
        }

        mapping.members.forEach { member ->
            if (out.size >= limit) return@forEach
            val ownerObfuscated = obfuscatedClassByOriginal[member.ownerOriginalName] ?: return@forEach
            val ownerDescriptor = descriptorOf(ownerObfuscated)
            when (member.kind) {
                "METHOD" -> dex.methods.asSequence()
                    .filter { it.declaringClass == ownerDescriptor && it.name == member.obfuscatedName }
                    .forEach { method ->
                        add(
                            ResolvedAlias(
                                kind = "METHOD",
                                obfuscatedSymbol = "${method.declaringClass}->${method.name}${method.prototype}",
                                originalSymbol = "${member.ownerOriginalName}.${member.originalName}${method.prototype}",
                                evidence = "Exact member name from mapping.txt; DEX prototype retained for overload disambiguation",
                            ),
                        )
                    }
                "FIELD" -> dex.fieldXrefs.asSequence()
                    .filter { it.declaringClass == ownerDescriptor && it.fieldName == member.obfuscatedName }
                    .distinctBy { it.fieldType }
                    .forEach { field ->
                        add(
                            ResolvedAlias(
                                kind = "FIELD",
                                obfuscatedSymbol = "${field.declaringClass}->${field.fieldName}:${field.fieldType}",
                                originalSymbol = "${member.ownerOriginalName}.${member.originalName}:${field.fieldType}",
                                evidence = "Exact field name from mapping.txt; field type confirmed by DEX xref",
                            ),
                        )
                    }
            }
        }

        return out.values.toList()
    }

    private fun descriptorOf(dotName: String): String = "L${dotName.trim().replace('.', '/')};"
}
