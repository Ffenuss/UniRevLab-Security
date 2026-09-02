package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Deterministic, address-free IL2CPP managed metadata dump for defensive review.
 *
 * It exports managed identities and metadata tokens recovered from global-metadata.dat plus native
 * correlation names where available. It intentionally does not emit patch offsets or mutation
 * instructions.
 */
object Il2CppManagedDumpExporter {
    fun export(report: StaticAnalysisReport, maxMethods: Int = 100_000): String {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            return buildString {
                appendLine("# UniRevLab IL2CPP managed dump")
                appendLine("# artifact_sha256=${report.artifact.sha256}")
                appendLine("# status=IL2CPP_METADATA_NOT_AVAILABLE")
            }
        }

        val correlations = report.correlations?.il2cppMethods.orEmpty().groupBy { it.methodIndex }
        val methodsByType = metadata.methodDefinitions.groupBy { it.declaringTypeIndex }
        val methodLimit = maxMethods.coerceAtLeast(0)
        var emittedMethods = 0

        return buildString {
            appendLine("# UniRevLab IL2CPP managed dump v1")
            appendLine("# artifact_sha256=${report.artifact.sha256}")
            appendLine("# metadata_entry=${metadata.entryName}")
            appendLine("# metadata_version=${metadata.metadataVersion ?: "unknown"}")
            appendLine("# layout_profile=${metadata.layoutProfile ?: "unknown"}")
            appendLine("# types=${metadata.typeDefinitions.size}")
            appendLine("# methods=${metadata.methodDefinitions.size}")
            appendLine("# coverage=${if (!metadata.truncated && !metadata.reconstructionTruncated && metadata.parseError == null) "COMPLETE" else "PARTIAL"}")
            appendLine("# NOTE: managed names are exact identities present in the supplied metadata; they may already have been obfuscated before IL2CPP conversion.")
            appendLine("# Native correlations list names only; no patch offsets are emitted.")
            appendLine()

            metadata.typeDefinitions.sortedBy { it.index }.forEach { type ->
                append("TYPE ")
                    .append(type.fullName)
                    .append(" token=0x")
                    .append(type.token.toString(16))
                    .append(" index=")
                    .append(type.index)
                    .appendLine()

                methodsByType[type.index].orEmpty().sortedBy { it.index }.forEach { method ->
                    if (emittedMethods >= methodLimit) return@forEach
                    append("  METHOD ")
                        .append(method.name)
                        .append(" params=")
                        .append(method.parameterCount)
                        .append(" token=0x")
                        .append(method.token.toString(16))
                        .append(" index=")
                        .append(method.index)
                    correlations[method.index].orEmpty().firstOrNull { it.functionName.isNotBlank() }?.let { correlation ->
                        append(" native=").append(sanitize(correlation.functionName))
                        append(" confidence=").append(sanitize(correlation.confidence))
                    }
                    appendLine()
                    emittedMethods++
                }
            }
            if (emittedMethods < metadata.methodDefinitions.size) {
                appendLine("# methods_truncated=true emitted=$emittedMethods")
            }
        }
    }

    private fun sanitize(value: String): String = value
        .replace('\n', ' ')
        .replace('\r', ' ')
        .replace('\t', ' ')
        .take(240)
}
