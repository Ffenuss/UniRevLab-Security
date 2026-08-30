package org.unirevlab.security.analysis

import org.unirevlab.security.model.DependencyComponentSummary
import org.unirevlab.security.model.StaticAnalysisReport
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

/** Deterministic SBOM serializers generated solely from evidence already present in a report. */
object SbomExporter {
    fun exportCycloneDx16(report: StaticAnalysisReport): String {
        val components = report.supplyChain?.components.orEmpty().sortedBy { it.id }
        val vulnerabilities = report.supplyChain?.vulnerabilities.orEmpty().sortedWith(compareBy({ it.componentId }, { it.advisoryId }))
        val serial = deterministicUuid(report.artifact.sha256)
        val timestamp = Instant.ofEpochMilli(report.assessment.createdAtEpochMs).toString()
        return buildString {
            append("{\n")
            field("bomFormat", "CycloneDX", 1, true)
            field("specVersion", "1.6", 1, true)
            number("version", 1, 1, true)
            field("serialNumber", "urn:uuid:$serial", 1, true)
            append(i(1)).append("\"metadata\": {\n")
            field("timestamp", timestamp, 2, true)
            append(i(2)).append("\"component\": {\n")
            field("type", "application", 3, true)
            field("bom-ref", "urn:unirevlab:artifact:${report.artifact.sha256}", 3, true)
            field("name", report.artifact.displayName, 3, true)
            append(i(3)).append("\"hashes\": [{\"alg\": \"SHA-256\", \"content\": \"").append(j(report.artifact.sha256)).append("\"}]\n")
            append(i(2)).append("}\n")
            append(i(1)).append("},\n")
            append(i(1)).append("\"components\": [")
            if (components.isNotEmpty()) append('\n')
            components.forEachIndexed { index, component ->
                appendCycloneComponent(component, 2)
                if (index != components.lastIndex) append(',')
                append('\n')
            }
            if (components.isNotEmpty()) append(i(1))
            append(']')
            if (vulnerabilities.isNotEmpty()) {
                append(",\n")
                append(i(1)).append("\"vulnerabilities\": [\n")
                vulnerabilities.forEachIndexed { index, vulnerability ->
                    append(i(2)).append("{\n")
                    field("bom-ref", "urn:unirevlab:advisory:${stableId(vulnerability.advisoryId + ":" + vulnerability.componentId + ":" + vulnerability.componentVersion)}", 3, true)
                    field("id", vulnerability.advisoryId, 3, true)
                    append(i(3)).append("\"source\": {\n")
                    field("name", vulnerability.source, 4, false)
                    append(i(3)).append("},\n")
                    append(i(3)).append("\"ratings\": [{\"severity\": \"${j(vulnerability.severity.lowercase())}\"}],\n")
                    field("description", vulnerability.summary, 3, true)
                    append(i(3)).append("\"affects\": [{\"ref\": \"urn:unirevlab:component:${stableId(vulnerability.componentId)}\"}]\n")
                    append(i(2)).append('}')
                    if (index != vulnerabilities.lastIndex) append(',')
                    append('\n')
                }
                append(i(1)).append(']')
            }
            append("\n}")
        }
    }

    fun exportSpdx301JsonLd(report: StaticAnalysisReport): String {
        val components = report.supplyChain?.components.orEmpty().sortedBy { it.id }
        val namespace = "https://unirevlab.org/spdx/${report.artifact.sha256}"
        val creation = "_:creationinfo"
        val toolId = "$namespace/Agent/UniRevLab"
        val documentId = "$namespace/Document"
        val sbomId = "$namespace/SBOM"
        val rootId = "$namespace/Package/root"
        val dependencyIds = components.associateWith { "$namespace/Package/${stableId(it.id)}" }
        val relationshipIds = components.mapIndexed { index, _ -> "$namespace/Relationship/${index + 1}" }
        val created = Instant.ofEpochMilli(report.assessment.createdAtEpochMs).toString()
        val elements = buildList {
            add(sbomId); add(toolId); add(rootId); addAll(dependencyIds.values); addAll(relationshipIds)
        }
        return buildString {
            append("{\n")
            field("@context", "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", 1, true)
            append(i(1)).append("\"@graph\": [\n")
            append(i(2)).append("{\n")
            field("type", "CreationInfo", 3, true)
            field("@id", creation, 3, true)
            array("createdBy", listOf(toolId), 3, true)
            field("specVersion", "3.0.1", 3, true)
            field("created", created, 3, false)
            append(i(2)).append("},\n")
            append(i(2)).append("{\n")
            field("type", "Tool", 3, true)
            field("spdxId", toolId, 3, true)
            field("name", "UniRevLab Security", 3, true)
            field("creationInfo", creation, 3, false)
            append(i(2)).append("},\n")
            append(i(2)).append("{\n")
            field("type", "SpdxDocument", 3, true)
            field("spdxId", documentId, 3, true)
            field("creationInfo", creation, 3, true)
            array("rootElement", listOf(sbomId), 3, true)
            array("element", elements, 3, true)
            array("profileConformance", listOf("core", "software"), 3, false)
            append(i(2)).append("},\n")
            append(i(2)).append("{\n")
            field("type", "software_Sbom", 3, true)
            field("spdxId", sbomId, 3, true)
            field("creationInfo", creation, 3, true)
            array("rootElement", listOf(rootId), 3, true)
            array("element", listOf(rootId) + dependencyIds.values, 3, true)
            array("software_sbomType", listOf("build"), 3, false)
            append(i(2)).append("},\n")
            appendSpdxPackage(rootId, report.artifact.displayName, null, null, creation, 2)
            if (components.isNotEmpty()) append(',')
            append('\n')
            components.forEachIndexed { index, c ->
                appendSpdxPackage(dependencyIds.getValue(c), c.name, c.version, c.purl, creation, 2)
                append(",\n")
                append(i(2)).append("{\n")
                field("type", "Relationship", 3, true)
                field("spdxId", relationshipIds[index], 3, true)
                field("creationInfo", creation, 3, true)
                field("from", rootId, 3, true)
                field("relationshipType", "dependsOn", 3, true)
                array("to", listOf(dependencyIds.getValue(c)), 3, false)
                append(i(2)).append('}')
                if (index != components.lastIndex) append(',')
                append('\n')
            }
            append(i(1)).append("]\n}")
        }
    }

    private fun StringBuilder.appendCycloneComponent(c: DependencyComponentSummary, level: Int) {
        append(i(level)).append("{\n")
        field("type", if (c.ecosystem.contains("RUNTIME")) "framework" else "library", level + 1, true)
        field("bom-ref", "urn:unirevlab:component:${stableId(c.id)}", level + 1, true)
        field("name", c.name, level + 1, c.version != null || c.purl != null || c.evidence.isNotEmpty())
        if (c.version != null) field("version", c.version, level + 1, c.purl != null || c.evidence.isNotEmpty())
        if (c.purl != null) field("purl", c.purl, level + 1, c.evidence.isNotEmpty())
        if (c.evidence.isNotEmpty()) {
            append(i(level + 1)).append("\"properties\": [\n")
            val props = buildList {
                add("unirevlab:confidence" to c.confidence)
                c.versionEvidence?.let { add("unirevlab:version-evidence" to it) }
                c.evidence.take(8).forEach { add("unirevlab:evidence" to it) }
            }
            props.forEachIndexed { index, (name, value) ->
                append(i(level + 2)).append("{\"name\": \"").append(j(name)).append("\", \"value\": \"").append(j(value)).append("\"}")
                if (index != props.lastIndex) append(',')
                append('\n')
            }
            append(i(level + 1)).append("]\n")
        }
        append(i(level)).append('}')
    }

    private fun StringBuilder.appendSpdxPackage(id: String, name: String, version: String?, purl: String?, creation: String, level: Int) {
        append(i(level)).append("{\n")
        field("type", "software_Package", level + 1, true)
        field("spdxId", id, level + 1, true)
        field("creationInfo", creation, level + 1, true)
        field("name", name, level + 1, version != null || purl != null)
        if (version != null) field("software_packageVersion", version, level + 1, purl != null)
        if (purl != null) field("software_packageUrl", purl, level + 1, false)
        append(i(level)).append('}')
    }

    private fun deterministicUuid(hex: String): UUID {
        val input = runCatching { hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }.getOrElse { hex.toByteArray() }
        val digest = MessageDigest.getInstance("SHA-256").digest(input).copyOf(16)
        digest[6] = ((digest[6].toInt() and 0x0f) or 0x50).toByte()
        digest[8] = ((digest[8].toInt() and 0x3f) or 0x80).toByte()
        val bb = java.nio.ByteBuffer.wrap(digest)
        return UUID(bb.long, bb.long)
    }

    private fun stableId(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray()).take(12).joinToString("") { "%02x".format(it) }

    private fun StringBuilder.field(name: String, value: String, level: Int, comma: Boolean) {
        append(i(level)).append('"').append(j(name)).append("\": \"").append(j(value)).append('"')
        if (comma) append(',')
        append('\n')
    }
    private fun StringBuilder.number(name: String, value: Long, level: Int, comma: Boolean) {
        append(i(level)).append('"').append(j(name)).append("\": ").append(value)
        if (comma) append(',')
        append('\n')
    }
    private fun StringBuilder.array(name: String, values: List<String>, level: Int, comma: Boolean) {
        append(i(level)).append('"').append(j(name)).append("\": [")
        append(values.joinToString(", ") { "\"${j(it)}\"" }).append(']')
        if (comma) append(',')
        append('\n')
    }
    private fun i(level: Int) = "  ".repeat(level)
    private fun j(value: String): String = buildString {
        value.forEach { c ->
            when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (c.code < 0x20) append("\\u%04x".format(c.code)) else append(c)
            }
        }
    }
}
