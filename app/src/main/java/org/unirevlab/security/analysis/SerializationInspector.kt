package org.unirevlab.security.analysis

import java.util.Locale
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Static-only serialization/deserialization surface inspector.
 *
 * It never instantiates target classes and never executes serialized payloads. The purpose is to
 * identify codecs, deserialization entry points, their callers, and whether those callers appear in
 * the manifest-reachable index.
 */
object SerializationInspector {
    enum class Direction { SERIALIZE, DESERIALIZE, BOTH }
    enum class Risk { HIGH, MEDIUM, LOW, INFORMATIONAL }

    data class Surface(
        val framework: String,
        val direction: Direction,
        val risk: Risk,
        val caller: String,
        val callee: String,
        val externallyReachable: Boolean,
        val reason: String,
    )

    data class Report(
        val surfaces: List<Surface>,
        val frameworks: List<String>,
        val deserializeCount: Int,
        val serializeCount: Int,
        val highRiskCount: Int,
        val externallyReachableCount: Int,
        val coverageComplete: Boolean,
    )

    private data class Rule(
        val framework: String,
        val direction: Direction,
        val risk: Risk,
        val classMarkers: List<String>,
        val methodMarkers: List<String>,
        val reason: String,
    )

    fun scan(report: StaticAnalysisReport): Report {
        val dex = report.dex
        val externalMethodIndexes = report.manifestDexReachability?.components.orEmpty()
            .asSequence()
            .filter { it.externallyAddressable }
            .flatMap { it.reachableMethodIndexes.asSequence() }
            .toSet()

        val surfaces = dex?.callXrefs.orEmpty().asSequence()
            .mapNotNull { xref -> match(xref, externalMethodIndexes) }
            .distinctBy { "${it.framework}|${it.direction}|${it.caller}|${it.callee}" }
            .sortedWith(
                compareBy<Surface> { riskOrder(it.risk) }
                    .thenByDescending { it.externallyReachable }
                    .thenBy { it.framework }
                    .thenBy { it.caller },
            )
            .take(MAX_SURFACES)
            .toList()

        return Report(
            surfaces = surfaces,
            frameworks = surfaces.map { it.framework }.distinct().sorted(),
            deserializeCount = surfaces.count { it.direction == Direction.DESERIALIZE || it.direction == Direction.BOTH },
            serializeCount = surfaces.count { it.direction == Direction.SERIALIZE || it.direction == Direction.BOTH },
            highRiskCount = surfaces.count { it.risk == Risk.HIGH },
            externallyReachableCount = surfaces.count { it.externallyReachable },
            coverageComplete = dex != null && !dex.truncated && dex.parseErrors == 0,
        )
    }

    private fun match(xref: DexMethodCallXref, externalMethodIndexes: Set<Int>): Surface? {
        val calleeClass = xref.calleeClass.lowercase(Locale.ROOT)
        val calleeMethod = xref.calleeName.lowercase(Locale.ROOT)
        val rule = RULES.firstOrNull { candidate ->
            candidate.classMarkers.any(calleeClass::contains) &&
                candidate.methodMarkers.any(calleeMethod::contains)
        } ?: return null

        return Surface(
            framework = rule.framework,
            direction = rule.direction,
            risk = rule.risk,
            caller = "${xref.callerClass}->${xref.callerName}",
            callee = "${xref.calleeClass}->${xref.calleeName}${xref.calleePrototype}",
            externallyReachable = xref.callerMethodIndex in externalMethodIndexes,
            reason = rule.reason,
        )
    }

    private fun riskOrder(risk: Risk): Int = when (risk) {
        Risk.HIGH -> 0
        Risk.MEDIUM -> 1
        Risk.LOW -> 2
        Risk.INFORMATIONAL -> 3
    }

    private val RULES = listOf(
        Rule(
            "Java Object Serialization", Direction.DESERIALIZE, Risk.HIGH,
            listOf("java/io/objectinputstream"), listOf("readobject", "readunshared", "readfields"),
            "Generic Java object deserialization can instantiate object graphs. Treat externally supplied streams as untrusted and constrain accepted types.",
        ),
        Rule(
            "Java Object Serialization", Direction.SERIALIZE, Risk.INFORMATIONAL,
            listOf("java/io/objectoutputstream"), listOf("writeobject", "writeunshared"),
            "Java object serialization output was observed.",
        ),
        Rule(
            "Android Serializable", Direction.DESERIALIZE, Risk.MEDIUM,
            listOf("android/content/intent", "android/os/bundle", "android/os/parcel"),
            listOf("getserializableextra", "getserializable", "readserializable"),
            "Serializable data is reconstructed from Android IPC/container APIs. Validate the producer, expected type and class loader assumptions.",
        ),
        Rule(
            "Android Parcelable", Direction.DESERIALIZE, Risk.LOW,
            listOf("android/content/intent", "android/os/bundle", "android/os/parcel"),
            listOf("getparcelableextra", "getparcelable", "readparcelable", "readtypedobject"),
            "Parcelable/typed-object input is reconstructed. Review externally reachable IPC paths and object validation.",
        ),
        Rule(
            "Gson", Direction.DESERIALIZE, Risk.MEDIUM,
            listOf("com/google/gson/gson"), listOf("fromjson"),
            "JSON deserialization through Gson was observed. Review polymorphic adapters, lenient parsing and trust-boundary validation.",
        ),
        Rule(
            "Gson", Direction.SERIALIZE, Risk.INFORMATIONAL,
            listOf("com/google/gson/gson"), listOf("tojson"),
            "JSON serialization through Gson was observed.",
        ),
        Rule(
            "Jackson", Direction.DESERIALIZE, Risk.MEDIUM,
            listOf("fasterxml/jackson/databind/objectmapper"), listOf("readvalue", "readtree", "convertvalue"),
            "Jackson deserialization was observed. Review polymorphic typing/default typing and accepted target classes.",
        ),
        Rule(
            "Jackson", Direction.SERIALIZE, Risk.INFORMATIONAL,
            listOf("fasterxml/jackson/databind/objectmapper"), listOf("writevalue", "writevalueasstring", "writevalueasbytes"),
            "Jackson serialization was observed.",
        ),
        Rule(
            "kotlinx.serialization", Direction.DESERIALIZE, Risk.LOW,
            listOf("kotlinx/serialization"), listOf("decodefromstring", "decodefrombytearray", "decodefromjsonelement"),
            "kotlinx.serialization decode entry point was observed. Validate schema assumptions and externally controlled fields.",
        ),
        Rule(
            "kotlinx.serialization", Direction.SERIALIZE, Risk.INFORMATIONAL,
            listOf("kotlinx/serialization"), listOf("encodetostring", "encodetobytearray", "encodetojsonelement"),
            "kotlinx.serialization encode entry point was observed.",
        ),
        Rule(
            "Protocol Buffers", Direction.DESERIALIZE, Risk.LOW,
            listOf("protobuf", "messagelite", "generatedmessage"), listOf("parsefrom", "parsedelimitedfrom", "mergefrom"),
            "Protocol Buffers parsing was observed. Review size limits, unknown-field handling and trust-boundary validation.",
        ),
        Rule(
            "Kryo", Direction.DESERIALIZE, Risk.HIGH,
            listOf("esotericsoftware/kryo/kryo"), listOf("readobject", "readclassandobject"),
            "Kryo object deserialization was observed. Registration and accepted classes should be tightly constrained for untrusted input.",
        ),
        Rule(
            "XStream", Direction.DESERIALIZE, Risk.HIGH,
            listOf("thoughtworks/xstream/xstream"), listOf("fromxml"),
            "XStream XML-to-object deserialization was observed. Review type permissions and input provenance.",
        ),
        Rule(
            "SnakeYAML", Direction.DESERIALIZE, Risk.HIGH,
            listOf("snakeyaml/yaml"), listOf("load", "loadas", "loadall"),
            "YAML object loading was observed. Use safe constructors/schema-restricted parsing for untrusted YAML.",
        ),
        Rule(
            "java.beans.XMLDecoder", Direction.DESERIALIZE, Risk.HIGH,
            listOf("java/beans/xmldecoder"), listOf("readobject"),
            "XMLDecoder reconstructs Java objects and must not consume untrusted XML.",
        ),
        Rule(
            "Hessian", Direction.DESERIALIZE, Risk.HIGH,
            listOf("hessian"), listOf("readobject"),
            "Hessian object deserialization was observed. Review accepted object types and untrusted input paths.",
        ),
    )

    private const val MAX_SURFACES = 400
}
