package org.unirevlab.security.analysis

import kotlin.math.roundToInt
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Static, non-destructive deobfuscation assistance built on the DEX index already collected by the
 * analyzer. It never executes target code and never rewrites the APK. Instead it estimates
 * obfuscation intensity and produces semantic aliases backed by xrefs, API calls and strings.
 */
object DeobfuscationEngine {
    enum class AliasConfidence { HIGH, MEDIUM, LOW }

    data class AliasSuggestion(
        val kind: String,
        val original: String,
        val suggestedAlias: String,
        val confidence: AliasConfidence,
        val reasons: List<String>,
    )

    data class MappingClass(
        val originalName: String,
        val obfuscatedName: String,
    )

    data class MappingMember(
        val ownerOriginalName: String,
        val originalName: String,
        val obfuscatedName: String,
        val signature: String,
        val kind: String,
    )

    data class MappingSummary(
        val classes: List<MappingClass>,
        val members: List<MappingMember>,
        val parseErrors: Int,
        val truncated: Boolean,
    )

    data class Summary(
        val score: Int,
        val likelyObfuscated: Boolean,
        val classesAnalyzed: Int,
        val obfuscatedClasses: Int,
        val methodsAnalyzed: Int,
        val obfuscatedMethods: Int,
        val opaqueStringIndicators: Int,
        val aliases: List<AliasSuggestion>,
        val coverageComplete: Boolean,
    )

    fun analyze(report: StaticAnalysisReport, maxAliases: Int = 250): Summary {
        val dex = report.dex ?: return Summary(
            score = 0,
            likelyObfuscated = false,
            classesAnalyzed = 0,
            obfuscatedClasses = 0,
            methodsAnalyzed = 0,
            obfuscatedMethods = 0,
            opaqueStringIndicators = 0,
            aliases = emptyList(),
            coverageComplete = false,
        )

        val candidateClasses = dex.classes
            .filterNot { isFrameworkDescriptor(it.descriptor) }
            .filterNot { isGeneratedDescriptor(it.descriptor) }
        val candidateClassDescriptors = candidateClasses.mapTo(HashSet()) { it.descriptor }
        val candidateMethods = dex.methods
            .filter { it.declaringClass in candidateClassDescriptors }
            .filterNot { it.name == "<init>" || it.name == "<clinit>" }

        val obfuscatedClassDescriptors = candidateClasses.asSequence()
            .filter { looksObfuscatedClass(it.descriptor) }
            .mapTo(HashSet()) { it.descriptor }
        val obfuscatedMethods = candidateMethods.filter(::looksObfuscatedMethod)

        val opaqueStrings = dex.stringXrefs.asSequence()
            .map { it.value }
            .distinct()
            .count(::looksOpaqueString)

        val classRatio = ratio(obfuscatedClassDescriptors.size, candidateClasses.size)
        val methodRatio = ratio(obfuscatedMethods.size, candidateMethods.size)
        val opaqueRatio = ratio(opaqueStrings.coerceAtMost(200), dex.stringXrefs.map { it.value }.distinct().size.coerceAtMost(200))
        val score = (classRatio * 48.0 + methodRatio * 47.0 + opaqueRatio * 5.0)
            .roundToInt()
            .coerceIn(0, 100)
        val likelyObfuscated = score >= 35 && (obfuscatedClassDescriptors.size >= 3 || obfuscatedMethods.size >= 10)

        val stringsByCaller = dex.stringXrefs.groupBy { MethodKey(it.dexEntry, it.callerMethodIndex) }
        val callsByCaller = dex.callXrefs.groupBy { MethodKey(it.dexEntry, it.callerMethodIndex) }
        val incomingCount = dex.callXrefs.groupingBy { MethodKey(it.dexEntry, it.calleeMethodIndex) }.eachCount()
        val componentKinds = componentKinds(report)

        val methodAliases = obfuscatedMethods.asSequence().mapNotNull { method ->
            inferMethodAlias(
                method = method,
                strings = stringsByCaller[MethodKey(method.dexEntry, method.methodIndex)].orEmpty().map { it.value },
                calls = callsByCaller[MethodKey(method.dexEntry, method.methodIndex)].orEmpty().map {
                    "${it.calleeClass}->${it.calleeName}${it.calleePrototype}"
                },
                incoming = incomingCount[MethodKey(method.dexEntry, method.methodIndex)] ?: 0,
            )
        }.toList()

        val roleByClass = methodAliases.groupBy { alias -> alias.original.substringBefore("->") }
        val classAliases = candidateClasses.asSequence()
            .filter { it.descriptor in obfuscatedClassDescriptors }
            .mapNotNull { cls ->
                inferClassAlias(
                    descriptor = cls.descriptor,
                    classIndex = cls.classIndex,
                    componentKind = componentKinds[cls.descriptor],
                    methodRoles = roleByClass[cls.descriptor].orEmpty(),
                )
            }
            .toList()

        val aliases = (classAliases + methodAliases)
            .sortedWith(
                compareBy<AliasSuggestion> { confidenceOrder(it.confidence) }
                    .thenBy { it.kind }
                    .thenBy { it.original },
            )
            .take(maxAliases.coerceAtLeast(0))

        return Summary(
            score = score,
            likelyObfuscated = likelyObfuscated,
            classesAnalyzed = candidateClasses.size,
            obfuscatedClasses = obfuscatedClassDescriptors.size,
            methodsAnalyzed = candidateMethods.size,
            obfuscatedMethods = obfuscatedMethods.size,
            opaqueStringIndicators = opaqueStrings,
            aliases = aliases,
            coverageComplete = !dex.truncated && dex.parseErrors == 0,
        )
    }

    /** Parse the class/member names from a standard ProGuard/R8 mapping.txt file. */
    fun parseMapping(text: String, maxChars: Int = 4_000_000, maxMembers: Int = 50_000): MappingSummary {
        val bounded = if (text.length > maxChars) text.take(maxChars) else text
        val classes = mutableListOf<MappingClass>()
        val members = mutableListOf<MappingMember>()
        var parseErrors = 0
        var currentOwner: String? = null
        var truncated = text.length > maxChars

        bounded.lineSequence().forEach { raw ->
            val line = raw.trimEnd()
            if (line.isBlank() || line.trimStart().startsWith("#")) return@forEach

            if (!line.first().isWhitespace()) {
                val match = CLASS_MAPPING.matchEntire(line.trim())
                if (match == null) {
                    parseErrors++
                    currentOwner = null
                } else {
                    currentOwner = match.groupValues[1]
                    classes += MappingClass(
                        originalName = match.groupValues[1],
                        obfuscatedName = match.groupValues[2],
                    )
                }
                return@forEach
            }

            val owner = currentOwner ?: return@forEach
            if (members.size >= maxMembers) {
                truncated = true
                return@forEach
            }
            val trimmed = line.trim()
            val arrow = trimmed.lastIndexOf(" -> ")
            if (arrow <= 0) {
                parseErrors++
                return@forEach
            }
            val leftRaw = trimmed.substring(0, arrow)
            val obfuscatedName = trimmed.substring(arrow + 4).trim()
            val left = leftRaw
                .replace(LEADING_LINE_RANGE, "")
                .replace(TRAILING_LINE_RANGE, "")
                .trim()
            if (left.isBlank() || obfuscatedName.isBlank()) {
                parseErrors++
                return@forEach
            }

            val isMethod = '(' in left
            val originalName = if (isMethod) {
                left.substringBefore('(').substringAfterLast(' ').trim()
            } else {
                left.substringAfterLast(' ').trim()
            }
            if (originalName.isBlank()) {
                parseErrors++
                return@forEach
            }
            members += MappingMember(
                ownerOriginalName = owner,
                originalName = originalName,
                obfuscatedName = obfuscatedName,
                signature = left,
                kind = if (isMethod) "METHOD" else "FIELD",
            )
        }

        return MappingSummary(
            classes = classes.distinct(),
            members = members.distinct(),
            parseErrors = parseErrors,
            truncated = truncated,
        )
    }

    private fun inferMethodAlias(
        method: DexMethodReference,
        strings: List<String>,
        calls: List<String>,
        incoming: Int,
    ): AliasSuggestion? {
        val callText = calls.joinToString("\n").lowercase()
        val stringText = strings.take(40).joinToString("\n").lowercase()
        val matched = ROLE_RULES.firstOrNull { rule ->
            rule.callMarkers.any(callText::contains) || rule.stringMarkers.any(stringText::contains)
        } ?: return null

        val reasons = buildList {
            calls.firstOrNull { call -> matched.callMarkers.any(call.lowercase()::contains) }
                ?.let { add("API/xref: ${it.take(180)}") }
            strings.firstOrNull { value -> matched.stringMarkers.any(value.lowercase()::contains) }
                ?.let { add("String: ${it.take(160)}") }
            if (incoming > 0) add("Callers in indexed graph: $incoming")
        }.ifEmpty { listOf("Semantic role inferred from indexed references") }

        return AliasSuggestion(
            kind = "METHOD",
            original = "${method.declaringClass}->${method.name}${method.prototype}",
            suggestedAlias = "${matched.aliasBase}_m${method.methodIndex}",
            confidence = matched.confidence,
            reasons = reasons,
        )
    }

    private fun inferClassAlias(
        descriptor: String,
        classIndex: Int,
        componentKind: String?,
        methodRoles: List<AliasSuggestion>,
    ): AliasSuggestion? {
        if (componentKind != null) {
            val base = when (componentKind.lowercase()) {
                "activity" -> "Activity"
                "service" -> "Service"
                "receiver" -> "Receiver"
                "provider" -> "Provider"
                else -> "Component"
            }
            return AliasSuggestion(
                kind = "CLASS",
                original = descriptor,
                suggestedAlias = "${base}_c$classIndex",
                confidence = AliasConfidence.HIGH,
                reasons = listOf("Declared Android component: $componentKind"),
            )
        }

        val bestRole = methodRoles.minByOrNull { confidenceOrder(it.confidence) } ?: return null
        val base = bestRole.suggestedAlias.substringBefore("_m")
            .replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        return AliasSuggestion(
            kind = "CLASS",
            original = descriptor,
            suggestedAlias = "${base}Class_c$classIndex",
            confidence = if (bestRole.confidence == AliasConfidence.HIGH) AliasConfidence.MEDIUM else AliasConfidence.LOW,
            reasons = listOf("Contains semantic method role: ${bestRole.suggestedAlias}") + bestRole.reasons.take(1),
        )
    }

    private fun componentKinds(report: StaticAnalysisReport): Map<String, String> {
        val manifest = report.manifest ?: return emptyMap()
        return buildMap {
            manifest.components.forEach { component ->
                val descriptor = componentDescriptor(manifest.packageName, component.name) ?: return@forEach
                put(descriptor, component.kind)
            }
        }
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

    private fun looksObfuscatedClass(descriptor: String): Boolean {
        val simple = descriptor.removePrefix("L").removeSuffix(";")
            .substringAfterLast('/')
            .substringBefore('$')
        if (simple in NON_OBFUSCATED_SHORT_CLASS_NAMES) return false
        if (simple.length <= 2 && simple.all { it.isLetterOrDigit() || it == '_' }) return true
        return OBFUSCATED_CLASS_NAME.matches(simple)
    }

    private fun looksObfuscatedMethod(method: DexMethodReference): Boolean {
        val name = method.name
        if (name in COMMON_SHORT_METHOD_NAMES) return false
        if (name.length <= 2 && name.all { it.isLetterOrDigit() || it == '_' }) return true
        return OBFUSCATED_METHOD_NAME.matches(name)
    }

    private fun isFrameworkDescriptor(descriptor: String): Boolean = FRAMEWORK_PREFIXES.any(descriptor::startsWith)

    private fun isGeneratedDescriptor(descriptor: String): Boolean {
        val simple = descriptor.removeSuffix(";").substringAfterLast('/')
        return simple == "R" || simple.startsWith("R$") || simple == "BuildConfig"
    }

    private fun looksOpaqueString(value: String): Boolean {
        val s = value.trim()
        if (s.length < 24 || s.length > 4096) return false
        val compact = s.replace("\n", "").replace("\r", "")
        val hex = compact.length >= 32 && compact.length % 2 == 0 && compact.all { it in "0123456789abcdefABCDEF" }
        val base64ish = compact.length >= 32 && compact.length % 4 == 0 && compact.all {
            it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' || it == '-' || it == '_'
        }
        return hex || base64ish
    }

    private fun ratio(part: Int, total: Int): Double = if (total <= 0) 0.0 else part.toDouble() / total.toDouble()

    private fun confidenceOrder(confidence: AliasConfidence): Int = when (confidence) {
        AliasConfidence.HIGH -> 0
        AliasConfidence.MEDIUM -> 1
        AliasConfidence.LOW -> 2
    }

    private data class MethodKey(val dexEntry: String, val methodIndex: Int)

    private data class RoleRule(
        val aliasBase: String,
        val confidence: AliasConfidence,
        val callMarkers: List<String>,
        val stringMarkers: List<String> = emptyList(),
    )

    private val ROLE_RULES = listOf(
        RoleRule(
            "deserializeObject", AliasConfidence.HIGH,
            listOf("objectinputstream->readobject", "objectinputstream;->readobject", "xmldecoder->readobject"),
        ),
        RoleRule(
            "parseJson", AliasConfidence.HIGH,
            listOf("gson;->fromjson", "objectmapper;->readvalue", "kotlinx/serialization", "json;->decodefromstring"),
        ),
        RoleRule(
            "parseProto", AliasConfidence.HIGH,
            listOf("protobuf", "->parsefrom", "->parsedelimitedfrom"),
        ),
        RoleRule(
            "signatureCheck", AliasConfidence.HIGH,
            listOf("getapkcontentssigners", "getsigningcertificatehistory", "checksignature", "checksignatures", "signinginfo"),
        ),
        RoleRule(
            "integrityCheck", AliasConfidence.HIGH,
            listOf("integritymanager", "requestintegritytoken", "messagedigest;->digest", "crc32"),
            listOf("tampered", "integrity", "checksum"),
        ),
        RoleRule(
            "rootCheck", AliasConfidence.HIGH,
            listOf("runtime;->exec", "processbuilder"),
            listOf("/system/xbin/su", "/system/bin/su", "magisk", "zygisk", "test-keys"),
        ),
        RoleRule(
            "debugCheck", AliasConfidence.HIGH,
            listOf("debug;->isdebuggerconnected", "debug;->waitingfordebugger", "ptrace"),
            listOf("tracerpid", "debugger"),
        ),
        RoleRule(
            "entitlementCheck", AliasConfidence.MEDIUM,
            listOf("billingclient", "querypurchases", "licensechecker", "checkaccess"),
            listOf("premium", "entitlement", "subscription", "license"),
        ),
        RoleRule(
            "webViewHandler", AliasConfidence.MEDIUM,
            listOf("webview;->", "websettings;->", "addjavascriptinterface"),
        ),
        RoleRule(
            "cryptoOperation", AliasConfidence.MEDIUM,
            listOf("javax/crypto/cipher", "javax/crypto/mac", "messagedigest", "secretkeyspec"),
        ),
        RoleRule(
            "networkRequest", AliasConfidence.MEDIUM,
            listOf("okhttp", "httpurlconnection", "retrofit", "urlconnection", "websocket"),
            listOf("https://", "http://"),
        ),
        RoleRule(
            "preferencesAccess", AliasConfidence.MEDIUM,
            listOf("sharedpreferences", "getsharedpreferences"),
        ),
        RoleRule(
            "databaseAccess", AliasConfidence.MEDIUM,
            listOf("sqlite", "roomdatabase", "supportsqlite"),
        ),
        RoleRule(
            "ipcHandler", AliasConfidence.MEDIUM,
            listOf("android/content/intent", "android/os/bundle", "android/os/parcel"),
        ),
        RoleRule(
            "fileOperation", AliasConfidence.LOW,
            listOf("java/io/file", "fileinputstream", "fileoutputstream", "files;->"),
        ),
    )

    private val FRAMEWORK_PREFIXES = listOf(
        "Ljava/", "Ljavax/", "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/coroutines/",
        "Ldalvik/", "Lsun/", "Lorg/jetbrains/", "Lcom/google/android/", "Lcom/google/firebase/",
    )
    private val NON_OBFUSCATED_SHORT_CLASS_NAMES = setOf("R", "BR", "DB", "UI", "VM")
    private val COMMON_SHORT_METHOD_NAMES = setOf("get", "set", "run", "map", "add", "put", "pop")
    private val OBFUSCATED_CLASS_NAME = Regex("[a-z]{1,3}[0-9]?")
    private val OBFUSCATED_METHOD_NAME = Regex("[a-z]{1,2}[0-9]?")
    private val CLASS_MAPPING = Regex("^(.+?)\\s+->\\s+([^:]+):$")
    private val LEADING_LINE_RANGE = Regex("^\\d+:\\d+:")
    private val TRAILING_LINE_RANGE = Regex(":\\d+:\\d+$")
}
