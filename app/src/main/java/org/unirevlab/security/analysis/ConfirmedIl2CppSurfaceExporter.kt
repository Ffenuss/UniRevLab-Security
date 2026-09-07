package org.unirevlab.security.analysis

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/** Extracts audit-relevant surfaces only from addresses present in a completed engine dump.cs. */
object ConfirmedIl2CppSurfaceExporter {
    data class Summary(
        val gameplayCount: Int,
        val applicationCount: Int,
        val methodCount: Int,
        val fieldCount: Int,
        val unresolvedRelevantMethodCount: Int,
        val relevantStringCount: Int,
        val outputJson: File,
        val outputCsv: File,
    )

    private data class DumpAddress(val rva: String, val fileOffset: String?, val virtualAddress: String?)
    private data class Member(val name: String, val declaredType: String?, val signature: String)

    private data class UnresolvedMethod(
        val domain: String,
        val category: String,
        val marker: String,
        val assembly: String,
        val namespace: String,
        val className: String,
        val memberName: String,
        val declaredType: String?,
        val managedSignature: String,
    )

    private data class StringSurface(
        val domain: String,
        val category: String,
        val marker: String,
        val address: String,
        val value: String,
        val symbolName: String?,
    )

    private data class Match(
        val domain: String,
        val category: String,
        val marker: String,
        val addressKind: String,
        val addressHex: String,
        val namespace: String,
        val className: String,
        val memberKind: String,
        val memberName: String,
        val declaredType: String?,
        val managedSignature: String,
        val managedIdentity: String,
        val methodRva: String? = null,
        val methodFileOffset: String? = null,
        val dumpVirtualAddress: String? = null,
        val fieldOffset: String? = null,
        val confidence: String,
    ) {
        val addressFormula: String = if (addressKind == "METHOD_RVA") {
            "moduleBase(lib/<abi>/libil2cpp.so) + $addressHex"
        } else {
            "objectAddress($namespace.$className) + $addressHex"
        }
        val runtimeAddressStatus: String = if (addressKind == "METHOD_RVA") {
            "REQUIRES_RUNTIME_MODULE_BASE"
        } else {
            "REQUIRES_LIVE_OBJECT_INSTANCE"
        }
    }

    fun export(dumpCs: File, outputDirectory: File): Summary {
        require(dumpCs.isFile && dumpCs.length() > 0L) { "Completed dump.cs is required" }
        val matches = mutableListOf<Match>()
        val unresolvedMethods = mutableListOf<UnresolvedMethod>()
        var currentNamespace = "<global>"
        var currentType = "<unknown-type>"
        var currentAssembly = "<unknown-assembly>"
        var pendingAddress: DumpAddress? = null
        var pendingUnresolvedMethod = false
        dumpCs.bufferedReader(Charsets.UTF_8, 128 * 1024).useLines { lines ->
            lines.forEach { raw ->
                val line = raw.trim()
                ASSEMBLY.find(line)?.groupValues?.getOrNull(1)?.let { currentAssembly = it.trim() }
                NAMESPACE.find(line)?.groupValues?.getOrNull(1)?.let {
                    currentNamespace = it.trim().ifBlank { "<global>" }
                }
                TYPE.find(line)?.groupValues?.getOrNull(1)?.let { currentType = it }
                if (UNRESOLVED_METHOD_ADDRESS.containsMatchIn(line)) {
                    pendingUnresolvedMethod = true
                    pendingAddress = null
                    return@forEach
                }
                METHOD_ADDRESS.find(line)?.let { match ->
                    pendingAddress = DumpAddress(
                        rva = hex(match.groupValues[1]),
                        fileOffset = match.groupValues.getOrNull(2)?.takeIf(String::isNotBlank)?.let(::hex),
                        virtualAddress = match.groupValues.getOrNull(3)?.takeIf(String::isNotBlank)?.let(::hex),
                    )
                    pendingUnresolvedMethod = false
                    return@forEach
                }
                val methodAddress = pendingAddress
                if (methodAddress != null && line.startsWith("|-") && !line.contains("RVA:")) {
                    parseGenericMethod(line)?.let { member ->
                        classify(currentNamespace, currentType, member, "METHOD_RVA", methodAddress.rva, methodAddress)?.let(matches::add)
                    }
                    pendingAddress = null
                    return@forEach
                }
                if (methodAddress != null && line.isNotBlank() && !line.startsWith("//") && !line.startsWith("[")) {
                    parseMethod(line)?.let { member ->
                        classify(currentNamespace, currentType, member, "METHOD_RVA", methodAddress.rva, methodAddress)?.let(matches::add)
                    }
                    pendingAddress = null
                }
                if (pendingUnresolvedMethod && line.isNotBlank() && !line.startsWith("//") && !line.startsWith("[")) {
                    parseMethod(line)?.let { member ->
                        classifyUnresolved(currentAssembly, currentNamespace, currentType, member)?.let(unresolvedMethods::add)
                    }
                    pendingUnresolvedMethod = false
                }
                parseField(line)?.let { (member, offset) ->
                    classify(currentNamespace, currentType, member, "FIELD_OFFSET", offset, null)?.let(matches::add)
                }
            }
        }
        val distinct = matches.distinctBy {
            listOf(it.domain, it.category, it.addressKind, it.addressHex, it.namespace, it.className, it.memberName, it.managedSignature)
        }.sortedWith(compareBy({ it.domain }, { it.category }, { it.namespace }, { it.className }, { it.memberName }, { it.addressHex }))
        val gameplay = distinct.filter { it.domain == "GAME" }
        val application = distinct.filter { it.domain != "GAME" }
        val unresolved = unresolvedMethods.distinctBy {
            listOf(it.assembly, it.namespace, it.className, it.memberName, it.managedSignature)
        }.sortedWith(compareBy({ it.domain }, { it.category }, { it.assembly }, { it.namespace }, { it.className }, { it.memberName }))
        val strings = parseRelevantStrings(File(dumpCs.parentFile, "script.json"))
        val jsonFile = File(outputDirectory, "security-surfaces.json")
        val csvFile = File(outputDirectory, "security-surfaces.csv")
        val json = JSONObject()
            .put("schemaVersion", "2.1")
            .put("source", "completed Rodroid dump.cs plus structured script.json string addresses")
            .put("semantics", "RVA is relative to the loaded module base; FIELD_OFFSET is relative to a live object instance. ASLR prevents a stable absolute runtime address from being stored in an offline report.")
            .put("counts", JSONObject()
                .put("resolvedMethods", distinct.count { it.memberKind == "METHOD" })
                .put("fields", distinct.count { it.memberKind == "FIELD" })
                .put("unresolvedRelevantMethods", unresolved.size)
                .put("relevantStringLiterals", strings.size))
            .put("gameplayOffsets", JSONArray(gameplay.map(::toJson)))
            .put("applicationAndMonetizationOffsets", JSONArray(application.map(::toJson)))
            .put("unresolvedRelevantMethods", JSONArray(unresolved.map(::unresolvedToJson)))
            .put("relevantStringLiterals", JSONArray(strings.map(::stringToJson)))
        jsonFile.writeText(json.toString(2), Charsets.UTF_8)
        csvFile.bufferedWriter(Charsets.UTF_8).use { output ->
            output.appendLine("domain,category,address_kind,address,namespace,class,member_kind,member_name,declared_type,managed_signature,address_formula,runtime_address_status,method_rva,method_file_offset,dump_virtual_address,field_offset,confidence,matched_marker")
            distinct.forEach { item ->
                output.appendLine(
                    listOf(
                        item.domain, item.category, item.addressKind, item.addressHex, item.namespace, item.className,
                        item.memberKind, item.memberName, item.declaredType.orEmpty(), item.managedSignature,
                        item.addressFormula, item.runtimeAddressStatus, item.methodRva.orEmpty(), item.methodFileOffset.orEmpty(),
                        item.dumpVirtualAddress.orEmpty(), item.fieldOffset.orEmpty(), item.confidence, item.marker,
                    ).joinToString(",") { csv(it) },
                )
            }
        }
        return Summary(
            gameplayCount = gameplay.size,
            applicationCount = application.size,
            methodCount = distinct.count { it.memberKind == "METHOD" },
            fieldCount = distinct.count { it.memberKind == "FIELD" },
            unresolvedRelevantMethodCount = unresolved.size,
            relevantStringCount = strings.size,
            outputJson = jsonFile,
            outputCsv = csvFile,
        )
    }

    private fun parseField(line: String): Pair<Member, String>? {
        val match = FIELD.matchEntire(line) ?: return null
        val declaration = match.groupValues[1].trim()
        val name = match.groupValues[2]
        val declaredType = stripModifiers(declaration).trim().ifBlank { null }
        return Member(name, declaredType, line.substringBefore("//").trim()) to hex(match.groupValues[3])
    }

    private fun parseMethod(line: String): Member? {
        if ('(' !in line) return null
        val signature = line.substringBefore('{').trim().removeSuffix(";").trim()
        val beforeParen = signature.substringBefore('(').trim()
        val name = METHOD_NAME.find(beforeParen)?.groupValues?.getOrNull(1) ?: return null
        val declaredType = stripModifiers(beforeParen.removeSuffix(name).trim()).trim().ifBlank { null }
        return Member(name, declaredType, signature)
    }

    private fun parseGenericMethod(line: String): Member? {
        val signature = line.removePrefix("|-").trim()
        if (signature.isBlank()) return null
        val methodName = signature.substringAfterLast('.').substringBefore('<').ifBlank { return null }
        return Member(methodName, null, signature)
    }

    private fun classifyUnresolved(assembly: String, namespace: String, className: String, member: Member): UnresolvedMethod? {
        val identity = "$namespace.$className.${member.signature}"
        val rule = matchingRule(identity) ?: return null
        return UnresolvedMethod(
            domain = rule.first.domain,
            category = rule.first.category,
            marker = rule.second,
            assembly = assembly,
            namespace = namespace,
            className = className,
            memberName = member.name,
            declaredType = member.declaredType,
            managedSignature = member.signature.take(2_000),
        )
    }

    private fun stripModifiers(value: String): String {
        var result = value
        while (true) {
            val next = MODIFIER.replaceFirst(result, "")
            if (next == result) return result
            result = next
        }
    }

    private fun classify(
        namespace: String,
        className: String,
        member: Member,
        addressKind: String,
        address: String,
        dumpAddress: DumpAddress?,
    ): Match? {
        val identity = "$namespace.$className.${member.signature}"
        val rule = matchingRule(identity) ?: return null
        return Match(
            domain = rule.first.domain,
            category = rule.first.category,
            marker = rule.second,
            addressKind = addressKind,
            addressHex = address,
            namespace = namespace,
            className = className,
            memberKind = if (addressKind == "METHOD_RVA") "METHOD" else "FIELD",
            memberName = member.name,
            declaredType = member.declaredType,
            managedSignature = member.signature.take(2_000),
            managedIdentity = identity.take(2_000),
            methodRva = dumpAddress?.rva,
            methodFileOffset = dumpAddress?.fileOffset,
            dumpVirtualAddress = dumpAddress?.virtualAddress,
            fieldOffset = address.takeIf { addressKind == "FIELD_OFFSET" },
            confidence = if (addressKind == "METHOD_RVA") "HIGH" else "MEDIUM",
        )
    }

    private fun matchingRule(value: String): Pair<Rule, String>? {
        val normalized = value.lowercase().filter(Char::isLetterOrDigit)
        return RULES.asSequence()
            .flatMap { candidate -> candidate.markers.asSequence().map { marker -> candidate to marker } }
            .filter { (_, marker) -> normalized.contains(marker) }
            .maxByOrNull { (_, marker) -> marker.length }
    }

    /** Streams only ScriptString from Rodroid's large script.json instead of loading it into RAM. */
    private fun parseRelevantStrings(scriptJson: File): List<StringSurface> {
        if (!scriptJson.isFile) return emptyList()
        val result = LinkedHashMap<Pair<String, String>, StringSurface>()
        var inStrings = false
        var address: Long? = null
        var value: String? = null
        var symbol: String? = null
        fun flush() {
            val currentAddress = address
            val currentValue = value
            if (currentAddress != null && currentValue != null) {
                matchingRule(currentValue)?.let { rule ->
                    val addressHex = "0x${currentAddress.toString(16).uppercase()}"
                    result.putIfAbsent(addressHex to currentValue, StringSurface(
                        domain = rule.first.domain,
                        category = rule.first.category,
                        marker = rule.second,
                        address = addressHex,
                        value = currentValue.take(2_000),
                        symbolName = symbol,
                    ))
                }
            }
            address = null
            value = null
            symbol = null
        }
        scriptJson.bufferedReader(Charsets.UTF_8, 128 * 1024).useLines { lines ->
            lines.forEach { raw ->
                val line = raw.trim()
                if (!inStrings) {
                    if (line.startsWith("\"ScriptString\"") && line.contains('[')) inStrings = true
                    return@forEach
                }
                if (line == "]," || line == "]") {
                    flush()
                    return@useLines
                }
                when {
                    line.startsWith("{") -> flush()
                    line.startsWith("\"Address\"") -> address = line.substringAfter(':').trim().removeSuffix(",").toLongOrNull()
                    line.startsWith("\"Value\"") -> value = decodeJsonString(line.substringAfter(':').trim().removeSuffix(","))
                    line.startsWith("\"Name\"") -> symbol = decodeJsonString(line.substringAfter(':').trim().removeSuffix(","))
                    line.startsWith("}") -> flush()
                }
            }
        }
        return result.values.take(MAX_RELEVANT_STRINGS)
    }

    private fun decodeJsonString(literal: String): String? = runCatching {
        JSONObject("{\"value\":$literal}").getString("value")
    }.getOrNull()

    private fun unresolvedToJson(item: UnresolvedMethod) = JSONObject()
        .put("domain", item.domain)
        .put("category", item.category)
        .put("assembly", item.assembly)
        .put("namespace", item.namespace)
        .put("className", item.className)
        .put("memberKind", "METHOD")
        .put("memberName", item.memberName)
        .apply { item.declaredType?.let { put("declaredType", it) } }
        .put("managedSignature", item.managedSignature)
        .put("resolutionStatus", "DECLARATION_RECOVERED_RVA_NOT_RESOLVED")
        .put("confidence", "MEDIUM")
        .put("matchedMarker", item.marker)

    private fun stringToJson(item: StringSurface) = JSONObject()
        .put("domain", item.domain)
        .put("category", item.category)
        .put("addressKind", "DUMP_STRING_ADDRESS")
        .put("address", item.address)
        .put("value", item.value)
        .apply { item.symbolName?.let { put("symbolName", it) } }
        .put("runtimeAddressStatus", "REQUIRES_RUNTIME_MODULE_BASE")
        .put("confidence", "HIGH")
        .put("matchedMarker", item.marker)

    private fun toJson(item: Match) = JSONObject().apply {
        put("domain", item.domain)
        put("category", item.category)
        put("memberKind", item.memberKind)
        put("namespace", item.namespace)
        put("className", item.className)
        put("memberName", item.memberName)
        item.declaredType?.let { put("declaredType", it) }
        if (item.declaredType == null) put("declaredTypeStatus", "NOT_RECOVERED_FROM_DUMP")
        put("managedSignature", item.managedSignature)
        put("managedIdentity", item.managedIdentity)
        put("addressKind", item.addressKind)
        put("address", item.addressHex)
        item.addressHex.removePrefix("0x").toLongOrNull(16)?.let { put("addressDecimal", it) }
        if (item.memberKind == "METHOD") {
            item.methodRva?.let { put("methodRva", it) }
            item.methodFileOffset?.let { put("methodFileOffset", it) }
            item.dumpVirtualAddress?.let { put("dumpVirtualAddress", it) }
        } else {
            item.fieldOffset?.let { put("fieldOffset", it) }
        }
        put("addressFormula", item.addressFormula)
        put("runtimeAddressStatus", item.runtimeAddressStatus)
        put(
            "runtimeAddressResolution",
            JSONObject()
                .put("absoluteAddressAvailableOffline", false)
                .put("reason", if (item.memberKind == "METHOD") "ASLR_MODULE_BASE_REQUIRED" else "LIVE_OBJECT_INSTANCE_REQUIRED")
                .put("requiredValue", if (item.memberKind == "METHOD") "runtime libil2cpp.so module base" else "live ${item.namespace}.${item.className} object address"),
        )
        put("confidence", item.confidence)
        put("matchedMarker", item.marker)
    }

    private fun hex(value: String) = "0x${value.uppercase()}"
    private fun csv(value: String) = "\"${value.replace("\"", "\"\"")}\""

    private data class Rule(val domain: String, val category: String, val markers: List<String>)
    private val RULES = listOf(
        Rule("GAME", "HEALTH_DAMAGE", listOf("currenthealth", "maximumhealth", "maxhealth", "health", "hitpoints", "hitpoint", "currenthp", "maxhp", "hpvalue", "damage", "armor", "invincible", "godmode", "lifepoints")),
        Rule("GAME", "ECONOMY", listOf("softcurrency", "hardcurrency", "currency", "coins", "coin", "money", "cash", "gold", "gems", "gem", "diamond", "wallet", "balance", "reward", "inventory", "loot")),
        Rule("GAME", "COMBAT", listOf("weapon", "ammunition", "ammo", "firerate", "attackspeed", "attackpower", "criticaldamage", "criticalchance", "recoil")),
        Rule("GAME", "MOVEMENT", listOf("movespeed", "movementspeed", "walkspeed", "runspeed", "jumpspeed", "teleport", "gravity")),
        Rule("GAME", "PROGRESSION", listOf("experiencepoints", "experience", "playerlevel", "accountlevel", "levelup", "highscore", "achievement", "questreward", "skillpoints", "cooldown", "stamina", "energy")),
        Rule("MONETIZATION", "PREMIUM_SUBSCRIPTION", listOf("ispremium", "premiumuser", "premiumstatus", "isvip", "vipstatus", "paiduser", "isproaccount", "proaccount", "entitlement", "subscriptionactive", "subscriptionstatus", "subscribed", "hasboughtgame", "fullversion")),
        Rule("MONETIZATION", "PURCHASE_BILLING", listOf("inapppurchase", "purchase", "billingclient", "checkout", "restorepurchase", "verifyreceipt", "validatereceipt", "receipt")),
        Rule("APPLICATION", "AUTHORIZATION", listOf("authorization", "permissioncheck", "accesslevel", "hasaccess", "isadmin", "userrole")),
        Rule("APPLICATION", "FEATURE_QUOTA", listOf("featureenabled", "featureflag", "isunlocked", "paidfeature", "ratelimit", "dailylimit", "usagequota", "triallimit")),
        Rule("APPLICATION", "INTEGRITY_LICENSE", listOf("integritycheck", "tampercheck", "signaturecheck", "verifyintegrity", "licensecheck", "verifylicense")),
    )

    private val NAMESPACE = Regex("""^//\s*Namespace:\s*(.*)$""")
    private val ASSEMBLY = Regex("""^//\s*Dll\s*:\s*(.*)$""")
    private val TYPE = Regex("""\b(?:class|struct|interface|enum)\s+([A-Za-z_][A-Za-z0-9_.$`<>]*)""")
    private val METHOD_ADDRESS = Regex("""\bRVA:\s*0x([0-9A-Fa-f]+)(?:\s+Offset:\s*0x([0-9A-Fa-f]+))?(?:\s+VA:\s*0x([0-9A-Fa-f]+))?""")
    private val UNRESOLVED_METHOD_ADDRESS = Regex("""\bRVA:\s*-1\b""")
    private val FIELD = Regex("""^(.+?)\s+([A-Za-z_][A-Za-z0-9_$`<>]*)\s*;\s*//\s*0x([0-9A-Fa-f]+)\b.*$""")
    private val METHOD_NAME = Regex("""([A-Za-z_~][A-Za-z0-9_$`<>.]*)$""")
    private val MODIFIER = Regex("""^\s*(?:public|private|protected|internal|static|readonly|const|volatile|unsafe|new|sealed|virtual|abstract|override|extern|async)\s+""")
    private const val MAX_RELEVANT_STRINGS = 5_000
}
