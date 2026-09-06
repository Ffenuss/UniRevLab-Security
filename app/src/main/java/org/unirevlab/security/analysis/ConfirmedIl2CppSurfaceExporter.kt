package org.unirevlab.security.analysis

import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/** Extracts audit-relevant surfaces only from addresses present in a completed engine dump.cs. */
object ConfirmedIl2CppSurfaceExporter {
    data class Summary(
        val gameplayCount: Int,
        val applicationCount: Int,
        val outputJson: File,
        val outputCsv: File,
    )

    private data class DumpAddress(val rva: String, val fileOffset: String?, val virtualAddress: String?)
    private data class Member(val name: String, val declaredType: String?, val signature: String)

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
        var currentNamespace = "<global>"
        var currentType = "<unknown-type>"
        var pendingAddress: DumpAddress? = null
        dumpCs.bufferedReader(Charsets.UTF_8, 128 * 1024).useLines { lines ->
            lines.forEach { raw ->
                val line = raw.trim()
                NAMESPACE.find(line)?.groupValues?.getOrNull(1)?.let {
                    currentNamespace = it.trim().ifBlank { "<global>" }
                }
                TYPE.find(line)?.groupValues?.getOrNull(1)?.let { currentType = it }
                METHOD_ADDRESS.find(line)?.let { match ->
                    pendingAddress = DumpAddress(
                        rva = hex(match.groupValues[1]),
                        fileOffset = match.groupValues.getOrNull(2)?.takeIf(String::isNotBlank)?.let(::hex),
                        virtualAddress = match.groupValues.getOrNull(3)?.takeIf(String::isNotBlank)?.let(::hex),
                    )
                    return@forEach
                }
                val methodAddress = pendingAddress
                if (methodAddress != null && line.isNotBlank() && !line.startsWith("//") && !line.startsWith("[")) {
                    parseMethod(line)?.let { member ->
                        classify(currentNamespace, currentType, member, "METHOD_RVA", methodAddress.rva, methodAddress)?.let(matches::add)
                    }
                    pendingAddress = null
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
        val jsonFile = File(outputDirectory, "security-surfaces.json")
        val csvFile = File(outputDirectory, "security-surfaces.csv")
        val json = JSONObject()
            .put("schemaVersion", "2.0")
            .put("source", "completed rodroid dump.cs")
            .put("semantics", "RVA is relative to the loaded module base; FIELD_OFFSET is relative to a live object instance. ASLR prevents a stable absolute runtime address from being stored in an offline report.")
            .put("gameplayOffsets", JSONArray(gameplay.map(::toJson)))
            .put("applicationAndMonetizationOffsets", JSONArray(application.map(::toJson)))
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
        return Summary(gameplay.size, application.size, jsonFile, csvFile)
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
        val normalized = identity.lowercase().filter(Char::isLetterOrDigit)
        val rule = RULES.asSequence()
            .flatMap { candidate -> candidate.markers.asSequence().map { marker -> candidate to marker } }
            .filter { (_, marker) -> normalized.contains(marker) }
            .maxByOrNull { (_, marker) -> marker.length }
            ?: return null
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

    private fun toJson(item: Match) = JSONObject()
        .put("domain", item.domain)
        .put("category", item.category)
        .put("memberKind", item.memberKind)
        .put("namespace", item.namespace)
        .put("className", item.className)
        .put("memberName", item.memberName)
        .put("declaredType", item.declaredType ?: JSONObject.NULL)
        .put("managedSignature", item.managedSignature)
        .put("managedIdentity", item.managedIdentity)
        .put("addressKind", item.addressKind)
        .put("address", item.addressHex)
        .put("addressDecimal", item.addressHex.removePrefix("0x").toLongOrNull(16) ?: JSONObject.NULL)
        .put("methodRva", item.methodRva ?: JSONObject.NULL)
        .put("methodFileOffset", item.methodFileOffset ?: JSONObject.NULL)
        .put("dumpVirtualAddress", item.dumpVirtualAddress ?: JSONObject.NULL)
        .put("fieldOffset", item.fieldOffset ?: JSONObject.NULL)
        .put("addressFormula", item.addressFormula)
        .put("runtimeAddressStatus", item.runtimeAddressStatus)
        .put("runtimeAbsoluteAddress", JSONObject.NULL)
        .put("confidence", item.confidence)
        .put("matchedMarker", item.marker)

    private fun hex(value: String) = "0x${value.uppercase()}"
    private fun csv(value: String) = "\"${value.replace("\"", "\"\"")}\""

    private data class Rule(val domain: String, val category: String, val markers: List<String>)
    private val RULES = listOf(
        Rule("GAME", "HEALTH_DAMAGE", listOf("currenthealth", "maximumhealth", "maxhealth", "health", "hitpoints", "hitpoint", "currenthp", "maxhp", "hpvalue", "damage", "armor", "invincible", "godmode", "lifepoints")),
        Rule("GAME", "ECONOMY", listOf("softcurrency", "hardcurrency", "currency", "coins", "coin", "money", "cash", "gold", "gems", "gem", "diamond", "wallet", "balance", "reward", "inventory", "loot")),
        Rule("GAME", "COMBAT", listOf("weapon", "ammunition", "ammo", "firerate", "attackspeed", "attackpower", "criticaldamage", "criticalchance", "recoil")),
        Rule("GAME", "MOVEMENT", listOf("movespeed", "movementspeed", "walkspeed", "runspeed", "jumpspeed", "teleport", "gravity")),
        Rule("GAME", "PROGRESSION", listOf("experiencepoints", "experience", "playerlevel", "accountlevel", "levelup", "highscore", "achievement", "questreward", "skillpoints", "cooldown", "stamina", "energy")),
        Rule("MONETIZATION", "PREMIUM_SUBSCRIPTION", listOf("ispremium", "premiumuser", "premiumstatus", "isvip", "vipstatus", "paiduser", "isproaccount", "proaccount", "entitlement", "subscriptionactive", "subscriptionstatus", "subscribed")),
        Rule("MONETIZATION", "PURCHASE_BILLING", listOf("inapppurchase", "purchase", "billingclient", "checkout", "restorepurchase", "verifyreceipt", "validatereceipt")),
        Rule("APPLICATION", "AUTHORIZATION", listOf("authorization", "permissioncheck", "accesslevel", "hasaccess", "isadmin", "userrole")),
        Rule("APPLICATION", "FEATURE_QUOTA", listOf("featureenabled", "featureflag", "isunlocked", "paidfeature", "ratelimit", "dailylimit", "usagequota", "triallimit")),
        Rule("APPLICATION", "INTEGRITY_LICENSE", listOf("integritycheck", "tampercheck", "signaturecheck", "verifyintegrity", "licensecheck", "verifylicense")),
    )

    private val NAMESPACE = Regex("""^//\s*Namespace:\s*(.*)$""")
    private val TYPE = Regex("""\b(?:class|struct|interface|enum)\s+([A-Za-z_][A-Za-z0-9_.$`<>]*)""")
    private val METHOD_ADDRESS = Regex("""\bRVA:\s*0x([0-9A-Fa-f]+)(?:\s+Offset:\s*0x([0-9A-Fa-f]+))?(?:\s+VA:\s*0x([0-9A-Fa-f]+))?""")
    private val FIELD = Regex("""^(.+?)\s+([A-Za-z_][A-Za-z0-9_$`<>]*)\s*;\s*//\s*0x([0-9A-Fa-f]+)\b.*$""")
    private val METHOD_NAME = Regex("""([A-Za-z_~][A-Za-z0-9_$`<>.]*)$""")
    private val MODIFIER = Regex("""^\s*(?:public|private|protected|internal|static|readonly|const|volatile|unsafe|new|sealed|virtual|abstract|override|extern|async)\s+""")
}
