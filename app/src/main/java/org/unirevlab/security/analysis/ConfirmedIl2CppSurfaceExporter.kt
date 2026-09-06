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

    private data class Match(
        val domain: String,
        val category: String,
        val marker: String,
        val addressKind: String,
        val addressHex: String,
        val identity: String,
        val confidence: String,
    )

    fun export(dumpCs: File, outputDirectory: File): Summary {
        require(dumpCs.isFile && dumpCs.length() > 0L) { "Completed dump.cs is required" }
        val matches = mutableListOf<Match>()
        var currentType = "<unknown-type>"
        var pendingRva: String? = null
        dumpCs.bufferedReader(Charsets.UTF_8, 128 * 1024).useLines { lines ->
            lines.forEach { raw ->
                val line = raw.trim()
                TYPE.find(line)?.groupValues?.getOrNull(1)?.let { currentType = it }
                RVA.find(line)?.groupValues?.getOrNull(1)?.let {
                    pendingRva = "0x${it.uppercase()}"
                    return@forEach
                }
                val rva = pendingRva
                if (rva != null && line.isNotBlank() && !line.startsWith("//") && !line.startsWith("[")) {
                    if ('(' in line) {
                        classify("$currentType.$line", "METHOD_RVA", rva)?.let(matches::add)
                    }
                    pendingRva = null
                }
                FIELD.find(line)?.let { field ->
                    val name = field.groupValues[1]
                    val offset = "0x${field.groupValues[2].uppercase()}"
                    classify("$currentType.$name", "FIELD_OFFSET", offset)?.let(matches::add)
                }
            }
        }
        val distinct = matches.distinctBy { listOf(it.domain, it.category, it.addressKind, it.addressHex, it.identity) }
            .sortedWith(compareBy({ it.domain }, { it.category }, { it.identity }, { it.addressHex }))
        val gameplay = distinct.filter { it.domain == "GAME" }
        val application = distinct.filter { it.domain != "GAME" }
        val jsonFile = File(outputDirectory, "security-surfaces.json")
        val csvFile = File(outputDirectory, "security-surfaces.csv")
        val json = JSONObject()
            .put("schemaVersion", "1.0")
            .put("source", "completed rodroid dump.cs")
            .put("semantics", "Defensive triage only; an address does not prove exploitability or client authority.")
            .put("gameplayOffsets", JSONArray(gameplay.map(::toJson)))
            .put("applicationAndMonetizationOffsets", JSONArray(application.map(::toJson)))
        jsonFile.writeText(json.toString(2), Charsets.UTF_8)
        csvFile.bufferedWriter(Charsets.UTF_8).use { output ->
            output.appendLine("domain,category,address_kind,address,confidence,matched_marker,managed_identity")
            distinct.forEach { item ->
                output.appendLine(listOf(item.domain, item.category, item.addressKind, item.addressHex, item.confidence, item.marker, item.identity).joinToString(",") { csv(it) })
            }
        }
        return Summary(gameplay.size, application.size, jsonFile, csvFile)
    }

    private fun classify(identity: String, addressKind: String, address: String): Match? {
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
            identity = identity.take(2_000),
            confidence = if (addressKind == "METHOD_RVA") "HIGH" else "MEDIUM",
        )
    }

    private fun toJson(item: Match) = JSONObject()
        .put("domain", item.domain)
        .put("category", item.category)
        .put("addressKind", item.addressKind)
        .put("address", item.addressHex)
        .put("confidence", item.confidence)
        .put("matchedMarker", item.marker)
        .put("managedIdentity", item.identity)

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

    private val RVA = Regex("""\bRVA:\s*0x([0-9A-Fa-f]+)\b""")
    private val TYPE = Regex("""\b(?:class|struct|interface)\s+([A-Za-z_][A-Za-z0-9_.$`<>]*)""")
    private val FIELD = Regex("""\b([A-Za-z_][A-Za-z0-9_$`<>]*)\s*;\s*//\s*0x([0-9A-Fa-f]+)\b""")
}
