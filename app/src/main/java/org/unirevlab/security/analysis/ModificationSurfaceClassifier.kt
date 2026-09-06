package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Ranks evidence-backed RVAs and unresolved IL2CPP identities that commonly sit on client trust
 * boundaries. Classification is semantic triage, not proof that changing a value produces a mod.
 */
object ModificationSurfaceClassifier {
    enum class TargetProfile { GAME_LIKELY, APPLICATION_LIKELY }
    enum class ProfileConfidence { HIGH, MEDIUM, LOW }
    enum class Priority { P1, P2, P3 }

    data class Candidate(
        val domain: String,
        val category: String,
        val priority: Priority,
        val source: String,
        val displayName: String,
        val technicalName: String?,
        val libraryEntry: String?,
        val abi: String?,
        val buildId: String?,
        val rva: Long?,
        val metadataToken: Long?,
        val resolvedRva: Boolean,
        val confidence: String,
        val matchedMarker: String,
        val reason: String,
    )

    data class Result(
        val targetProfile: TargetProfile,
        val profileConfidence: ProfileConfidence,
        val profileReasons: List<String>,
        val resolvedOffsets: List<Candidate>,
        val unresolvedManagedCandidates: List<Candidate>,
        val totalResolvedBeforeLimit: Int,
        val totalUnresolvedBeforeLimit: Int,
    )

    fun analyze(
        report: StaticAnalysisReport,
        maxResolved: Int = MAX_RESOLVED,
        maxUnresolved: Int = MAX_UNRESOLVED,
    ): Result {
        val profile = detectProfile(report)
        val libraryByEntry = report.native?.libraries.orEmpty().associateBy { it.entryName }
        val rules = when (profile.first) {
            TargetProfile.GAME_LIKELY -> GAMEPLAY_RULES + MONETIZATION_RULES + SHARED_RULES
            TargetProfile.APPLICATION_LIKELY -> APPLICATION_RULES + MONETIZATION_RULES + SHARED_RULES
        }

        val resolved = mutableListOf<Candidate>()
        val correlatedMethodIndexes = mutableSetOf<Int>()

        report.correlations?.il2cppMethods.orEmpty().forEach { method ->
            val text = "${method.declaringType}.${method.methodName} ${method.functionName}"
            val match = bestMatch(text, rules) ?: return@forEach
            correlatedMethodIndexes += method.methodIndex
            val library = libraryByEntry[method.libraryEntry]
            resolved += match.toCandidate(
                source = "IL2CPP_METHOD_RVA",
                displayName = "${method.declaringType}.${method.methodName}(…)",
                technicalName = method.functionName,
                libraryEntry = method.libraryEntry,
                abi = library?.abi,
                buildId = library?.buildId,
                rva = method.functionRva,
                metadataToken = method.token,
                resolvedRva = true,
                confidence = "HIGH",
                reasonPrefix = "Metadata-метод связан с конкретной native-функцией и RVA.",
            )
        }

        report.correlations?.jniNative.orEmpty().forEach { method ->
            val text = "${method.declaringClass}.${method.methodName} ${method.functionName.orEmpty()}"
            val match = bestMatch(text, rules) ?: return@forEach
            val library = libraryByEntry[method.libraryEntry]
            resolved += match.toCandidate(
                source = "JNI_METHOD_RVA",
                displayName = "${method.declaringClass}.${method.methodName}${method.prototype}",
                technicalName = method.functionName,
                libraryEntry = method.libraryEntry,
                abi = library?.abi,
                buildId = library?.buildId,
                rva = method.functionRva,
                metadataToken = null,
                resolvedRva = true,
                confidence = "HIGH",
                reasonPrefix = "DEX native-метод связан с конкретной ELF-функцией и RVA.",
            )
        }

        report.native?.libraries.orEmpty().forEach { library ->
            (library.exportedSymbols + library.importedSymbols)
                .asSequence()
                .filter { it.defined && it.virtualAddress != null }
                .distinctBy { it.name to it.virtualAddress }
                .forEach symbolLoop@ { symbol ->
                    val match = bestMatch(symbol.name, rules) ?: return@symbolLoop
                    resolved += match.toCandidate(
                        source = "NATIVE_SYMBOL_RVA",
                        displayName = symbol.name,
                        technicalName = symbol.name,
                        libraryEntry = library.entryName,
                        abi = library.abi,
                        buildId = library.buildId,
                        rva = symbol.virtualAddress,
                        metadataToken = null,
                        resolvedRva = true,
                        confidence = "LOW",
                        reasonPrefix = "RVA подтверждён таблицей ELF, назначение определено только по имени символа.",
                    )
                }
        }

        val resolvedDistinct = resolved
            .distinctBy { listOf(it.source, it.libraryEntry, it.rva, it.category, it.displayName) }
            .sortedWith(candidateComparator())

        val unresolved = report.il2cpp?.metadata?.methodDefinitions.orEmpty()
            .asSequence()
            .filterNot { it.index in correlatedMethodIndexes }
            .mapNotNull { method ->
                val match = bestMatch("${method.declaringType}.${method.name}", rules) ?: return@mapNotNull null
                match.toCandidate(
                    source = "IL2CPP_METADATA_ONLY",
                    displayName = "${method.declaringType}.${method.name}(…)",
                    technicalName = null,
                    libraryEntry = null,
                    abi = null,
                    buildId = null,
                    rva = null,
                    metadataToken = method.token,
                    resolvedRva = false,
                    confidence = "MEDIUM",
                    reasonPrefix = "Имя восстановлено из metadata, но native RVA этого метода не подтверждён.",
                )
            }
            .distinctBy { listOf(it.displayName, it.category, it.metadataToken) }
            .sortedWith(candidateComparator())
            .toList()

        return Result(
            targetProfile = profile.first,
            profileConfidence = profile.second,
            profileReasons = profile.third,
            resolvedOffsets = resolvedDistinct.take(maxResolved.coerceAtLeast(0)),
            unresolvedManagedCandidates = unresolved.take(maxUnresolved.coerceAtLeast(0)),
            totalResolvedBeforeLimit = resolvedDistinct.size,
            totalUnresolvedBeforeLimit = unresolved.size,
        )
    }

    private fun detectProfile(report: StaticAnalysisReport): Triple<TargetProfile, ProfileConfidence, List<String>> {
        val runtimeKinds = report.runtimes?.profiles.orEmpty().map { it.kind.uppercase() }
        val engineKinds = runtimeKinds.filter { kind ->
            kind.contains("UNITY") || kind.contains("UNREAL") || kind.contains("GODOT") || kind.contains("COCOS")
        }
        val managedCorpus = report.il2cpp?.metadata?.let { metadata ->
            (metadata.typeDefinitions.asSequence().map { it.fullName } +
                metadata.methodDefinitions.asSequence().map { "${it.declaringType}.${it.name}" })
                .take(PROFILE_CORPUS_LIMIT)
                .toList()
        }.orEmpty()
        val gameplayMatches = managedCorpus.count { bestMatch(it, GAMEPLAY_RULES) != null }
        val name = "${report.artifact.displayName} ${report.manifest?.packageName.orEmpty()}"
        val nameLooksGame = normalized(name).let { value -> GAME_NAME_MARKERS.any(value::contains) }

        return when {
            engineKinds.isNotEmpty() && gameplayMatches >= 2 -> Triple(
                TargetProfile.GAME_LIKELY,
                ProfileConfidence.HIGH,
                listOf("Игровой runtime: ${engineKinds.joinToString()}", "Игровых semantic-идентификаторов: $gameplayMatches"),
            )
            engineKinds.isNotEmpty() -> Triple(
                TargetProfile.GAME_LIKELY,
                ProfileConfidence.MEDIUM,
                listOf("Обнаружен runtime, часто используемый играми: ${engineKinds.joinToString()}", "Профиль является вероятностным"),
            )
            gameplayMatches >= 4 || (nameLooksGame && gameplayMatches >= 1) -> Triple(
                TargetProfile.GAME_LIKELY,
                ProfileConfidence.MEDIUM,
                listOf("Игровых semantic-идентификаторов: $gameplayMatches", "Игровой runtime не подтверждён"),
            )
            else -> Triple(
                TargetProfile.APPLICATION_LIKELY,
                if (runtimeKinds.isNotEmpty()) ProfileConfidence.MEDIUM else ProfileConfidence.LOW,
                listOf("Подтверждённых игровых runtime/semantic-признаков недостаточно", "Используется профиль обычного приложения"),
            )
        }
    }

    private data class Rule(
        val domain: String,
        val category: String,
        val priority: Priority,
        val title: String,
        val markers: List<String>,
    )

    private data class RuleMatch(val rule: Rule, val marker: String) {
        fun toCandidate(
            source: String,
            displayName: String,
            technicalName: String?,
            libraryEntry: String?,
            abi: String?,
            buildId: String?,
            rva: Long?,
            metadataToken: Long?,
            resolvedRva: Boolean,
            confidence: String,
            reasonPrefix: String,
        ) = Candidate(
            domain = rule.domain,
            category = rule.category,
            priority = rule.priority,
            source = source,
            displayName = displayName,
            technicalName = technicalName,
            libraryEntry = libraryEntry,
            abi = abi,
            buildId = buildId,
            rva = rva,
            metadataToken = metadataToken,
            resolvedRva = resolvedRva,
            confidence = confidence,
            matchedMarker = marker,
            reason = "$reasonPrefix ${rule.title}; маркер: $marker.",
        )
    }

    private fun bestMatch(value: String, rules: List<Rule>): RuleMatch? {
        val text = normalized(value)
        return rules.asSequence()
            .flatMap { rule -> rule.markers.asSequence().map { marker -> rule to normalized(marker) } }
            .filter { (_, marker) -> marker.length >= 4 && text.contains(marker) }
            .map { (rule, marker) -> RuleMatch(rule, marker) }
            .sortedWith(compareBy<RuleMatch>({ priorityOrder(it.rule.priority) }, { -it.marker.length }, { it.rule.category }))
            .firstOrNull()
    }

    private fun candidateComparator() = compareBy<Candidate>(
        { priorityOrder(it.priority) },
        { sourceOrder(it.source) },
        { it.category },
        { it.displayName },
        { it.rva ?: Long.MAX_VALUE },
    )

    private fun priorityOrder(value: Priority): Int = when (value) {
        Priority.P1 -> 0
        Priority.P2 -> 1
        Priority.P3 -> 2
    }

    private fun sourceOrder(value: String): Int = when (value) {
        "IL2CPP_METHOD_RVA" -> 0
        "JNI_METHOD_RVA" -> 1
        "NATIVE_SYMBOL_RVA" -> 2
        else -> 3
    }

    private fun normalized(value: String): String = value.lowercase().filter(Char::isLetterOrDigit)

    private val GAMEPLAY_RULES = listOf(
        Rule("GAMEPLAY", "ECONOMY_REWARDS", Priority.P1, "экономика, награды или инвентарь", listOf("currency", "coins", "gold", "gems", "diamond", "wallet", "balance", "reward", "inventory", "loot", "itemcount")),
        Rule("GAMEPLAY", "HEALTH_DAMAGE", Priority.P1, "здоровье, урон или неуязвимость", listOf("health", "hitpoints", "damage", "armor", "invincible", "godmode", "takeddamage", "dealtdamage")),
        Rule("GAMEPLAY", "COMBAT_RESOURCES", Priority.P1, "оружие или боевые ресурсы", listOf("weapon", "ammo", "firerate", "attackspeed", "criticaldamage", "criticalchance", "recoil")),
        Rule("GAMEPLAY", "MOVEMENT_PHYSICS", Priority.P2, "перемещение или физика", listOf("movespeed", "movementspeed", "walkspeed", "runspeed", "jumpspeed", "teleport", "velocity", "gravity")),
        Rule("GAMEPLAY", "TIMERS_ENERGY", Priority.P2, "таймеры, энергия или cooldown", listOf("cooldown", "stamina", "energy", "manapoint", "actionpoint", "remainingtime", "gametimer")),
        Rule("GAMEPLAY", "PROGRESSION", Priority.P2, "прогресс, уровень или результат матча", listOf("experience", "playerscore", "highscore", "playerlevel", "achievement", "missionreward", "questreward", "unlocklevel", "matchresult")),
    )

    private val APPLICATION_RULES = listOf(
        Rule("APPLICATION", "AUTHORIZATION", Priority.P1, "авторизация, роли или доступ", listOf("authorization", "permissioncheck", "accesslevel", "hasaccess", "isadmin", "userrole", "featureaccess")),
        Rule("APPLICATION", "FEATURE_GATES", Priority.P1, "локальный feature gate", listOf("featureenabled", "featureflag", "isunlocked", "unlockfeature", "restrictedfeature", "paidfeature")),
        Rule("APPLICATION", "QUOTA_LIMITS", Priority.P2, "квоты или ограничения использования", listOf("ratelimit", "dailylimit", "downloadlimit", "exportlimit", "usagequota", "remainingcredits", "triallimit")),
        Rule("APPLICATION", "DATA_EXPORT_SYNC", Priority.P3, "экспорт, синхронизация или локальный доступ к данным", listOf("exportdata", "downloaddata", "syncdata", "offlinemode", "localbackup")),
    )

    private val MONETIZATION_RULES = listOf(
        Rule("MONETIZATION", "PREMIUM_ENTITLEMENT", Priority.P1, "premium/VIP entitlement", listOf("ispremium", "premiumuser", "isvip", "vipuser", "paiduser", "isproaccount", "entitlement", "entitled", "subscriptionactive", "subscribed")),
        Rule("MONETIZATION", "PURCHASE_RECEIPT", Priority.P1, "покупка, billing или проверка receipt", listOf("purchase", "inapppurchase", "billingclient", "checkout", "restorepurchase", "verifyreceipt", "validatereceipt", "verifypurchase", "validatepurchase")),
        Rule("MONETIZATION", "ADS", Priority.P2, "отключение или выдача рекламы", listOf("removeads", "adsremoved", "adfree", "disableads", "rewardedad", "grantadreward")),
    )

    private val SHARED_RULES = listOf(
        Rule("SHARED_SECURITY", "INTEGRITY_TAMPER", Priority.P1, "контроль целостности или модификации клиента", listOf("integritycheck", "tampercheck", "antitamper", "signaturecheck", "verifychecksum", "verifyintegrity", "rootdetection", "debugdetection")),
        Rule("SHARED_SECURITY", "LICENSE", Priority.P1, "лицензирование клиента", listOf("licensecheck", "verifylicense", "licensevalid", "licenseduser")),
        Rule("SHARED_SECURITY", "SERVER_VALIDATION", Priority.P2, "серверная проверка или доверительная граница", listOf("servervalidate", "serververify", "backendverify", "remotevalidation", "validateentitlement")),
    )

    private val GAME_NAME_MARKERS = listOf("game", "play", "battle", "rpg", "arcade")
    private const val PROFILE_CORPUS_LIMIT = 20_000
    private const val MAX_RESOLVED = 800
    private const val MAX_UNRESOLVED = 800
}
