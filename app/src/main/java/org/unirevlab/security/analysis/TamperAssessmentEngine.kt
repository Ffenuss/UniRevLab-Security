package org.unirevlab.security.analysis

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale
import java.util.zip.ZipFile
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Defensive tamper-surface assessment for an authorized target.
 *
 * It discovers client-side trust/state/configuration surfaces and proposes observation-only hooks.
 * It deliberately does not generate entitlement/IAP/license bypass patches or reveal raw secrets.
 */
object TamperAssessmentEngine {
    data class SurfaceHit(
        val category: String,
        val kind: String,
        val location: String,
        val preview: String,
        val score: Int,
        val dexEntry: String? = null,
        val classDescriptor: String? = null,
        val methodName: String? = null,
        val prototype: String? = null,
        val archiveEntry: String? = null,
    )

    data class SecretHit(
        val kind: String,
        val location: String,
        val redactedPreview: String,
        val sha256: String,
    )

    data class HookProposal(
        val id: String,
        val category: String,
        val reason: String,
        val dexEntry: String,
        val classDescriptor: String,
        val methodName: String,
        val prototype: String,
        val template: String = "ENTRY_TRACE",
    )

    data class CategorySummary(val category: String, val count: Int, val maxScore: Int)

    data class Assessment(
        val score: Int,
        val band: String,
        val categories: List<CategorySummary>,
        val hits: List<SurfaceHit>,
        val secrets: List<SecretHit>,
        val hookProposals: List<HookProposal>,
        val truncated: Boolean,
    )

    data class SearchResult(
        val kind: String,
        val location: String,
        val preview: String,
        val dexEntry: String? = null,
        val classDescriptor: String? = null,
        val methodName: String? = null,
        val prototype: String? = null,
        val archiveEntry: String? = null,
    )

    data class HardeningSuggestion(
        val priority: String,
        val title: String,
        val evidence: String,
        val actions: List<String>,
    )

    private val cache = Collections.synchronizedMap(mutableMapOf<String, Assessment>())

    fun scan(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace): Assessment {
        val cacheKey = "${report.artifact.sha256}:${workspace.originalApk.length()}"
        cache[cacheKey]?.let { return it }
        val built = buildAssessment(report, workspace)
        cache[cacheKey] = built
        return built
    }

    fun search(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace, rawQuery: String): List<SearchResult> {
        val parsed = parseQuery(rawQuery)
        val q = parsed.second.lowercase(Locale.ROOT)
        require(q.length >= 2) { "Введите минимум 2 символа для поиска" }
        val filter = parsed.first
        val out = mutableListOf<SearchResult>()
        fun add(kind: String, haystack: String, result: () -> SearchResult) {
            if (out.size >= MAX_SEARCH_RESULTS) return
            if (filter != null && filter != kind.lowercase(Locale.ROOT)) return
            if (haystack.lowercase(Locale.ROOT).contains(q)) out += result()
        }

        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        dex?.classes.orEmpty().forEach { cls ->
            add("class", cls.descriptor) { SearchResult("DEX_CLASS", "${cls.dexEntry}:${cls.descriptor}", cls.descriptor, cls.dexEntry, cls.descriptor) }
        }
        dex?.methods.orEmpty().forEach { method ->
            val label = "${method.declaringClass}->${method.name}${method.prototype}"
            add("method", label) { methodResult("DEX_METHOD", method, label) }
        }
        dex?.stringXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            val hay = "${xref.value} ${xref.callerClass} ${xref.callerName}"
            add("string", hay) {
                SearchResult(
                    "DEX_STRING", "${xref.dexEntry}:${xref.callerClass}->${xref.callerName}@${xref.instructionOffsetCodeUnits}",
                    safePreview(xref.value), method?.dexEntry ?: xref.dexEntry, method?.declaringClass ?: xref.callerClass,
                    method?.name ?: xref.callerName, method?.prototype,
                )
            }
        }
        dex?.fieldXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            val hay = "${xref.declaringClass} ${xref.fieldName} ${xref.fieldType} ${xref.callerClass} ${xref.callerName}"
            add("field", hay) {
                SearchResult(
                    "DEX_FIELD", "${xref.dexEntry}:${xref.declaringClass}->${xref.fieldName}:${xref.fieldType}",
                    "${xref.kind}: ${xref.callerClass}->${xref.callerName}", method?.dexEntry ?: xref.dexEntry,
                    method?.declaringClass ?: xref.callerClass, method?.name ?: xref.callerName, method?.prototype,
                )
            }
        }
        dex?.constants.orEmpty().forEach { constant ->
            val method = methodsByKey[constant.dexEntry to constant.methodIndex]
            val hay = "${constant.kind} ${constant.value} ${method?.declaringClass.orEmpty()} ${method?.name.orEmpty()}"
            add("const", hay) {
                SearchResult(
                    "DEX_CONSTANT", "${constant.dexEntry}:method#${constant.methodIndex}@${constant.instructionOffsetCodeUnits}",
                    "${constant.kind}=${safePreview(constant.value)}", method?.dexEntry ?: constant.dexEntry,
                    method?.declaringClass, method?.name, method?.prototype,
                )
            }
        }

        report.native?.libraries.orEmpty().forEach { lib ->
            add("native", lib.entryName) { SearchResult("NATIVE_LIBRARY", lib.entryName, "${lib.abi} ${lib.machine}", archiveEntry = lib.entryName) }
            (lib.exportedSymbols + lib.importedSymbols).forEach { symbol ->
                add("native", "${lib.entryName} ${symbol.name}") {
                    SearchResult("NATIVE_SYMBOL", "${lib.entryName}:${symbol.name}", "${symbol.symbolType} ${symbol.binding}", archiveEntry = lib.entryName)
                }
            }
            lib.jniSymbols.forEach { symbol ->
                add("native", "${lib.entryName} $symbol") { SearchResult("JNI_SYMBOL", "${lib.entryName}:$symbol", symbol, archiveEntry = lib.entryName) }
            }
        }

        report.il2cpp?.metadata?.typeDefinitions.orEmpty().forEach { type ->
            add("type", type.fullName) { SearchResult("IL2CPP_TYPE", "${report.il2cpp?.metadata?.entryName}:${type.index}", type.fullName) }
        }
        report.il2cpp?.metadata?.methodDefinitions.orEmpty().forEach { method ->
            val label = "${method.declaringType}->${method.name}"
            add("method", label) { SearchResult("IL2CPP_METHOD", "${report.il2cpp?.metadata?.entryName}:${method.index}", label) }
        }
        report.runtimeArtifacts?.unityMono?.assemblies.orEmpty().forEach { assembly ->
            assembly.typeDefinitions.forEach { type ->
                add("type", "${assembly.entryName} ${type.fullName}") { SearchResult("MANAGED_TYPE", assembly.entryName, type.fullName, archiveEntry = assembly.entryName) }
            }
            assembly.methodDefinitions.forEach { method ->
                add("method", "${assembly.entryName} ${method.declaringType} ${method.name}") {
                    SearchResult("MANAGED_METHOD", assembly.entryName, "${method.declaringType}->${method.name}", archiveEntry = assembly.entryName)
                }
            }
        }

        workspace.archiveEntries.forEach { entry ->
            add("file", entry) { SearchResult("ARCHIVE_ENTRY", entry, entry, archiveEntry = entry) }
        }
        if (filter == null || filter in setOf("file", "text", "string")) {
            searchTextEntries(workspace, q, out)
        }
        if (filter == "secret") {
            scan(report, workspace).secrets.take(MAX_SEARCH_RESULTS - out.size).forEach { secret ->
                out += SearchResult("SECRET_CANDIDATE", secret.location, "${secret.kind}: ${secret.redactedPreview}")
            }
        }
        return out.take(MAX_SEARCH_RESULTS)
    }

    fun hardeningAdvice(
        report: StaticAnalysisReport,
        assessment: Assessment,
        apkDiff: ApkMutationDiffEngine.ApkDiffReport,
        codeDiffs: List<ApkMutationDiffEngine.CodeDiff>,
    ): List<HardeningSuggestion> {
        val categories = assessment.categories.associateBy { it.category }
        val out = mutableListOf<HardeningSuggestion>()
        if (categories.containsKey("ENTITLEMENT_TRUST")) {
            out += HardeningSuggestion(
                "HIGH", "Не доверять локальному entitlement/feature-флагу",
                "Найдены клиентские точки принятия решений о доступе/лицензии/покупке.",
                listOf(
                    "Сделать сервер источником истины для платных прав и критичных feature entitlements.",
                    "Проверять store receipts/transactions на сервере и выдавать короткоживущий подписанный entitlement.",
                    "Не считать обфускацию или native-перенос самостоятельной границей безопасности.",
                ),
            )
        }
        if (categories.containsKey("LOCAL_STATE")) {
            out += HardeningSuggestion(
                "HIGH", "Убрать доверие к критичному локальному состоянию",
                "Найдены изменяемые клиентские state/economy/gameplay значения или константы.",
                listOf(
                    "Для соревновательных, экономических и серверных операций валидировать состояние на backend.",
                    "Использовать server-authoritative расчёты и sanity/rate checks, а не только локальные ограничения.",
                    "Для offline-состояния подпись/HMAC с per-install ключом снижает простые правки, но не заменяет серверную проверку.",
                ),
            )
        }
        if (categories.containsKey("FEATURE_CONFIG")) {
            out += HardeningSuggestion(
                "MEDIUM", "Защитить security-critical конфигурацию",
                "Обнаружены локальные config/feature surfaces и редактируемые текстовые assets.",
                listOf(
                    "Подписывать удалённую конфигурацию и проверять подпись перед применением.",
                    "Не хранить security-critical allow/deny решение только в assets/resources/shared preferences.",
                    "Разделять UX feature flags и реальные серверные права доступа.",
                ),
            )
        }
        if (assessment.secrets.isNotEmpty()) {
            out += HardeningSuggestion(
                "CRITICAL", "Удалить глобальные секреты из клиентского APK",
                "Найдено redacted secret/key candidates: ${assessment.secrets.size}.",
                listOf(
                    "Считать любой общий secret, поставляемый в APK/DEX/.so/assets, извлекаемым.",
                    "Ротировать подтверждённые утечки и переносить привилегированные операции на backend/broker.",
                    "Android Keystore использовать для per-install ключей; серверные private keys и общие API secrets в APK не хранить.",
                ),
            )
        }
        if (categories.containsKey("INTEGRITY")) {
            out += HardeningSuggestion(
                "MEDIUM", "Сделать integrity-проверку серверным сигналом",
                "Есть локальные integrity/signature/attestation точки, которые сами находятся внутри изменяемого клиента.",
                listOf(
                    "Использовать Play Integrity/attestation на сервере как один из risk signals.",
                    "Проверку собственной подписи/хэшей оставлять defense-in-depth, не единственной защитой.",
                    "Привязывать высокорисковые backend-операции к nonce, session и серверной проверке результата attestation.",
                ),
            )
        }
        val tinyPatch = codeDiffs.filter { it.addedLines + it.removedLines in 1..8 }
        if (tinyPatch.isNotEmpty()) {
            out += HardeningSuggestion(
                "HIGH", "Критичное поведение меняется малым патчем",
                "${tinyPatch.size} изменённых участков требуют не более 8 строк каждый; это наглядный признак слабой client trust boundary.",
                listOf(
                    "Перенести решение, дающее ценность/доступ/авторизацию, за доверенную серверную границу.",
                    "Добавить серверные инварианты, чтобы локальная правка не давала действительного результата на backend.",
                    "После исправления повторить этот же Patch Lab сценарий и убедиться, что клиентская правка больше не меняет серверный результат.",
                ),
            )
        }
        if (apkDiff.signatureMetadataChanges > 0 || report.manifest?.signingCertificateSha256?.isNotEmpty() == true) {
            out += HardeningSuggestion(
                "MEDIUM", "Учитывать переподписание клиента",
                "Лабораторная сборка имеет другую подпись; локальная подпись сама по себе не предотвращает модификацию после переустановки.",
                listOf(
                    "На backend проверять app integrity/signing identity через поддерживаемую attestation-схему.",
                    "Не помещать долгоживущие секреты в код, рассчитывая только на подпись APK.",
                ),
            )
        }
        if (apkDiff.unexpectedContentChanges.isNotEmpty()) {
            out += HardeningSuggestion(
                "CRITICAL", "Проверить непредвиденные изменения пересборки",
                "Изменены entry вне выбранных лабораторных патчей: ${apkDiff.unexpectedContentChanges.take(8).joinToString()}.",
                listOf("Не использовать такую сборку как доказательство до устранения побочных изменений."),
            )
        }
        return out.distinctBy { it.title }.sortedBy { priorityOrdinal(it.priority) }
    }

    private fun buildAssessment(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace): Assessment {
        val hits = mutableListOf<SurfaceHit>()
        val secrets = mutableListOf<SecretHit>()
        var truncated = false
        fun hit(value: SurfaceHit) {
            if (hits.size < MAX_HITS) hits += value else truncated = true
        }

        val packagePrefix = report.manifest?.packageName?.takeIf { it.isNotBlank() }?.replace('.', '/')?.let { "L$it/" }
        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        dex?.methods.orEmpty().forEach { method ->
            val label = "${method.declaringClass}->${method.name}${method.prototype}"
            categoriesFor(label).forEach { (category, score) ->
                hit(methodHit(category, score, method, label))
            }
            if (DECISION_METHOD.matches(method.name) && isAppOwned(method.declaringClass, packagePrefix)) {
                hit(methodHit("CLIENT_DECISION", 36, method, label))
            }
        }
        dex?.stringXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            categoriesFor("${xref.value} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->
                hit(
                    SurfaceHit(
                        category, "DEX_STRING", "${xref.dexEntry}:${xref.callerClass}->${xref.callerName}@${xref.instructionOffsetCodeUnits}",
                        safePreview(xref.value), score, method?.dexEntry ?: xref.dexEntry,
                        method?.declaringClass ?: xref.callerClass, method?.name ?: xref.callerName, method?.prototype,
                    ),
                )
            }
        }
        dex?.fieldXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            categoriesFor("${xref.fieldName} ${xref.declaringClass} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->
                hit(
                    SurfaceHit(
                        category, "DEX_FIELD", "${xref.dexEntry}:${xref.declaringClass}->${xref.fieldName}:${xref.fieldType}",
                        "${xref.kind}; caller=${xref.callerClass}->${xref.callerName}", score,
                        method?.dexEntry ?: xref.dexEntry, method?.declaringClass ?: xref.callerClass,
                        method?.name ?: xref.callerName, method?.prototype,
                    ),
                )
            }
        }
        var genericConstants = 0
        dex?.constants.orEmpty().forEach { constant ->
            val method = methodsByKey[constant.dexEntry to constant.methodIndex] ?: return@forEach
            val methodLabel = "${method.declaringClass}->${method.name}${method.prototype}"
            val categories = categoriesFor(methodLabel)
            if (categories.isNotEmpty()) {
                categories.forEach { (category, score) ->
                    hit(SurfaceHit(category, "DEX_CONSTANT", "${constant.dexEntry}:$methodLabel@${constant.instructionOffsetCodeUnits}", "${constant.kind}=${safePreview(constant.value)}", score - 5, method.dexEntry, method.declaringClass, method.name, method.prototype))
                }
            } else if (genericConstants < MAX_GENERIC_CONSTANTS && isAppOwned(method.declaringClass, packagePrefix) && isInterestingConstant(constant.value)) {
                genericConstants++
                hit(SurfaceHit("APP_CONSTANT", "DEX_CONSTANT", "${constant.dexEntry}:$methodLabel@${constant.instructionOffsetCodeUnits}", "${constant.kind}=${safePreview(constant.value)}", 30, method.dexEntry, method.declaringClass, method.name, method.prototype))
            }
        }

        dex?.secretCandidates.orEmpty().forEach { secret ->
            secrets += SecretHit(secret.kind, "${secret.dexEntry}:string#${secret.stringIndex}", secret.redactedPreview, secret.valueSha256)
        }
        report.native?.libraries.orEmpty().forEach { lib ->
            lib.secretCandidates.forEach { secret ->
                secrets += SecretHit(secret.kind, secret.libraryEntry, secret.redactedPreview, secret.valueSha256)
            }
            (lib.exportedSymbols + lib.importedSymbols).forEach { symbol ->
                categoriesFor("${lib.entryName} ${symbol.name}").forEach { (category, score) ->
                    hit(SurfaceHit(category, "NATIVE_SYMBOL", "${lib.entryName}:${symbol.name}", "${symbol.symbolType} ${symbol.binding}", score - 4, archiveEntry = lib.entryName))
                }
            }
        }

        report.il2cpp?.metadata?.methodDefinitions.orEmpty().forEach { method ->
            categoriesFor("${method.declaringType} ${method.name}").forEach { (category, score) ->
                hit(SurfaceHit(category, "IL2CPP_METHOD", "${report.il2cpp?.metadata?.entryName}:${method.index}", "${method.declaringType}->${method.name}", score - 3))
            }
        }
        report.runtimeArtifacts?.unityMono?.assemblies.orEmpty().forEach { assembly ->
            assembly.methodDefinitions.forEach { method ->
                categoriesFor("${method.declaringType} ${method.name}").forEach { (category, score) ->
                    hit(SurfaceHit(category, "MANAGED_METHOD", assembly.entryName, "${method.declaringType}->${method.name}", score - 3, archiveEntry = assembly.entryName))
                }
            }
        }

        ZipFile(workspace.originalApk).use { zip ->
            var textBytes = 0L
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                val name = entry.name
                categoriesFor(name).forEach { (category, score) -> hit(SurfaceHit(category, "ARCHIVE_ENTRY", name, name, score - 8, archiveEntry = name)) }
                if (isConfigLike(name)) hit(SurfaceHit("CONFIG_FILE", "ARCHIVE_ENTRY", name, name, 22, archiveEntry = name))
                if (!isTextCandidate(name) || textBytes >= MAX_AUTO_TEXT_BYTES) continue
                val text = runCatching { readText(zip, entry.name, MAX_AUTO_TEXT_ENTRY_BYTES) }.getOrNull() ?: continue
                textBytes += text.toByteArray(Charsets.UTF_8).size
                val lower = text.lowercase(Locale.ROOT)
                CATEGORY_TERMS.forEach { (category, terms) ->
                    val term = terms.firstOrNull { lower.contains(it) } ?: return@forEach
                    val line = text.lineSequence().firstOrNull { it.lowercase(Locale.ROOT).contains(term) }.orEmpty()
                    hit(SurfaceHit(category, "TEXT_ASSET", name, safePreview(line), CATEGORY_SCORES.getValue(category) - 6, archiveEntry = name))
                }
                scanTextSecrets(name, text, secrets)
            }
            if (textBytes >= MAX_AUTO_TEXT_BYTES) truncated = true
        }

        val distinctHits = hits.distinctBy { listOf(it.category, it.kind, it.location, it.preview).joinToString("|") }
            .sortedWith(compareByDescending<SurfaceHit> { it.score }.thenBy { it.location })
            .take(MAX_HITS)
        val distinctSecrets = secrets.distinctBy { it.sha256 }.take(MAX_SECRETS)
        val categories = distinctHits.groupBy { it.category }.map { (category, values) -> CategorySummary(category, values.size, values.maxOf { it.score }) }
            .sortedWith(compareByDescending<CategorySummary> { it.maxScore }.thenByDescending { it.count })
        val codeMethodKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
        val proposals = distinctHits.asSequence()
            .filter { it.dexEntry != null && it.classDescriptor != null && it.methodName != null && it.prototype != null }
            .filter { "${it.dexEntry}|${it.classDescriptor}|${it.methodName}|${it.prototype}" in codeMethodKeys }
            .distinctBy { "${it.dexEntry}|${it.classDescriptor}|${it.methodName}|${it.prototype}" }
            .take(MAX_HOOK_PROPOSALS)
            .mapIndexed { index, hit ->
                HookProposal(
                    id = "trace-${index + 1}", category = hit.category,
                    reason = "Trace-only наблюдение: ${categoryTitle(hit.category)}; ${hit.location}",
                    dexEntry = requireNotNull(hit.dexEntry), classDescriptor = requireNotNull(hit.classDescriptor),
                    methodName = requireNotNull(hit.methodName), prototype = requireNotNull(hit.prototype),
                )
            }.toList()
        val rawScore = categories.sumOf { (it.maxScore * (1.0 + minOf(it.count, 8) / 10.0)).toInt() } + distinctSecrets.size * 18
        val score = rawScore.coerceIn(0, 100)
        return Assessment(score, band(score), categories, distinctHits, distinctSecrets, proposals, truncated)
    }

    private fun searchTextEntries(workspace: PatchLabEngine.Workspace, q: String, out: MutableList<SearchResult>) {
        var scanned = 0L
        workspace.archiveEntries.asSequence().filter(::isTextCandidate).forEach { entry ->
            if (out.size >= MAX_SEARCH_RESULTS || scanned >= MAX_MANUAL_TEXT_BYTES) return@forEach
            val text = runCatching { PatchLabEngine.loadArchiveText(workspace, entry) }.getOrNull() ?: return@forEach
            scanned += text.toByteArray(Charsets.UTF_8).size
            text.lineSequence().withIndex().forEach { indexed ->
                if (out.size >= MAX_SEARCH_RESULTS) return@forEach
                if (indexed.value.lowercase(Locale.ROOT).contains(q)) {
                    out += SearchResult("TEXT_FILE", "$entry:${indexed.index + 1}", safePreview(indexed.value), archiveEntry = entry)
                }
            }
        }
    }

    private fun methodResult(kind: String, method: DexMethodReference, preview: String) = SearchResult(
        kind, "${method.dexEntry}:${method.declaringClass}->${method.name}${method.prototype}", preview,
        method.dexEntry, method.declaringClass, method.name, method.prototype,
    )

    private fun methodHit(category: String, score: Int, method: DexMethodReference, preview: String) = SurfaceHit(
        category, "DEX_METHOD", "${method.dexEntry}:${method.declaringClass}->${method.name}${method.prototype}",
        safePreview(preview), score, method.dexEntry, method.declaringClass, method.name, method.prototype,
    )

    private fun categoriesFor(text: String): List<Pair<String, Int>> {
        val lower = text.lowercase(Locale.ROOT)
        return CATEGORY_TERMS.mapNotNull { (category, terms) ->
            if (terms.any { lower.contains(it) }) category to CATEGORY_SCORES.getValue(category) else null
        }
    }

    private fun parseQuery(raw: String): Pair<String?, String> {
        val trimmed = raw.trim()
        val index = trimmed.indexOf(':')
        if (index <= 0) return null to trimmed
        val prefix = trimmed.substring(0, index).lowercase(Locale.ROOT)
        val known = setOf("file", "text", "method", "class", "field", "string", "const", "native", "secret", "type")
        return if (prefix in known) prefix to trimmed.substring(index + 1).trim() else null to trimmed
    }

    private fun scanTextSecrets(entry: String, text: String, out: MutableList<SecretHit>) {
        if (out.size >= MAX_SECRETS) return
        if (text.contains("-----BEGIN PRIVATE KEY-----") || text.contains("-----BEGIN RSA PRIVATE KEY-----") || text.contains("-----BEGIN EC PRIVATE KEY-----")) {
            val marker = "private-key-marker:$entry"
            out += SecretHit("PRIVATE_KEY_MATERIAL", entry, "-----BEGIN … PRIVATE KEY-----", sha256(marker))
        }
        GENERIC_SECRET.findAll(text).take(8).forEach { match ->
            if (out.size >= MAX_SECRETS) return@forEach
            val value = match.groupValues.getOrNull(2).orEmpty()
            if (value.length < 12 || value.all { it == '*' || it == 'x' || it == 'X' }) return@forEach
            out += SecretHit(match.groupValues[1].uppercase(Locale.ROOT), entry, redact(value), sha256(value))
        }
    }

    private fun readText(zip: ZipFile, entryName: String, maxBytes: Int): String? {
        val entry = zip.getEntry(entryName) ?: return null
        zip.getInputStream(entry).use { input ->
            val bytes = readBounded(input, maxBytes) ?: return null
            return decodeText(bytes)
        }
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Int): ByteArray? {
        val out = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
        val buffer = ByteArray(32 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            total += read
            if (total > maxBytes) return null
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun decodeText(bytes: ByteArray): String? {
        if (bytes.any { it == 0.toByte() }) return null
        val value = bytes.toString(Charsets.UTF_8)
        if ('\uFFFD' in value) return null
        val controls = value.count { it.code < 0x20 && it !in listOf('\n', '\r', '\t') }
        if (controls > maxOf(2, value.length / 100)) return null
        return value
    }

    private fun isTextCandidate(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return TEXT_EXTENSIONS.any { lower.endsWith(it) } || lower.substringAfterLast('/').let { it == "config" || it == "settings" }
    }

    private fun isConfigLike(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return isTextCandidate(name) && listOf("config", "setting", "feature", "flag", "remote", "property", "profile", "balance", "rule").any { lower.contains(it) }
    }

    private fun isAppOwned(descriptor: String, packagePrefix: String?): Boolean = packagePrefix != null && descriptor.startsWith(packagePrefix)
    private fun isInterestingConstant(value: String): Boolean {
        val normalized = value.trim().lowercase(Locale.ROOT)
        if (normalized in setOf("0", "0x0", "1", "0x1", "-1")) return false
        return normalized.matches(Regex("[-+]?(?:0x[0-9a-f]+|\\d+(?:\\.\\d+)?)"))
    }

    private fun safePreview(value: String): String = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim().take(260)
    private fun redact(value: String): String = when {
        value.length <= 8 -> "***"
        else -> value.take(4) + "…" + value.takeLast(4)
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    private fun band(score: Int): String = when { score >= 75 -> "HIGH"; score >= 45 -> "MEDIUM"; score >= 20 -> "LOW"; else -> "MINIMAL" }
    private fun categoryTitle(category: String): String = when (category) {
        "ENTITLEMENT_TRUST" -> "client-side entitlement/access decision"
        "LOCAL_STATE" -> "local state/economy/gameplay surface"
        "FEATURE_CONFIG" -> "feature/configuration surface"
        "INTEGRITY" -> "integrity/attestation surface"
        "AUTH_SESSION" -> "auth/session material"
        "CLIENT_DECISION" -> "client-side boolean/decision method"
        "APP_CONSTANT" -> "application-owned scalar constant"
        "CONFIG_FILE" -> "editable configuration asset"
        else -> category
    }
    private fun priorityOrdinal(value: String): Int = when (value) { "CRITICAL" -> 0; "HIGH" -> 1; "MEDIUM" -> 2; else -> 3 }

    private val CATEGORY_TERMS = linkedMapOf(
        "ENTITLEMENT_TRUST" to listOf("premium", "subscription", "entitlement", "purchase", "isowned", "owned", "unlock", "license", "licence", "trial", "ispro", "hasaccess", "accesslevel", "vip", "paid"),
        "LOCAL_STATE" to listOf("health", "hp", "lives", "life", "damage", "armor", "energy", "stamina", "speed", "cooldown", "score", "rank", "balance", "coins", "coin", "gems", "gem", "currency", "wallet", "credits"),
        "FEATURE_CONFIG" to listOf("featureflag", "feature_flag", "remoteconfig", "remote_config", "experiment", "variant", "toggle", "feature", "config", "setting"),
        "INTEGRITY" to listOf("integrity", "tamper", "signature", "checksum", "attestation", "playintegrity", "rootcheck", "emulatorcheck"),
        "AUTH_SESSION" to listOf("apikey", "api_key", "clientsecret", "client_secret", "bearer", "sessiontoken", "auth_token", "accesstoken", "access_token"),
    )
    private val CATEGORY_SCORES = mapOf("ENTITLEMENT_TRUST" to 70, "LOCAL_STATE" to 60, "FEATURE_CONFIG" to 48, "INTEGRITY" to 56, "AUTH_SESSION" to 68)
    private val DECISION_METHOD = Regex("^(is|has|can|allow|check|verify|validate|enable|should|may)[A-Z_].*|^(is|has|can|allow|check|verify|validate|enable|should|may).*$", RegexOption.IGNORE_CASE)
    private val GENERIC_SECRET = Regex("(?i)[\\\"']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token)[\\\"']?\\s*[:=]\\s*[\\\"']?([A-Za-z0-9+/_=.-]{12,})")
    private val TEXT_EXTENSIONS = listOf(".json", ".txt", ".xml", ".yaml", ".yml", ".properties", ".ini", ".cfg", ".conf", ".csv", ".toml", ".js", ".html", ".md")
    private const val MAX_HITS = 360
    private const val MAX_SECRETS = 80
    private const val MAX_HOOK_PROPOSALS = 32
    private const val MAX_SEARCH_RESULTS = 200
    private const val MAX_GENERIC_CONSTANTS = 80
    private const val MAX_AUTO_TEXT_ENTRY_BYTES = 512 * 1024
    private const val MAX_AUTO_TEXT_BYTES = 12L * 1024L * 1024L
    private const val MAX_MANUAL_TEXT_BYTES = 24L * 1024L * 1024L
}
