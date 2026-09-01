from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def read(path):
    return (ROOT / path).read_text(encoding='utf-8')

def write(path, text):
    (ROOT / path).write_text(text, encoding='utf-8')

def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f'missing anchor: {label}')
    return text.replace(old, new, 1)

# Version
p = 'app/build.gradle.kts'
s = read(p)
s = replace_once(s, 'versionCode = 33', 'versionCode = 34', 'versionCode')
s = replace_once(s, 'versionName = "0.25.4-dev-simplified-authorization"', 'versionName = "0.25.5-dev-automod-search-ux"', 'versionName')
write(p, s)

# TamperAssessmentEngine: unlimited, project-scoped default search; raw:/native: can still inspect everything.
p = 'app/src/main/java/org/unirevlab/security/analysis/TamperAssessmentEngine.kt'
s = read(p)
start = s.index('    fun search(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace, rawQuery: String): List<SearchResult> {')
end = s.index('    fun hardeningAdvice(', start)
new_search = r'''    fun search(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace, rawQuery: String): List<SearchResult> {
        val parsed = parseQuery(rawQuery)
        val q = parsed.second.lowercase(Locale.ROOT)
        require(q.length >= 2) { "Введите минимум 2 символа для поиска" }
        val rawMode = parsed.first == "raw"
        val filter = if (rawMode) null else parsed.first
        val defaultScoped = parsed.first == null
        val packagePrefix = report.manifest?.packageName?.takeIf { it.isNotBlank() }?.replace('.', '/')?.let { "L$it/" }
        val out = mutableListOf<SearchResult>()

        fun add(kind: String, haystack: String, result: () -> SearchResult) {
            if (filter != null && filter != kind.lowercase(Locale.ROOT)) return
            if (haystack.lowercase(Locale.ROOT).contains(q)) out += result()
        }

        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        dex?.classes.orEmpty().forEach { cls ->
            if (defaultScoped && !isProjectCode(cls.descriptor, packagePrefix)) return@forEach
            add("class", cls.descriptor) { SearchResult("DEX_CLASS", "${cls.dexEntry}:${cls.descriptor}", cls.descriptor, cls.dexEntry, cls.descriptor) }
        }
        dex?.methods.orEmpty().forEach { method ->
            if (defaultScoped && !isProjectCode(method.declaringClass, packagePrefix)) return@forEach
            val label = "${method.declaringClass}->${method.name}${method.prototype}"
            add("method", label) { methodResult("DEX_METHOD", method, label) }
        }
        dex?.stringXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            val callerClass = method?.declaringClass ?: xref.callerClass
            if (defaultScoped && !isProjectCode(callerClass, packagePrefix)) return@forEach
            val hay = "${xref.value} ${xref.callerClass} ${xref.callerName}"
            add("string", hay) {
                SearchResult(
                    "DEX_STRING", "${xref.dexEntry}:${xref.callerClass}->${xref.callerName}@${xref.instructionOffsetCodeUnits}",
                    safePreview(xref.value), method?.dexEntry ?: xref.dexEntry, callerClass,
                    method?.name ?: xref.callerName, method?.prototype,
                )
            }
        }
        dex?.fieldXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]
            val callerClass = method?.declaringClass ?: xref.callerClass
            if (defaultScoped && !isProjectCode(callerClass, packagePrefix)) return@forEach
            val hay = "${xref.declaringClass} ${xref.fieldName} ${xref.fieldType} ${xref.callerClass} ${xref.callerName}"
            add("field", hay) {
                SearchResult(
                    "DEX_FIELD", "${xref.dexEntry}:${xref.declaringClass}->${xref.fieldName}:${xref.fieldType}",
                    "${xref.kind}: ${xref.callerClass}->${xref.callerName}", method?.dexEntry ?: xref.dexEntry,
                    callerClass, method?.name ?: xref.callerName, method?.prototype,
                )
            }
        }
        dex?.constants.orEmpty().forEach { constant ->
            val method = methodsByKey[constant.dexEntry to constant.methodIndex]
            if (defaultScoped && (method == null || !isProjectCode(method.declaringClass, packagePrefix))) return@forEach
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
            if (defaultScoped && !isLikelyProjectNative(lib.entryName)) return@forEach
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
            scan(report, workspace).secrets.forEach { secret ->
                out += SearchResult("SECRET_CANDIDATE", secret.location, "${secret.kind}: ${secret.redactedPreview}")
            }
        }
        return out.distinctBy { listOf(it.kind, it.location, it.preview).joinToString("|") }
    }

'''
s = s[:start] + new_search + s[end:]

old_search_text = '''    private fun searchTextEntries(workspace: PatchLabEngine.Workspace, q: String, out: MutableList<SearchResult>) {
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
'''
new_search_text = '''    private fun searchTextEntries(workspace: PatchLabEngine.Workspace, q: String, out: MutableList<SearchResult>) {
        workspace.archiveEntries.asSequence().filter(::isTextCandidate).forEach { entry ->
            val text = runCatching { PatchLabEngine.loadArchiveText(workspace, entry) }.getOrNull() ?: return@forEach
            text.lineSequence().withIndex().forEach { indexed ->
                if (indexed.value.lowercase(Locale.ROOT).contains(q)) {
                    out += SearchResult("TEXT_FILE", "$entry:${indexed.index + 1}", safePreview(indexed.value), archiveEntry = entry)
                }
            }
        }
    }
'''
s = replace_once(s, old_search_text, new_search_text, 'searchTextEntries')

s = replace_once(
    s,
    '        val known = setOf("file", "text", "method", "class", "field", "string", "const", "native", "secret", "type")',
    '        val known = setOf("file", "text", "method", "class", "field", "string", "const", "native", "secret", "type", "raw")',
    'raw search prefix',
)

s = replace_once(
    s,
    '    private fun isAppOwned(descriptor: String, packagePrefix: String?): Boolean = packagePrefix != null && descriptor.startsWith(packagePrefix)\n    private fun isProjectCode(descriptor: String, packagePrefix: String?): Boolean {\n        if (isAppOwned(descriptor, packagePrefix)) return true\n        return NON_PROJECT_PREFIXES.none { descriptor.startsWith(it) }\n    }',
    '''    private fun isAppOwned(descriptor: String, packagePrefix: String?): Boolean = packagePrefix != null && descriptor.startsWith(packagePrefix)
    private fun isProjectCode(descriptor: String, packagePrefix: String?): Boolean {
        if (isAppOwned(descriptor, packagePrefix)) return true
        return NON_PROJECT_PREFIXES.none { descriptor.startsWith(it) }
    }
    internal fun isProjectCodeForAutomation(descriptor: String, packagePrefix: String?): Boolean =
        isProjectCode(descriptor, packagePrefix)
    internal fun categoriesForAutomation(text: String): List<Pair<String, Int>> = categoriesFor(text)

    private fun isLikelyProjectNative(entryName: String): Boolean {
        val file = entryName.substringAfterLast('/').lowercase(Locale.ROOT)
        if (file in setOf("libapp.so", "libil2cpp.so", "libmain.so", "libgame.so", "libnative-lib.so")) return true
        return NATIVE_SDK_MARKERS.none { marker -> marker in file }
    }''',
    'project/native helpers',
)

# Prevent third-party native C++ std::money_* symbols from inflating the assessment.
s = replace_once(
    s,
    '            (lib.exportedSymbols + lib.importedSymbols).forEach { symbol ->\n                categoriesFor("${lib.entryName} ${symbol.name}").forEach { (category, score) ->',
    '            if (isLikelyProjectNative(lib.entryName)) (lib.exportedSymbols + lib.importedSymbols).forEach { symbol ->\n                categoriesFor("${lib.entryName} ${symbol.name}").forEach { (category, score) ->',
    'native assessment scope',
)

s = replace_once(
    s,
    '        "LOCAL_STATE" to listOf("health", "hp", "lives", "life", "damage", "armor", "energy", "stamina", "speed", "cooldown", "score", "rank", "balance", "coins", "coin", "gems", "gem", "currency", "wallet", "credits"),',
    '        "LOCAL_STATE" to listOf("health", "hp", "lives", "life", "damage", "armor", "energy", "stamina", "speed", "cooldown", "score", "rank", "balance", "coins", "coin", "gems", "gem", "currency", "wallet", "credits", "money", "cash", "gold", "diamond", "diamonds", "xp", "experience", "level", "mana", "ammo", "attack", "defense", "defence", "power", "fuel", "ticket", "tickets", "points", "stars"),',
    'local state terms',
)

insert_marker = '    private val NON_PROJECT_PREFIXES = listOf(\n'
idx = s.index(insert_marker)
native_markers = '''    private val NATIVE_SDK_MARKERS = listOf(
        "firebase", "sentry", "applovin", "facebook", "fban", "crashlytics", "flutter",
        "mediakit", "mpv", "datastore", "sqlite", "boringssl", "ssl", "crypto", "protobuf",
        "realm", "bugsnag", "adjust", "onesignal", "unity", "c++_shared", "gnustl", "openal",
    )
'''
s = s[:idx] + native_markers + s[idx:]
write(p, s)

# AutoModEngine: build candidate plan directly from all editable project DEX evidence, not only top assessment hits.
p = 'app/src/main/java/org/unirevlab/security/analysis/AutoModEngine.kt'
s = read(p)
plan_start = s.index('    fun plan(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace): Plan {')
plan_end = s.index('    fun apply(', plan_start)
new_plan = r'''    fun plan(report: StaticAnalysisReport, workspace: PatchLabEngine.Workspace): Plan {
        if (report.artifact.sha256.isNotBlank()) {
            require(workspace.artifactSha256.equals(report.artifact.sha256, ignoreCase = true)) {
                "AutoMod заблокирован: workspace не совпадает с проанализированным APK"
            }
        }
        val packagePrefix = report.manifest?.packageName
            ?.takeIf { it.isNotBlank() }
            ?.replace('.', '/')
            ?.let { "L$it/" }

        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        val codeKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
        fun editableProject(method: org.unirevlab.security.model.DexMethodReference): Boolean =
            "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys &&
                TamperAssessmentEngine.isProjectCodeForAutomation(method.declaringClass, packagePrefix)

        data class Evidence(
            val category: String,
            val method: org.unirevlab.security.model.DexMethodReference,
            val score: Int,
            val text: String,
        )
        val evidence = mutableListOf<Evidence>()
        fun collect(method: org.unirevlab.security.model.DexMethodReference, text: String, scorePenalty: Int = 0) {
            if (!editableProject(method)) return
            TamperAssessmentEngine.categoriesForAutomation(text).forEach { (category, score) ->
                evidence += Evidence(category, method, (score - scorePenalty).coerceAtLeast(1), text)
            }
        }

        dex?.methods.orEmpty().forEach { method ->
            collect(method, "${method.declaringClass}->${method.name}${method.prototype}")
        }
        dex?.stringXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            collect(method, "${xref.value} ${xref.callerClass} ${xref.callerName}", 2)
        }
        dex?.fieldXrefs.orEmpty().forEach { xref ->
            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach
            collect(method, "${xref.declaringClass} ${xref.fieldName} ${xref.fieldType} ${xref.callerClass} ${xref.callerName}", 1)
        }
        dex?.constants.orEmpty().forEach { constant ->
            val method = methodsByKey[constant.dexEntry to constant.methodIndex] ?: return@forEach
            collect(method, "${method.declaringClass} ${method.name} ${constant.kind} ${constant.value}", 5)
        }

        val candidates = evidence.asSequence()
            .mapNotNull { item ->
                val method = item.method
                val suggestion = suggest(
                    category = item.category,
                    methodName = method.name,
                    prototype = method.prototype,
                    baseScore = item.score,
                    evidence = item.text,
                ) ?: return@mapNotNull null
                Action(
                    id = "automod-${item.category.lowercase(Locale.ROOT)}-${method.methodIndex}",
                    category = item.category,
                    dexEntry = method.dexEntry,
                    classDescriptor = method.declaringClass,
                    methodName = method.name,
                    prototype = method.prototype,
                    mode = suggestion.mode,
                    intValue = suggestion.intValue,
                    confidence = suggestion.confidence,
                    reason = suggestion.reason,
                )
            }
            .groupBy { it.methodKey }
            .mapNotNull { (_, values) -> values.maxByOrNull { it.confidence } }
            .sortedWith(compareByDescending<Action> { it.confidence }.thenBy { it.target })

        val selected = selectDiverse(candidates)
        return Plan(
            artifactSha256 = workspace.artifactSha256,
            assessmentScore = assessment.score,
            assessmentBand = assessment.band,
            actions = selected,
            eligibleBeforeCap = candidates.size,
        )
    }

'''
s = s[:plan_start] + new_plan + s[plan_end:]

s = replace_once(
    s,
    '''    internal fun suggestForTesting(
        category: String,
        methodName: String,
        prototype: String,
        baseScore: Int = 70,
    ): Suggestion? = suggest(category, methodName, prototype, baseScore)
''',
    '''    internal fun suggestForTesting(
        category: String,
        methodName: String,
        prototype: String,
        baseScore: Int = 70,
        evidence: String = "",
    ): Suggestion? = suggest(category, methodName, prototype, baseScore, evidence)
''',
    'suggestForTesting',
)

suggest_start = s.index('    private fun suggest(category: String, methodName: String, prototype: String, baseScore: Int): Suggestion? {')
suggest_end = s.index('    private fun String.lastReturnType()', suggest_start)
new_suggest = r'''    private fun suggest(
        category: String,
        methodName: String,
        prototype: String,
        baseScore: Int,
        evidence: String = "",
    ): Suggestion? {
        val methodTokens = identifierTokens(methodName)
        val evidenceTokens = identifierTokens(evidence)
        val tokens = methodTokens + evidenceTokens
        val compact = tokens.joinToString("")
        val methodCompact = methodTokens.joinToString("")
        val decisionPrefix = methodTokens.firstOrNull() in DECISION_PREFIXES
        val evidenceBacked = evidenceTokens.isNotEmpty() && baseScore >= 46

        if (prototype.endsWith(")Z")) {
            val negative = NEGATIVE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
            return when (category) {
                "ENTITLEMENT_TRUST" -> {
                    if (PENDING_MARKERS.any { it in tokens }) return null
                    val signal = ENTITLEMENT_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(
                            Mode.RETURN_FALSE, null, (baseScore + if (decisionPrefix) 8 else 2).coerceIn(0, 100),
                            "Демонстрация: client-side entitlement/access gate подтверждён кодом/ссылками и принудительно возвращает false.",
                        )
                    } else {
                        Suggestion(
                            Mode.RETURN_TRUE, null, (baseScore + if (decisionPrefix) 10 else 3).coerceIn(0, 100),
                            "Демонстрация: client-side premium/access/entitlement gate подтверждён кодом/ссылками и принудительно возвращает true.",
                        )
                    }
                }
                "FEATURE_CONFIG" -> {
                    val signal = FEATURE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(Mode.RETURN_FALSE, null, (baseScore + 2).coerceIn(0, 100), "Демонстрация: локальный disabled/blocked feature-флаг принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, (baseScore + 4).coerceIn(0, 100), "Демонстрация: локальный feature/config gate принудительно возвращает true.")
                    }
                }
                "INTEGRITY" -> {
                    val signal = INTEGRITY_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if (negative) {
                        Suggestion(Mode.RETURN_FALSE, null, (baseScore + 6).coerceIn(0, 100), "Демонстрация: client-side tamper/root/emulator/debugger сигнал принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, (baseScore + 4).coerceIn(0, 100), "Демонстрация: локальная integrity/signature/attestation проверка принудительно возвращает true.")
                    }
                }
                "LOCAL_STATE" -> {
                    val signal = LOCAL_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }
                    if (!signal || (!decisionPrefix && !evidenceBacked)) null
                    else if ("dead" in tokens || "empty" in tokens || "depleted" in tokens) {
                        Suggestion(Mode.RETURN_FALSE, null, baseScore.coerceIn(0, 100), "Демонстрация: локальное отрицательное state-решение принудительно возвращает false.")
                    } else {
                        Suggestion(Mode.RETURN_TRUE, null, baseScore.coerceIn(0, 100), "Демонстрация: локальное state-решение принудительно возвращает true.")
                    }
                }
                else -> null
            }
        }

        if (category == "LOCAL_STATE" && prototype.lastReturnType() in setOf('I', 'S', 'B', 'C')) {
            val selected = LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in methodTokens }
                ?: LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in evidenceTokens }
                ?: return null
            val confidence = (baseScore + if (termInMethod(selected.key, methodTokens, methodCompact)) 4 else 0).coerceIn(0, 100)
            return Suggestion(
                Mode.RETURN_INT, selected.value, confidence,
                "Демонстрация: project-owned ${selected.key} state getter/consumer подтверждён индексом и получает фиксированное тестовое значение ${selected.value}.",
            )
        }
        return null
    }

    private fun termInMethod(term: String, methodTokens: Set<String>, methodCompact: String): Boolean =
        term in methodTokens || methodCompact.contains(term)

'''
s = s[:suggest_start] + new_suggest + s[suggest_end:]

s = replace_once(
    s,
    '    private val LOCAL_BOOLEAN_MARKERS = setOf("alive", "dead", "lives", "energy", "stamina", "ammo", "currency", "coins", "gems")',
    '    private val LOCAL_BOOLEAN_MARKERS = setOf("alive", "dead", "lives", "energy", "stamina", "ammo", "currency", "coins", "gems", "money", "cash", "gold", "mana")',
    'local boolean markers',
)
s = replace_once(
    s,
    '        "credits" to 9999,\n',
    '        "credits" to 9999,\n        "money" to 9999,\n        "cash" to 9999,\n        "gold" to 9999,\n        "diamond" to 9999,\n        "diamonds" to 9999,\n        "xp" to 9999,\n        "experience" to 9999,\n        "level" to 99,\n        "mana" to 999,\n        "ammo" to 999,\n        "attack" to 999,\n        "defense" to 999,\n        "defence" to 999,\n        "power" to 999,\n        "fuel" to 999,\n        "ticket" to 999,\n        "tickets" to 999,\n        "points" to 9999,\n        "stars" to 999,\n',
    'local int values',
)
write(p, s)

# AutoMod UI: explain zero-target diagnostics rather than a mysterious disabled button.
p = 'app/src/main/java/org/unirevlab/security/ui/AutoModPanel.kt'
s = read(p)
s = replace_once(
    s,
    '                        "Высокоуверенных app-owned целей для автоматической модификации не найдено. " +\n                            "Это не означает отсутствия риска — используйте ручной Patch Lab/trace.",',
    '                        "Автоматически патчабельных DEX-целей не найдено. AutoMod проверил project-owned методы, " +\n                            "string/field/constant evidence и поддерживаемые boolean/int return-типы. " +\n                            "Если состояние хранится во время выполнения, используйте Runtime State Lab; если цель native/IL2CPP — соответствующий native/managed режим.",',
    'automod zero explanation',
)
write(p, s)

# Regression tests for obfuscated/evidence-backed AutoMod and third-party substring noise.
p = 'app/src/test/java/org/unirevlab/security/analysis/AutoModEngineTest.kt'
s = read(p)
anchor = '''    @Test
    fun choosesBoundedLocalStateIntegerDemo() {
'''
insert = '''    @Test
    fun evidenceBackedObfuscatedMethodsCanStillBecomeDemoTargets() {
        assertEquals(
            AutoModEngine.Mode.RETURN_TRUE,
            AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "a", "()Z", 68, "premium entitlement access")?.mode,
        )
        val money = AutoModEngine.suggestForTesting("LOCAL_STATE", "b", "()I", 58, "player money balance")
        assertEquals(AutoModEngine.Mode.RETURN_INT, money?.mode)
        assertEquals(9999, money?.intValue)
    }

'''
s = replace_once(s, anchor, insert + anchor, 'AutoMod evidence test')
write(p, s)

p = 'app/src/test/java/org/unirevlab/security/analysis/TamperAssessmentClassifierTest.kt'
s = read(p)
s = replace_once(
    s,
    '        assertTrue("LOCAL_STATE" in TamperAssessmentEngine.categoriesForTesting("getHighScore"))\n',
    '        assertTrue("LOCAL_STATE" in TamperAssessmentEngine.categoriesForTesting("getHighScore"))\n        assertTrue("LOCAL_STATE" in TamperAssessmentEngine.categoriesForTesting("playerMoney"))\n',
    'money classifier test',
)
write(p, s)

print('v0.25.5 AutoMod/search engine patch applied')
