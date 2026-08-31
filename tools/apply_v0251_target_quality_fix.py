from pathlib import Path

ROOT = Path('.')


def replace_once(path: str, old: str, new: str):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if new in text:
        return
    if old not in text:
        raise SystemExit(f'patch state mismatch: {path}: anchor not found')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')


build = ROOT / 'app/build.gradle.kts'
text = build.read_text(encoding='utf-8')
if 'versionName = "0.25.1-dev-target-quality"' not in text:
    if 'versionName = "0.25.0-dev-easy-audit"' not in text:
        raise SystemExit('v0.25.1 expects v0.25.0 source')
    text = text.replace('versionCode = 29', 'versionCode = 30', 1)
    text = text.replace('versionName = "0.25.0-dev-easy-audit"', 'versionName = "0.25.1-dev-target-quality"', 1)
    build.write_text(text, encoding='utf-8')

engine = 'app/src/main/java/org/unirevlab/security/analysis/TamperAssessmentEngine.kt'
replace_once(
    engine,
    '''        val dex = report.dex\n        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }\n        dex?.methods.orEmpty().forEach { method ->\n            val label = "${method.declaringClass}->${method.name}${method.prototype}"\n            categoriesFor(label).forEach { (category, score) ->\n                hit(methodHit(category, score, method, label))\n            }\n            if (DECISION_METHOD.matches(method.name) && isAppOwned(method.declaringClass, packagePrefix)) {\n                hit(methodHit("CLIENT_DECISION", 36, method, label))\n            }\n        }''',
    '''        val dex = report.dex\n        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }\n        val codeMethodKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()\n        fun isEditableProjectMethod(method: DexMethodReference): Boolean =\n            "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeMethodKeys &&\n                isProjectCode(method.declaringClass, packagePrefix)\n\n        dex?.methods.orEmpty().filter(::isEditableProjectMethod).forEach { method ->\n            val label = "${method.declaringClass}->${method.name}${method.prototype}"\n            categoriesFor(label).forEach { (category, score) ->\n                hit(methodHit(category, score, method, label))\n            }\n            if (DECISION_METHOD.matches(method.name)) {\n                hit(methodHit("CLIENT_DECISION", 36, method, label))\n            }\n        }''',
)
replace_once(
    engine,
    '''        dex?.stringXrefs.orEmpty().forEach { xref ->\n            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]\n            categoriesFor("${xref.value} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->''',
    '''        dex?.stringXrefs.orEmpty().forEach { xref ->\n            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach\n            if (!isEditableProjectMethod(method)) return@forEach\n            categoriesFor("${xref.value} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->''',
)
replace_once(
    engine,
    '''                        safePreview(xref.value), score, method?.dexEntry ?: xref.dexEntry,\n                        method?.declaringClass ?: xref.callerClass, method?.name ?: xref.callerName, method?.prototype,''',
    '''                        safePreview(xref.value), score, method.dexEntry,\n                        method.declaringClass, method.name, method.prototype,''',
)
replace_once(
    engine,
    '''        dex?.fieldXrefs.orEmpty().forEach { xref ->\n            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex]\n            categoriesFor("${xref.fieldName} ${xref.declaringClass} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->''',
    '''        dex?.fieldXrefs.orEmpty().forEach { xref ->\n            val method = methodsByKey[xref.dexEntry to xref.callerMethodIndex] ?: return@forEach\n            if (!isEditableProjectMethod(method)) return@forEach\n            categoriesFor("${xref.fieldName} ${xref.declaringClass} ${xref.callerClass} ${xref.callerName}").forEach { (category, score) ->''',
)
replace_once(
    engine,
    '''                        "${xref.kind}; caller=${xref.callerClass}->${xref.callerName}", score,\n                        method?.dexEntry ?: xref.dexEntry, method?.declaringClass ?: xref.callerClass,\n                        method?.name ?: xref.callerName, method?.prototype,''',
    '''                        "${xref.kind}; caller=${xref.callerClass}->${xref.callerName}", score,\n                        method.dexEntry, method.declaringClass, method.name, method.prototype,''',
)
replace_once(
    engine,
    '''        dex?.constants.orEmpty().forEach { constant ->\n            val method = methodsByKey[constant.dexEntry to constant.methodIndex] ?: return@forEach\n            val methodLabel = "${method.declaringClass}->${method.name}${method.prototype}"''',
    '''        dex?.constants.orEmpty().forEach { constant ->\n            val method = methodsByKey[constant.dexEntry to constant.methodIndex] ?: return@forEach\n            if (!isEditableProjectMethod(method)) return@forEach\n            val methodLabel = "${method.declaringClass}->${method.name}${method.prototype}"''',
)
replace_once(
    engine,
    '''            } else if (genericConstants < MAX_GENERIC_CONSTANTS && isAppOwned(method.declaringClass, packagePrefix) && isInterestingConstant(constant.value)) {''',
    '''            } else if (genericConstants < MAX_GENERIC_CONSTANTS && isInterestingConstant(constant.value)) {''',
)
replace_once(
    engine,
    '''        val categories = distinctHits.groupBy { it.category }.map { (category, values) -> CategorySummary(category, values.size, values.maxOf { it.score }) }\n            .sortedWith(compareByDescending<CategorySummary> { it.maxScore }.thenByDescending { it.count })\n        val codeMethodKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()\n        val proposals = distinctHits.asSequence()''',
    '''        val categories = distinctHits.groupBy { it.category }.map { (category, values) -> CategorySummary(category, values.size, values.maxOf { it.score }) }\n            .sortedWith(compareByDescending<CategorySummary> { it.maxScore }.thenByDescending { it.count })\n        val proposals = distinctHits.asSequence()''',
)
replace_once(
    engine,
    '''            .filter { "${it.dexEntry}|${it.classDescriptor}|${it.methodName}|${it.prototype}" in codeMethodKeys }''',
    '''            .filter { "${it.dexEntry}|${it.classDescriptor}|${it.methodName}|${it.prototype}" in codeMethodKeys }\n            .filter { isProjectCode(requireNotNull(it.classDescriptor), packagePrefix) }''',
)
replace_once(
    engine,
    '''    private fun categoriesFor(text: String): List<Pair<String, Int>> {\n        val lower = text.lowercase(Locale.ROOT)\n        return CATEGORY_TERMS.mapNotNull { (category, terms) ->\n            if (terms.any { lower.contains(it) }) category to CATEGORY_SCORES.getValue(category) else null\n        }\n    }''',
    '''    private fun categoriesFor(text: String): List<Pair<String, Int>> {\n        val tokens = identifierTokens(text)\n        val compact = tokens.joinToString("")\n        return CATEGORY_TERMS.mapNotNull { (category, terms) ->\n            val matched = terms.any { term ->\n                val normalized = term.lowercase(Locale.ROOT).replace("_", "")\n                if (normalized in COMPOUND_TERMS) compact.contains(normalized) else normalized in tokens\n            }\n            if (matched) category to CATEGORY_SCORES.getValue(category) else null\n        }\n    }\n\n    private fun identifierTokens(text: String): Set<String> {\n        val expanded = text.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")\n        return expanded.lowercase(Locale.ROOT).split(Regex("[^a-z0-9]+"))\n            .asSequence().filter { it.isNotBlank() }.toSet()\n    }''',
)
replace_once(
    engine,
    '''    private fun isAppOwned(descriptor: String, packagePrefix: String?): Boolean = packagePrefix != null && descriptor.startsWith(packagePrefix)''',
    '''    private fun isAppOwned(descriptor: String, packagePrefix: String?): Boolean = packagePrefix != null && descriptor.startsWith(packagePrefix)\n    private fun isProjectCode(descriptor: String, packagePrefix: String?): Boolean {\n        if (isAppOwned(descriptor, packagePrefix)) return true\n        return NON_PROJECT_PREFIXES.none { descriptor.startsWith(it) }\n    }''',
)
replace_once(
    engine,
    '''        if (assessment.secrets.isNotEmpty()) {\n            out += HardeningSuggestion(\n                "CRITICAL", "Удалить глобальные секреты из клиентского APK",\n                "Найдено redacted secret/key candidates: ${assessment.secrets.size}.",''',
    '''        val highRiskSecrets = assessment.secrets.filterNot { it.kind == "GOOGLE_API_KEY_LIKE" || it.kind == "PRIVATE_KEY_MARKER" }\n        if (highRiskSecrets.isNotEmpty()) {\n            out += HardeningSuggestion(\n                "CRITICAL", "Удалить подтверждённые глобальные секреты из клиентского APK",\n                "Найдено high-risk redacted secret/key candidates: ${highRiskSecrets.size}.",''',
)
replace_once(
    engine,
    '''        if (categories.containsKey("INTEGRITY")) {''',
    '''        if (assessment.secrets.any { it.kind == "GOOGLE_API_KEY_LIKE" }) {\n            out += HardeningSuggestion(\n                "MEDIUM", "Проверить ограничения Google API key",\n                "Найден Google API-key-like identifier в клиентском артефакте; само присутствие такого ключа не всегда является утечкой.",\n                listOf(\n                    "Проверить Android package/certificate restrictions и разрешённые API.",\n                    "Не использовать клиентский API key как доказательство авторизации пользователя или как серверный secret.",\n                    "Проверить quotas и ротацию, если ключ ранее использовался без ограничений.",\n                ),\n            )\n        }\n        if (categories.containsKey("INTEGRITY")) {''',
)
replace_once(
    engine,
    '''        if (text.contains("-----BEGIN PRIVATE KEY-----") || text.contains("-----BEGIN RSA PRIVATE KEY-----") || text.contains("-----BEGIN EC PRIVATE KEY-----")) {\n            val marker = "private-key-marker:$entry"\n            out += SecretHit("PRIVATE_KEY_MATERIAL", entry, "-----BEGIN … PRIVATE KEY-----", sha256(marker))\n        }''',
    '''        PRIVATE_KEY_BLOCK.find(text)?.let { match ->\n            val material = match.value\n            out += SecretHit("PRIVATE_KEY_MATERIAL", entry, "-----BEGIN … PRIVATE KEY-----", sha256(material))\n        }''',
)
replace_once(
    engine,
    '''    private val CATEGORY_SCORES = mapOf("ENTITLEMENT_TRUST" to 70, "LOCAL_STATE" to 60, "FEATURE_CONFIG" to 48, "INTEGRITY" to 56, "AUTH_SESSION" to 68)''',
    '''    private val CATEGORY_SCORES = mapOf("ENTITLEMENT_TRUST" to 70, "LOCAL_STATE" to 60, "FEATURE_CONFIG" to 48, "INTEGRITY" to 56, "AUTH_SESSION" to 68)\n    private val COMPOUND_TERMS = setOf("isowned", "hasaccess", "accesslevel", "featureflag", "remoteconfig", "playintegrity", "rootcheck", "emulatorcheck", "apikey", "clientsecret", "sessiontoken", "authtoken", "accesstoken")\n    private val NON_PROJECT_PREFIXES = listOf(\n        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",\n        "Ldalvik/", "Lsun/", "Lorg/apache/", "Lorg/chromium/", "Lorg/json/",\n        "Lcom/google/", "Lcom/android/", "Lcom/facebook/", "Lcom/squareup/",\n        "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lio/flutter/", "Lio/sentry/",\n        "Lcom/applovin/", "Lcom/adjust/", "Lcom/bugsnag/", "Lcom/onesignal/",\n    )''',
)
replace_once(
    engine,
    '''    private val GENERIC_SECRET = Regex("(?i)[\\\\\\\"']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token)[\\\\\\\"']?\\\\s*[:=]\\\\s*[\\\\\\\"']?([A-Za-z0-9+/_=.-]{12,})")''',
    '''    private val GENERIC_SECRET = Regex("(?i)[\\\\\\\"']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token)[\\\\\\\"']?\\\\s*[:=]\\\\s*[\\\\\\\"']?([A-Za-z0-9+/_=.-]{12,})")\n    private val PRIVATE_KEY_BLOCK = Regex(\n        "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\\\\s+[A-Za-z0-9+/=\\\\r\\\\n]{128,}\\\\s+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",\n        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),\n    )''',
)

classifier = 'app/src/main/java/org/unirevlab/security/analysis/SensitiveStringClassifier.kt'
replace_once(
    classifier,
    '''            return "PRIVATE_KEY_MATERIAL"''',
    '''            return "PRIVATE_KEY_MARKER"''',
)

patch_engine = 'app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt'
replace_once(
    patch_engine,
    '''        val directMethod = Regex("(L[^;\\\\s]+;)->([^\\\\s(]+)(\\\\([^\\\\n]*?\\\\)[VZBSCIJFDL\\\\[][^\\\\s:]*)")\n            .find(joined)\n        if (directMethod != null) {\n            return PatchTarget(\n                findingId = finding.id,\n                dexEntry = dexEntry,\n                classDescriptor = directMethod.groupValues[1],\n                methodName = directMethod.groupValues[2],\n                prototype = directMethod.groupValues[3],\n                nativeEntry = nativeEntry,\n                evidenceLocation = evidence.firstOrNull()?.location,\n                evidenceValue = evidence.firstOrNull()?.value,\n            )\n        }''',
    '''        val directMethod = Regex("(L[^;\\\\s]+;)->([^\\\\s(]+)(\\\\([^\\\\n]*?\\\\)[VZBSCIJFDL\\\\[][^\\\\s:]*)")\n            .find(joined)\n        if (directMethod != null) {\n            val targetClass = directMethod.groupValues[1]\n            val targetName = directMethod.groupValues[2]\n            val targetPrototype = directMethod.groupValues[3]\n            val dexSummary = report.dex\n            val codeKeys = dexSummary?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()\n            val direct = dexSummary?.methods.orEmpty().firstOrNull { method ->\n                method.declaringClass == targetClass && method.name == targetName && method.prototype == targetPrototype &&\n                    "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys\n            }\n            if (direct != null) {\n                return PatchTarget(\n                    findingId = finding.id, dexEntry = direct.dexEntry, classDescriptor = direct.declaringClass,\n                    methodName = direct.name, prototype = direct.prototype, nativeEntry = nativeEntry,\n                    evidenceLocation = evidence.firstOrNull()?.location, evidenceValue = evidence.firstOrNull()?.value,\n                )\n            }\n            val methodsByKey = dexSummary?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }\n            val packagePrefix = report.manifest?.packageName?.takeIf { it.isNotBlank() }?.replace('.', '/')?.let { "L$it/" }\n            val caller = dexSummary?.callXrefs.orEmpty().asSequence()\n                .filter { it.calleeClass == targetClass && it.calleeName == targetName && it.calleePrototype == targetPrototype }\n                .mapNotNull { xref -> methodsByKey[xref.dexEntry to xref.callerMethodIndex] }\n                .filter { method -> "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}" in codeKeys }\n                .sortedByDescending { method -> packagePrefix != null && method.declaringClass.startsWith(packagePrefix) }\n                .firstOrNull()\n            if (caller != null) {\n                return PatchTarget(\n                    findingId = finding.id, dexEntry = caller.dexEntry, classDescriptor = caller.declaringClass,\n                    methodName = caller.name, prototype = caller.prototype, nativeEntry = nativeEntry,\n                    evidenceLocation = evidence.firstOrNull()?.location,\n                    evidenceValue = "External callee: $targetClass->$targetName$targetPrototype",\n                )\n            }\n        }''',
)
replace_once(
    patch_engine,
    '''        val method = report.dex?.methods?.firstOrNull { candidate ->\n            joined.contains(candidate.declaringClass, ignoreCase = false) &&\n                joined.contains(candidate.name, ignoreCase = false) &&\n                joined.contains(candidate.prototype, ignoreCase = false)\n        }''',
    '''        val fallbackCodeKeys = report.dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()\n        val method = report.dex?.methods?.firstOrNull { candidate ->\n            joined.contains(candidate.declaringClass, ignoreCase = false) &&\n                joined.contains(candidate.name, ignoreCase = false) &&\n                joined.contains(candidate.prototype, ignoreCase = false) &&\n                "${candidate.dexEntry}|${candidate.declaringClass}|${candidate.name}|${candidate.prototype}" in fallbackCodeKeys\n        }''',
)

# Strengthen the existing regression test with the exact failure mode observed on-device.
test = 'app/src/test/java/org/unirevlab/security/analysis/TamperAssessmentEngineTest.kt'
replace_once(
    test,
    '''                methods = listOf(DexMethodReference("classes.dex", 1, "Lorg/example/Access;", "hasPremium", "()Z")),\n                codeMethods = listOf(DexMethodCodeReference("classes.dex", 1, "Lorg/example/Access;", "hasPremium", "()Z", 1L, 2, 0, 0, 0, 1)),''',
    '''                methods = listOf(\n                    DexMethodReference("classes.dex", 1, "Lorg/example/Access;", "hasPremium", "()Z"),\n                    DexMethodReference("classes.dex", 2, "Landroid/media/MediaDrm;", "getOfflineLicenseKeySetIds", "()Ljava/util/List;"),\n                    DexMethodReference("classes.dex", 3, "Landroid/support/customtabs/ICustomTabsService$Default;", "isEngagementSignalsApiAvailable", "()Z"),\n                ),\n                codeMethods = listOf(\n                    DexMethodCodeReference("classes.dex", 1, "Lorg/example/Access;", "hasPremium", "()Z", 1L, 2, 0, 0, 0, 1),\n                    DexMethodCodeReference("classes.dex", 3, "Landroid/support/customtabs/ICustomTabsService$Default;", "isEngagementSignalsApiAvailable", "()Z", 2L, 2, 0, 0, 0, 1),\n                ),''',
)
replace_once(
    test,
    '''        assertTrue(assessment.hookProposals.any { it.methodName == "hasPremium" })\n        assertTrue(assessment.secrets.isNotEmpty())''',
    '''        assertTrue(assessment.hookProposals.any { it.methodName == "hasPremium" })\n        assertTrue(assessment.hits.none { it.classDescriptor?.startsWith("Landroid/") == true })\n        assertTrue(assessment.hookProposals.none { it.classDescriptor.startsWith("Landroid/") })\n        assertTrue(assessment.secrets.isNotEmpty())''',
)

print('v0.25.1 target-quality fix applied')
