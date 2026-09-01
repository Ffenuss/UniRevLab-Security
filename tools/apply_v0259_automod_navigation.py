from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        if new in text:
            return
        raise SystemExit(f'{label}: neither source anchor nor applied result found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

path = 'app/src/main/java/org/unirevlab/security/analysis/AutoModEngine.kt'
replace_once(path,
'''        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        val codeKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
''',
'''        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val dex = report.dex
        val methodsByKey = dex?.methods.orEmpty().associateBy { it.dexEntry to it.methodIndex }
        val methodsBySignature = dex?.methods.orEmpty().associateBy { method ->
            "${method.dexEntry}|${method.declaringClass}|${method.name}|${method.prototype}"
        }
        val codeKeys = dex?.codeMethods.orEmpty().map { "${it.dexEntry}|${it.declaringClass}|${it.name}|${it.prototype}" }.toSet()
''', 'automod maps')

replace_once(path,
'''        dex?.methods.orEmpty().forEach { method ->
            collect(method, "${method.declaringClass}->${method.name}${method.prototype}")
        }
''',
'''        // Highest-signal source: exact surfaces already resolved by Tamper Assessment.
        assessment.hits.forEach { hit ->
            val dexEntry = hit.dexEntry ?: return@forEach
            val classDescriptor = hit.classDescriptor ?: return@forEach
            val methodName = hit.methodName ?: return@forEach
            val prototype = hit.prototype ?: return@forEach
            val method = methodsBySignature["$dexEntry|$classDescriptor|$methodName|$prototype"] ?: return@forEach
            if (!editableProject(method)) return@forEach
            evidence += Evidence(
                category = hit.category,
                method = method,
                score = hit.score.coerceIn(1, 100),
                text = "${hit.preview} ${hit.location} ${method.declaringClass} ${method.name}",
            )
        }

        // Then scan the complete editable project method index. This keeps obfuscated app code eligible
        // even when package ownership cannot be inferred from a conventional Java/Kotlin namespace.
        dex?.methods.orEmpty().forEach { method ->
            collect(method, "${method.declaringClass}->${method.name}${method.prototype}")
        }
''', 'tamper hits first')

replace_once(path,
'''        val evidenceBacked = evidenceTokens.isNotEmpty() && baseScore >= 46
''',
'''        val evidenceBacked = evidenceTokens.isNotEmpty() && baseScore >= 42
''', 'evidence threshold')

replace_once(path,
'''    data class Plan(
        val artifactSha256: String,
        val assessmentScore: Int,
        val assessmentBand: String,
        val actions: List<Action>,
        val eligibleBeforeCap: Int,
    )
''',
'''    data class Plan(
        val artifactSha256: String,
        val assessmentScore: Int,
        val assessmentBand: String,
        val actions: List<Action>,
        val eligibleBeforeCap: Int,
        val diagnostics: String = "",
    )
''', 'plan diagnostics model')

replace_once(path,
'''        return Plan(
            artifactSha256 = workspace.artifactSha256,
            assessmentScore = assessment.score,
            assessmentBand = assessment.band,
            actions = selected,
            eligibleBeforeCap = candidates.size,
        )
''',
'''        val editableMethodCount = dex?.methods.orEmpty().count(::editableProject)
        val exactTamperMethodHits = assessment.hits.count {
            it.dexEntry != null && it.classDescriptor != null && it.methodName != null && it.prototype != null
        }
        val diagnostics = when {
            candidates.isNotEmpty() -> "editable methods: $editableMethodCount; exact tamper method hits: $exactTamperMethodHits; eligible: ${candidates.size}"
            editableMethodCount == 0 -> "Нет редактируемых DEX method bodies: возможно логика находится в native/IL2CPP/managed runtime."
            exactTamperMethodHits == 0 -> "Tamper Assessment не связал поверхности с точными DEX method bodies; используйте scoped search/Runtime State Lab."
            else -> "Найдены редактируемые методы и tamper hits, но сигнатуры return/type не подходят для безопасного AutoMod-шаблона."
        }
        return Plan(
            artifactSha256 = workspace.artifactSha256,
            assessmentScore = assessment.score,
            assessmentBand = assessment.band,
            actions = selected,
            eligibleBeforeCap = candidates.size,
            diagnostics = diagnostics,
        )
''', 'diagnostics result')

path = 'app/src/main/java/org/unirevlab/security/ui/AutoModPanel.kt'
replace_once(path,
'''                if (current.actions.isEmpty()) {
                    Text(
                        "Автоматически патчабельных DEX-целей не найдено. AutoMod проверил project-owned методы, " +
                            "string/field/constant evidence и поддерживаемые boolean/int return-типы. " +
                            "Если состояние хранится во время выполнения, используйте Runtime State Lab; если цель native/IL2CPP — соответствующий native/managed режим.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else {
''',
'''                if (current.actions.isEmpty()) {
                    Text(
                        "AutoMod не выбрал автоматическую цель. ${current.diagnostics}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else {
                    if (current.diagnostics.isNotBlank()) {
                        Text(current.diagnostics, style = MaterialTheme.typography.bodySmall)
                    }
''', 'automod diagnostics ui')

path = 'app/build.gradle.kts'
replace_once(path, 'versionCode = 37', 'versionCode = 38', 'version code')
replace_once(path, 'versionName = "0.25.8-dev-apkset-sources"', 'versionName = "0.25.9-dev-automod-navigation"', 'version name')

path = 'app/src/test/java/org/unirevlab/security/analysis/AutoModEngineTest.kt'
replace_once(path,
'''    @Test
    fun choosesBoundedLocalStateIntegerDemo() {
''',
'''    @Test
    fun lowerBoundExactEvidenceStillSupportsObfuscatedTargets() {
        assertEquals(
            AutoModEngine.Mode.RETURN_TRUE,
            AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "a", "()Z", 42, "premium access entitlement")?.mode,
        )
        assertEquals(
            AutoModEngine.Mode.RETURN_INT,
            AutoModEngine.suggestForTesting("LOCAL_STATE", "b", "()I", 42, "player score")?.mode,
        )
    }

    @Test
    fun choosesBoundedLocalStateIntegerDemo() {
''', 'automod regression')

print('v0.25.9 AutoMod target-resolution patch applied')
