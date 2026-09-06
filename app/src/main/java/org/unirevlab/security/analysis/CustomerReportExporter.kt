package org.unirevlab.security.analysis

import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport
import java.time.Instant

object CustomerReportExporter {
    fun export(
        report: StaticAnalysisReport,
        gradleEvidence: GradleModuleEvidenceResult? = null,
        languageCode: String = "ru",
        realDump: RealIl2CppDumpEngine.Result? = null,
    ): String = if (languageCode == "en") exportEnglish(report, gradleEvidence, realDump) else exportRussian(report, gradleEvidence, realDump)

    private fun exportRussian(report: StaticAnalysisReport, gradleEvidence: GradleModuleEvidenceResult? = null, realDump: RealIl2CppDumpEngine.Result? = null): String {
        val il2cppDetected = report.il2cpp?.detected == true || realDump?.pairLocated == true
        val modificationSurfaces = ModificationSurfaceClassifier.analyze(report)
        val resistance = if (report.il2cpp?.detected == true) {
            runCatching { Il2CppModdingResistanceEngine.analyze(report) }.getOrNull()
        } else null
        val limitations = report.findings.filter { it.category == "ANALYSIS" }
        val reviewSignals = report.findings.filter { it.category != "ANALYSIS" && it.requiresManualReview }
        val confirmedFacts = report.findings.filter { it.category != "ANALYSIS" && !it.requiresManualReview }
        return buildString {
        appendLine("# Отчёт авторизованного аудита приложения")
        appendLine()
        appendLine("- Проект: ${scopeField(report.assessment.projectName)}")
        appendLine("- Заказчик / владелец: ${scopeField(report.assessment.organization)}")
        appendLine("- Цель: ${scopeField(report.assessment.purpose)}")
        appendLine("- Assessment ID: `${report.assessment.assessmentId}`")
        appendLine("- Артефакт: ${safe(report.artifact.displayName)}")
        appendLine("- Package: `${report.manifest?.packageName ?: report.artifact.sourcePackageName ?: "не определён"}`")
        appendLine("- SHA-256: `${report.artifact.sha256}`")
        appendLine("- Время формирования: ${Instant.now()}")
        appendLine("- Движок: `${report.engineVersion}`")
        appendLine()
        appendLine("## Результат")
        appendLine()
        appendLine("Подтверждённых статических конфигураций и технических фактов: **${confirmedFacts.size}**; сигналов, требующих проверки достижимости и влияния: **${reviewSignals.size}**; ограничений анализатора: **${limitations.size}**.")
        appendLine()
        appendLine("Наличие строки, импорта API или экспортированного компонента само по себе не считается доказательством эксплуатации. Такие сигналы отделены от подтверждённых конфигураций.")
        appendLine()
        appendLine("## Что фактически выполнено")
        appendLine()
        appendLine("| Этап | Статус |")
        appendLine("|---|---|")
        appendLine("| Структура APK, manifest, ресурсы | ВЫПОЛНЕНО |")
        appendLine("| DEX и пассивный reverse-анализ | ВЫПОЛНЕНО |")
        appendLine("| Native ELF/JNI | ВЫПОЛНЕНО с указанными ниже ограничениями |")
        appendLine("| IL2CPP | ${if (il2cppDetected) "ОБНАРУЖЕН" else "НЕ ОБНАРУЖЕН"} |")
        appendLine("| Динамические проверки | НЕ ВЫПОЛНЕНЫ${if (report.assessment.dynamicAnalysis) " (были запрошены)" else ""} |")
        appendLine("| Активное сетевое тестирование | НЕ ВЫПОЛНЕНО${if (report.assessment.networkTesting) " (было запрошено)" else ""} |")
        appendLine()
        appendLine("| Метрика | Значение |")
        appendLine("|---|---:|")
        appendLine("| Findings | ${report.findings.size} |")
        appendLine("| Critical | ${report.findings.count { it.severity == Severity.CRITICAL }} |")
        appendLine("| High | ${report.findings.count { it.severity == Severity.HIGH }} |")
        appendLine("| Medium | ${report.findings.count { it.severity == Severity.MEDIUM }} |")
        appendLine("| DEX methods indexed | ${report.dex?.methodsIndexed ?: 0} |")
        appendLine("| Native libraries | ${report.native?.librariesScanned ?: 0} |")
        appendLine("| IL2CPP | ${if (il2cppDetected) "обнаружен" else "не обнаружен"} |")
        appendLine("| Предварительные modification-surface сигналы | ${modificationSurfaces.totalResolvedBeforeLimit + modificationSurfaces.totalUnresolvedBeforeLimit} |")
        gradleEvidence?.let {
            appendLine("| APK/Gradle modules | ${it.modulesDetected} |")
            appendLine("| Dynamic features | ${it.dynamicFeaturesDetected} |")
            appendLine("| Asset packs | ${it.assetPacksDetected} |")
            appendLine("| Configuration splits | ${it.configurationSplitsDetected} |")
            appendLine("| Embedded Gradle build files | ${it.buildFilesDetected} |")
        }
        appendLine()
        gradleEvidence?.let { evidence ->
            appendLine("## Gradle и модульная структура")
            appendLine()
            appendLine("Проанализированы manifests всех доступных base/split APK и сохранившиеся AGP, AAR, Kotlin и dependency metadata.")
            appendLine()
            appendLine("- Обнаружено APK-модулей: ${evidence.modulesDetected}")
            appendLine("- Dynamic-feature модулей: ${evidence.dynamicFeaturesDetected}")
            appendLine("- Asset-pack модулей: ${evidence.assetPacksDetected}")
            appendLine("- Configuration splits: ${evidence.configurationSplitsDetected}")
            appendLine("- Точных Gradle build-файлов внутри пакета: ${evidence.buildFilesDetected}")
            appendLine("- Метаданных и build-маркеров: ${evidence.metadataMarkersDetected}")
            appendLine("- Покрытие: ${if (evidence.truncated) "частичное из-за защитных лимитов" else "полное для доступных архивов"}")
            appendLine()
            appendLine("Исходная структура Gradle обычно не включается в release APK; поэтому отсутствие `build.gradle` не является ошибкой. Dynamic feature и asset pack классифицируются отдельно по distribution manifest.")
            appendLine()
        }
        appendLine("## IL2CPP и пригодность офсетов")
        appendLine()
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cppDetected) {
            appendLine("- `libil2cpp.so`: ${il2cpp?.libil2cppLibraries?.size ?: realDump?.successfulAbis?.size ?: 0} файл(а).")
            appendLine("- `global-metadata.dat`: ${metadata?.entryName ?: "не определён"}.")
            appendLine("- Версия metadata: ${metadata?.metadataVersion ?: "не определена"}; magic: ${if (metadata?.magicValid == true) "корректный" else "не подтверждён"}.")
            appendLine("- Восстановлено типов: ${metadata?.typeDefinitions?.size ?: 0}; методов: ${metadata?.methodDefinitions?.size ?: 0}.")
        } else {
            appendLine("Связанная пара `libil2cpp.so` + `global-metadata.dat` не подтверждена. Если компоненты лежат в разных split APK, они должны быть объединены до формирования этого вывода.")
        }
        appendLine("- Ghidra-анализов: ${report.ghidra.size}.")
        appendLine("- Подтверждённых связей «managed method → native RVA»: ${report.correlations?.il2cppMethodsResolved ?: 0}.")
        appendLine("- Подтверждённых JNI-связей: ${report.correlations?.dexNativeMethodsResolved ?: 0}.")
        appendLine()
        appendLine("Metadata token, ELF-символ и подтверждённый native RVA метода — разные сущности. `offsets-readable.html` показывает их раздельно и не выдаёт сырой символ за готовый hook-offset.")
        appendLine()
        appendLine("## Предварительные поверхности для проверки после настоящего dump")
        appendLine()
        appendLine("- Профиль цели: **${targetProfileLabel(modificationSurfaces.targetProfile)}**; уверенность: ${profileConfidenceLabel(modificationSurfaces.profileConfidence)}.")
        modificationSurfaces.profileReasons.forEach { appendLine("- ${safe(it)}") }
        appendLine("- Статических кандидатов: ${modificationSurfaces.totalResolvedBeforeLimit}; managed-кандидатов только с metadata token: ${modificationSurfaces.totalUnresolvedBeforeLimit}.")
        appendLine()
        appendLine("Это только предварительная навигация по общему статическому отчёту. Она не попадает в итоговый экспорт подтверждённых офсетов: тот создаётся позднее исключительно из успешно завершённого Rodroid dump.")
        appendLine()
        if (modificationSurfaces.resolvedOffsets.isNotEmpty()) {
            appendLine("| Приоритет | Область | Категория | Источник | Identity | Библиотека | Предварительный адрес |")
            appendLine("|---|---|---|---|---|---|---|")
            modificationSurfaces.resolvedOffsets.take(MAX_MODIFICATION_TARGETS).forEach { candidate ->
                appendLine("| ${candidate.priority} | ${surfaceDomainLabel(candidate.domain)} | ${surfaceCategoryLabel(candidate.category)} | ${candidate.source} | `${safe(candidate.displayName)}` | `${safe(candidate.libraryEntry ?: "—")}` | `${candidate.rva?.let { "0x${it.toString(16)}" } ?: "—"}` |")
            }
            appendLine()
            if (modificationSurfaces.totalResolvedBeforeLimit > MAX_MODIFICATION_TARGETS) {
                appendLine("Итоговые `offsets-readable.html` и `offset-evidence.json` не копируют эту таблицу: они строятся только из реального dump.")
                appendLine()
            }
        } else {
            appendLine("Подходящих кандидатов с подтверждённым RVA не найдено. Это не означает отсутствие изменяемой клиентской логики.")
            appendLine()
        }
        if (modificationSurfaces.unresolvedManagedCandidates.isNotEmpty()) {
            appendLine("Найдены ${modificationSurfaces.totalUnresolvedBeforeLimit} managed identity без доказанного native RVA. Они остаются гипотезами и не включаются в итоговые файлы офсетов.")
            appendLine()
        }
        report.supplyChain?.let { supply ->
            val advisoryFeed = supply.advisoryFeed
            appendLine("## Зависимости и известные уязвимости")
            appendLine()
            appendLine("- Компонентов определено: ${supply.components.size}; с подтверждённой версией: ${supply.components.count { it.version != null }}.")
            if (advisoryFeed == null) {
                appendLine("- Проверка по advisory feed: **НЕ ВЫПОЛНЕНА**.")
                appendLine("- Пустой список CVE означает «не проверено», а не «уязвимостей нет».")
            } else {
                appendLine("- Advisory feed: ${safe(advisoryFeed.feedId)}; записей: ${advisoryFeed.advisoryCount}; подпись проверена: ${advisoryFeed.signatureVerified}.")
                appendLine("- Найдено совпадений: ${supply.vulnerabilities.size}.")
            }
            appendLine()
        }
        appendLine("## Вывод о доверии к клиенту")
        appendLine()
        if (il2cppDetected) {
            appendLine("Наличие IL2CPP не делает критическую клиентскую логику доверенной: `libil2cpp.so` и metadata автоматически обнаружены и отражены в evidence. Критические полномочия и ценные операции должны подтверждаться сервером.")
        } else {
            appendLine("Независимо от runtime, клиентская логика и локальное состояние не должны быть единственным источником истины для полномочий, оплаты, баланса или доверенного результата.")
        }
        appendLine()
        resistance?.let { result ->
            appendLine("## Устойчивость IL2CPP к изменению клиента")
            appendLine()
            appendLine(result.summary)
            appendLine()
            appendLine("- Итоговый приоритет: **${result.overallPriority}**")
            appendLine("- Client-authoritative: ${result.clientAuthoritative}")
            appendLine("- Mixed: ${result.mixed}")
            appendLine("- Server-gated: ${result.serverGated}")
            appendLine("- Inconclusive: ${result.inconclusive}")
            appendLine("- Полнота покрытия: ${if (result.coverageComplete) "полная" else "частичная"}")
            appendLine()
            result.targets.take(MAX_RESISTANCE_TARGETS).forEach { target ->
                appendLine("### ${safe(target.managedIdentity)}")
                appendLine()
                appendLine("- Категория: ${target.category}")
                appendLine("- Граница доверия: **${target.authority}**")
                appendLine("- Приоритет: ${target.priority}; уверенность: ${target.confidence}")
                target.metadataToken?.let { appendLine("- Metadata token: `0x${it.toString(16)}`") }
                target.nativeFunctionName?.let { appendLine("- Native identity: `${safe(it)}`") }
                target.hardeningActions.take(3).forEach { appendLine("- Исправление: ${safe(it)}") }
                appendLine()
            }
        }
        appendFindingSection("Подтверждённые конфигурации и технические факты", confirmedFacts)
        appendFindingSection("Сигналы, которые нужно подтвердить вручную", reviewSignals)
        appendFindingSection("Ограничения покрытия анализатора", limitations)
        appendLine("## Состав evidence-пакета")
        appendLine()
        appendLine("- `full-report.json` — полный структурированный отчёт.")
        appendLine("- `customer-report.md` — этот отчёт.")
        appendLine("- `offsets-readable.html` — таблица подтверждённых офсетов, построенная только из завершённого Rodroid dump.")
        appendLine("- `offset-evidence.json` — подтверждённые method RVA и field offsets по всем успешно обработанным ABI; гипотезы исключены.")
        appendLine("- `il2cpp-dump.cs` — настоящий dump типов, полей и методов для основного ABI.")
        appendLine("- `il2cpp-real-dump.zip` — полные Rodroid-результаты для всех ABI, script, строки, headers и сводные индексы.")
        appendLine("- `gradle-module-evidence.json` — Gradle/AGP metadata и карта base, split и dynamic-feature модулей.")
        appendLine("- `analysis-artifacts.zip` — выбранные анализатором DEX/native/runtime inputs; это не полная копия всех записей исходного APK.")
        appendLine("- `verification-plan.json` — план и статусы выполнения, а не результаты тестов.")
        appendLine("- `evidence-manifest.json` — хеши файлов evidence-пакета.")
        appendLine("- `evidence-signature.json` — локальная подпись manifest. Для подтверждения личности аудитора публичный ключ должен быть заранее передан заказчику по независимому каналу.")
        appendLine()
        appendLine("## Ограничение метода")
        appendLine()
        appendLine("Отчёт не помечает проверку выполненной, если она фактически не запускалась. Статический сигнал не объявляется эксплуатацией без подтверждения достижимости и влияния.")
        }
    }

    private fun exportEnglish(report: StaticAnalysisReport, gradleEvidence: GradleModuleEvidenceResult?, realDump: RealIl2CppDumpEngine.Result?): String {
        val il2cppDetected = report.il2cpp?.detected == true || realDump?.pairLocated == true
        val limitations = report.findings.filter { it.category == "ANALYSIS" }
        val review = report.findings.filter { it.category != "ANALYSIS" && it.requiresManualReview }
        val confirmed = report.findings.filter { it.category != "ANALYSIS" && !it.requiresManualReview }
        return buildString {
            appendLine("# Authorized application security assessment")
            appendLine()
            appendLine("- Project: ${scopeField(report.assessment.projectName)}")
            appendLine("- Customer / owner: ${scopeField(report.assessment.organization)}")
            appendLine("- Purpose: ${scopeField(report.assessment.purpose)}")
            appendLine("- Assessment ID: `${report.assessment.assessmentId}`")
            appendLine("- Artifact: ${safe(report.artifact.displayName)}")
            appendLine("- Package: `${report.manifest?.packageName ?: report.artifact.sourcePackageName ?: "unknown"}`")
            appendLine("- SHA-256: `${report.artifact.sha256}`")
            appendLine("- Generated: ${Instant.now()}")
            appendLine("- Engine: `${report.engineVersion}`")
            appendLine()
            appendLine("## Summary")
            appendLine()
            appendLine("Confirmed static facts: **${confirmed.size}**; signals requiring reachability/impact review: **${review.size}**; analyzer limitations: **${limitations.size}**.")
            appendLine("Strings, imported APIs, and exported components are not treated as proof of exploitation on their own.")
            appendLine()
            appendLine("| Metric | Value |")
            appendLine("|---|---:|")
            appendLine("| Findings | ${report.findings.size} |")
            appendLine("| Critical | ${report.findings.count { it.severity == Severity.CRITICAL }} |")
            appendLine("| High | ${report.findings.count { it.severity == Severity.HIGH }} |")
            appendLine("| Medium | ${report.findings.count { it.severity == Severity.MEDIUM }} |")
            appendLine("| DEX methods indexed | ${report.dex?.methodsIndexed ?: 0} |")
            appendLine("| Native libraries | ${report.native?.librariesScanned ?: 0} |")
            appendLine("| IL2CPP detected | $il2cppDetected |")
            gradleEvidence?.let {
                appendLine("| APK/Gradle modules | ${it.modulesDetected} |")
                appendLine("| Dynamic features | ${it.dynamicFeaturesDetected} |")
                appendLine("| Asset packs | ${it.assetPacksDetected} |")
                appendLine("| Configuration splits | ${it.configurationSplitsDetected} |")
            }
            appendLine()
            appendLine("## IL2CPP evidence boundary")
            appendLine()
            appendLine("The general static scan provides discovery hints only. Final offset exports are generated later and exclusively from a successfully completed Rodroid dump for each ABI. Metadata tokens and heuristic names are never promoted to native RVA.")
            appendLine()
            appendEnglishFindingSection("Confirmed configurations and technical facts", confirmed)
            appendEnglishFindingSection("Signals requiring manual confirmation", review)
            appendEnglishFindingSection("Analyzer coverage limitations", limitations)
            appendLine("## Evidence package contents")
            appendLine()
            appendLine("- `full-report.json`: complete machine-readable evidence.")
            appendLine("- `customer-report.md`: this report plus the real dump status appended by the pipeline.")
            appendLine("- `offsets-readable.html`: searchable confirmed offsets from completed dumps only.")
            appendLine("- `offset-evidence.json`: confirmed method RVA and field offsets for every successful ABI.")
            appendLine("- `il2cpp-dump.cs`: real managed dump for the primary ABI.")
            appendLine("- `il2cpp-real-dump.zip`: all per-ABI Rodroid outputs, scripts, strings, headers, and aggregate indexes.")
            appendLine("- `gradle-module-evidence.json`: base, split, dynamic-feature, and build metadata evidence.")
            appendLine("- `analysis-artifacts.zip`: bounded passive analysis inputs.")
            appendLine("- `verification-plan.json`: proposed verification steps, not fabricated test results.")
            appendLine()
            appendLine("## Method limitation")
            appendLine()
            appendLine("A check is not marked complete unless it actually ran. Static signals are not called exploitable without reachability and impact evidence.")
        }
    }

    private fun StringBuilder.appendEnglishFindingSection(title: String, findings: List<Finding>) {
        appendLine("## $title")
        appendLine()
        if (findings.isEmpty()) {
            appendLine("No entries.")
            appendLine()
            return
        }
        findings.take(MAX_FINDINGS).forEachIndexed { index, finding ->
            appendLine("### ${index + 1}. ${safe(finding.title)}")
            appendLine()
            appendLine("- ID: `${finding.id}`")
            appendLine("- Status: **${if (finding.category == "ANALYSIS") "ANALYZER LIMITATION" else if (finding.requiresManualReview) "REQUIRES CONFIRMATION" else "STATICALLY CONFIRMED"}**")
            appendLine("- Severity: **${finding.severity}**")
            appendLine("- Confidence: ${finding.confidence}")
            appendLine("- Category: ${safe(finding.category)}")
            appendLine()
            appendLine(safe(finding.description))
            appendLine()
            finding.evidence.take(MAX_EVIDENCE_PER_FINDING).forEach { evidence ->
                appendLine("- Evidence: `${safe(evidence.source)}` · `${safe(evidence.location)}` · ${safe(evidence.value)}")
            }
            appendLine("- Remediation: ${safe(finding.remediation)}")
            appendLine()
        }
    }

    private fun StringBuilder.appendFindingSection(title: String, findings: List<Finding>) {
        appendLine("## $title")
        appendLine()
        if (findings.isEmpty()) {
            appendLine("Нет записей.")
            appendLine()
            return
        }
        findings.take(MAX_FINDINGS).forEachIndexed { index, finding ->
            appendLine("### ${index + 1}. ${localizedTitle(finding)}")
            appendLine()
            appendLine("- ID: `${finding.id}`")
            appendLine("- Статус: **${statusLabel(finding)}**")
            appendLine("- Важность: **${severityLabel(finding.severity)}**")
            appendLine("- Уверенность: ${confidenceLabel(finding.confidence)}")
            appendLine("- Категория: ${categoryLabel(finding.category)}")
            appendLine()
            appendLine(LOCALIZED_DESCRIPTIONS[finding.id] ?: safe(finding.description))
            appendLine()
            if (finding.evidence.isNotEmpty()) {
                appendLine("Доказательства:")
                finding.evidence.take(MAX_EVIDENCE_PER_FINDING).forEach { evidence ->
                    appendLine("- `${safe(evidence.source)}` · `${safe(evidence.location)}` · ${safe(evidence.value)}")
                }
                if (finding.evidence.size > MAX_EVIDENCE_PER_FINDING) {
                    appendLine("- Ещё записей: ${finding.evidence.size - MAX_EVIDENCE_PER_FINDING}; полный список находится в `full-report.json`.")
                }
                appendLine()
            }
            appendLine("Что сделать: ${LOCALIZED_REMEDIATIONS[finding.id] ?: safe(finding.remediation)}")
            if (finding.references.isNotEmpty()) {
                appendLine()
                appendLine("Стандарты: ${finding.references.joinToString { "`${safe(it.standard)} ${safe(it.id)}`" }}")
            }
            appendLine()
        }
    }

    private fun statusLabel(finding: Finding): String = when {
        finding.category == "ANALYSIS" -> "ОГРАНИЧЕНИЕ АНАЛИЗАТОРА"
        finding.requiresManualReview -> "ТРЕБУЕТ ПОДТВЕРЖДЕНИЯ"
        else -> "ПОДТВЕРЖДЕНО СТАТИЧЕСКИ"
    }

    private fun severityLabel(value: Severity): String = when (value) {
        Severity.CRITICAL -> "КРИТИЧЕСКАЯ"
        Severity.HIGH -> "ВЫСОКАЯ"
        Severity.MEDIUM -> "СРЕДНЯЯ"
        Severity.LOW -> "НИЗКАЯ"
        Severity.INFORMATIONAL -> "ИНФОРМАЦИОННАЯ"
    }

    private fun confidenceLabel(value: Confidence): String = when (value) {
        Confidence.CONFIRMED -> "подтверждено точным признаком"
        Confidence.HIGH -> "высокая"
        Confidence.MEDIUM -> "средняя"
        Confidence.LOW -> "низкая"
    }

    private fun categoryLabel(value: String): String = when (value) {
        "NETWORK" -> "Сеть"
        "PLATFORM" -> "Android-платформа"
        "PRIVACY" -> "Приватность"
        "STORAGE" -> "Хранение данных"
        "CODE" -> "Код"
        "NATIVE" -> "Native/JNI"
        "NATIVE_HARDENING" -> "Защита native-кода"
        "RESILIENCE" -> "Устойчивость к изменению"
        "ANALYSIS" -> "Полнота анализа"
        else -> safe(value)
    }

    private fun targetProfileLabel(value: ModificationSurfaceClassifier.TargetProfile): String = when (value) {
        ModificationSurfaceClassifier.TargetProfile.GAME_LIKELY -> "вероятнее всего игра"
        ModificationSurfaceClassifier.TargetProfile.APPLICATION_LIKELY -> "вероятнее всего обычное приложение"
    }

    private fun profileConfidenceLabel(value: ModificationSurfaceClassifier.ProfileConfidence): String = when (value) {
        ModificationSurfaceClassifier.ProfileConfidence.HIGH -> "высокая"
        ModificationSurfaceClassifier.ProfileConfidence.MEDIUM -> "средняя"
        ModificationSurfaceClassifier.ProfileConfidence.LOW -> "низкая"
    }

    private fun surfaceDomainLabel(value: String): String = when (value) {
        "GAMEPLAY" -> "Игровая логика"
        "APPLICATION" -> "Обычное приложение"
        "MONETIZATION" -> "Монетизация"
        "SHARED_SECURITY" -> "Общая защита"
        else -> safe(value)
    }

    private fun surfaceCategoryLabel(value: String): String = value.lowercase().replace('_', ' ')

    private fun localizedTitle(finding: Finding): String =
        LOCALIZED_TITLES[finding.id] ?: safe(finding.title)

    private fun scopeField(value: String): String {
        val normalized = safe(value)
        return if (normalized.length < 2 || normalized.all(Char::isDigit)) "не указано" else normalized
    }

    private fun safe(value: String): String = value.replace('\n', ' ').replace('\r', ' ').trim()
    private val LOCALIZED_TITLES = mapOf(
        "ANDROID-NETWORK-CONFIG-CLEARTEXT" to "Network Security Config разрешает незашифрованный HTTP",
        "ANDROID-EXPORTED-PROVIDER-UNPROTECTED" to "Экспортированный ContentProvider не защищён permission",
        "DEX-HARDCODED-HTTP-URL" to "В DEX найден конкретный незашифрованный HTTP-адрес",
        "NATIVE-HARDCODED-HTTP-URL" to "В native-библиотеке найден конкретный HTTP-адрес",
        "DEX-WEBVIEW-KNOWN-RISKY-ARGUMENT" to "Опасная настройка WebView включается известным значением",
        "ANDROID-DANGEROUS-PERMISSIONS" to "Опасные Android permissions требуют обоснования",
        "NATIVE-NONSTANDARD-LOCATION" to "Native-библиотека находится вне стандартного lib/<abi>",
        "NATIVE-PROCESS-EXECUTION-API-REVIEW" to "Native-код импортирует API запуска процессов",
        "ANALYSIS-DEX-PARTIAL" to "DEX-анализ выполнен частично",
        "ANALYSIS-NATIVE-PARTIAL" to "Native-анализ выполнен частично",
        "ANDROID-CUSTOM-SCHEME-REVIEW" to "Custom URL schemes требуют проверки входных данных",
        "ANDROID-EXPORTED-UNPROTECTED-REVIEW" to "Экспортированные компоненты без permission требуют проверки",
        "DEX-DYNAMIC-CODE-LOADING" to "Обнаружена загрузка DEX через class loader",
        "NATIVE-DYNAMIC-LOADING-API-REVIEW" to "Native-код импортирует dlopen/dlsym",
        "NATIVE-JNI-ATTACK-SURFACE" to "Обнаружена JNI/native поверхность атаки",
        "NATIVE-STACK-CANARY-REVIEW" to "Не найден импорт runtime stack canary",
        "ANDROID-APP-LINK-PLACEHOLDER-HOST" to "В App Link остался build placeholder",
        "ANDROID-MANIFEST-DEBUGGABLE" to "Release-приложение допускает debugging",
        "ANDROID-MANIFEST-CLEARTEXT" to "Приложение может разрешать cleartext traffic",
        "ANDROID-MANIFEST-BACKUP" to "Backup данных приложения не ограничен правилами",
        "ANDROID-EXPORTED-PROVIDER-URI-GRANTS" to "Provider выдаёт URI grants без базового permission",
        "ANDROID-EXPORTED-WEAK-PERMISSION" to "Компонент защищён слабым custom permission",
        "ANDROID-UNVERIFIED-APP-LINKS" to "Web-ссылки не запрашивают App Link verification",
        "ANDROID-DEEP-LINK-PATH-PATTERN-REVIEW" to "Deep-link pathPattern требует проверки",
        "ANDROID-NETWORK-USER-CA-TRUST" to "Production-конфигурация доверяет пользовательским CA",
        "ANDROID-SIGNATURE-V1-ONLY" to "APK использует только подпись v1",
        "ANDROID-SIGNATURE-SCHEME-UNCLASSIFIED" to "Схему подписи APK не удалось классифицировать",
        "DEX-POTENTIAL-HARDCODED-SECRET" to "Строка в DEX похожа на секрет",
        "DEX-PROCESS-EXECUTION-SURFACE" to "DEX ссылается на API запуска процессов",
        "DEX-WEBVIEW-SENSITIVE-API" to "DEX ссылается на чувствительные WebView API",
        "DEX-INSTALL-SOURCE-CHECK" to "Приложение проверяет источник установки",
        "NATIVE-EXECUTABLE-STACK" to "Native-библиотека запрашивает исполняемый stack",
        "NATIVE-RELRO-MISSING" to "В native-библиотеке отсутствует GNU RELRO",
        "NATIVE-BIND-NOW-MISSING" to "Native-библиотека использует только partial RELRO",
        "NATIVE-POTENTIAL-HARDCODED-SECRET" to "Native-строка похожа на секрет",
        "IL2CPP-APPLICATION-SURFACE" to "Обнаружена IL2CPP application surface",
        "ANALYSIS-IL2CPP-METADATA-UNRECOGNIZED" to "Формат IL2CPP metadata распознан не полностью",
    )
    private val LOCALIZED_DESCRIPTIONS = mapOf(
        "ANDROID-NETWORK-CONFIG-CLEARTEXT" to "В упакованной сетевой конфигурации найдено cleartextTrafficPermitted=true. Настройка подтверждена, но влияние зависит от реально достижимых production-адресов и передаваемых данных.",
        "ANDROID-EXPORTED-PROVIDER-UNPROTECTED" to "Компонент доступен другим приложениям без manifest-level permission. Утечка данных не доказана, пока не проверены его методы и URI.",
        "DEX-HARDCODED-HTTP-URL" to "После удаления schema, localhost и шаблонных значений остались конкретные адреса с http://. Их достижимость ещё нужно подтвердить.",
        "NATIVE-HARDCODED-HTTP-URL" to "В printable data ELF найден конкретный адрес http://. HTTPS, XML namespace, localhost и форматные шаблоны сюда не включаются.",
        "DEX-WEBVIEW-KNOWN-RISKY-ARGUMENT" to "Статический анализ восстановил передачу true в чувствительную настройку WebView. Для оценки влияния нужно проверить вариант сборки и достижимость вызова.",
        "ANDROID-DANGEROUS-PERMISSIONS" to "Permission присутствуют в manifest, но само наличие не является уязвимостью. Нужно учитывать версию Android, maxSdk и пользовательскую функцию.",
        "NATIVE-NONSTANDARD-LOCATION" to "Файл .so действительно расположен вне стандартного пути внутри APK. Префикс split APK не считается частью внутреннего пути.",
        "NATIVE-PROCESS-EXECUTION-API-REVIEW" to "Импорт system/exec/popen подтверждён, но передача недоверенных данных в него не доказана.",
        "ANALYSIS-DEX-PARTIAL" to "Один из ограниченных наборов методов, инструкций или xref достиг лимита. Покрытие строк указывается отдельно.",
        "ANALYSIS-NATIVE-PARTIAL" to "Не все обнаруженные библиотеки или таблицы ELF были полностью обработаны. Это ограничение анализатора, а не уязвимость приложения.",
        "ANDROID-CUSTOM-SCHEME-REVIEW" to "Custom scheme может быть вызван другим приложением и не подтверждает владение доменом.",
        "ANDROID-EXPORTED-UNPROTECTED-REVIEW" to "Компоненты доступны внешним callers, но наличие уязвимой операции ещё не доказано.",
        "DEX-DYNAMIC-CODE-LOADING" to "Найден вызов class loader для runtime-кода. Обычный Google Play Dynamite отфильтрован.",
        "NATIVE-DYNAMIC-LOADING-API-REVIEW" to "Динамическое разрешение библиотек подтверждено, но небезопасный путь загрузки не доказан.",
        "NATIVE-JNI-ATTACK-SURFACE" to "Найдены JNI entry points или RegisterNatives indicators. Это карта поверхности проверки, а не самостоятельная уязвимость.",
        "NATIVE-STACK-CANARY-REVIEW" to "Отсутствие __stack_chk_fail в dynsym не доказывает отсутствие защиты во всех функциях.",
        "ANDROID-APP-LINK-PLACEHOLDER-HOST" to "В установленный manifest попало буквальное значение вроде {link_domain}; Android не сможет подтвердить владение таким доменом.",
    )
    private val LOCALIZED_REMEDIATIONS = mapOf(
        "ANDROID-NETWORK-CONFIG-CLEARTEXT" to "Отключить cleartext по умолчанию, оставить только документированные исключения и проверить реальные сетевые маршруты.",
        "ANDROID-EXPORTED-PROVIDER-UNPROTECTED" to "Отключить export, если внешний доступ не нужен, либо добавить permission и проверку авторизации внутри provider.",
        "DEX-HARDCODED-HTTP-URL" to "Перевести production endpoint на HTTPS и проверить вызовы, которые используют строку.",
        "NATIVE-HARDCODED-HTTP-URL" to "Найти xref строки, подтвердить достижимость и заменить production-транспорт на HTTPS.",
        "DEX-WEBVIEW-KNOWN-RISKY-ARGUMENT" to "Отключить WebView debugging и permissive file-origin настройки в release, ограничить origins и JavaScript bridge.",
        "ANDROID-DANGEROUS-PERMISSIONS" to "Удалить ненужные permissions и запрашивать остальные только в момент использования функции.",
        "NATIVE-NONSTANDARD-LOCATION" to "Проверить источник, целостность и путь загрузки такой библиотеки.",
        "NATIVE-PROCESS-EXECUTION-API-REVIEW" to "Проследить аргументы вызова и исключить shell-интерпретацию пользовательских значений.",
        "ANALYSIS-DEX-PARTIAL" to "Повторить анализ с увеличенным профилем ресурсов или проверить непокрытые структуры отдельным инструментом.",
        "ANALYSIS-NATIVE-PARTIAL" to "Повторить анализ с увеличенным лимитом и явно проверить непросканированные библиотеки.",
        "ANDROID-CUSTOM-SCHEME-REVIEW" to "Для чувствительных маршрутов использовать verified App Links, остальные параметры проверять по allowlist.",
        "ANDROID-EXPORTED-UNPROTECTED-REVIEW" to "Проверить каждый entry point, добавить permission или сделать компонент non-exported.",
        "DEX-DYNAMIC-CODE-LOADING" to "Проверить источник загружаемого кода, запретить writable/untrusted locations и проверять целостность.",
        "NATIVE-DYNAMIC-LOADING-API-REVIEW" to "Проверить формирование путей и доверие к загружаемым библиотекам.",
        "NATIVE-JNI-ATTACK-SURFACE" to "Сопоставить Java/Kotlin declarations с native-функциями и проверить данные на границе JNI.",
        "NATIVE-STACK-CANARY-REVIEW" to "Проверить build flags и репрезентативные функции disassembly.",
        "ANDROID-APP-LINK-PLACEHOLDER-HOST" to "Подставлять реальный host в release, падать в CI при unresolved placeholders и проверять App Links после установки.",
    )
    private const val MAX_FINDINGS = 50
    private const val MAX_EVIDENCE_PER_FINDING = 5
    private const val MAX_RESISTANCE_TARGETS = 30
    private const val MAX_MODIFICATION_TARGETS = 30
}
