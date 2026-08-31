package org.unirevlab.security.analysis

import java.util.Locale
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * One-tap defensive audit inspired by common real-world Android tampering workflows.
 *
 * It intentionally answers "where is the client trust boundary weak and how should the owner fix it?"
 * rather than generating ad-removal, billing emulation, entitlement bypass or license-bypass patches.
 */
object EasyAuditEngine {
    data class AuditCheck(
        val id: String,
        val title: String,
        val status: String,
        val severity: String,
        val evidence: List<String>,
        val explanation: String,
        val actions: List<String>,
    )

    data class EasyAuditReport(
        val score: Int,
        val band: String,
        val checks: List<AuditCheck>,
        val flagSweep: FlagSweepEngine.SweepReport,
        val traceHooks: List<TamperAssessmentEngine.HookProposal>,
    )

    fun run(
        report: StaticAnalysisReport,
        workspace: PatchLabEngine.Workspace,
        customFlags: List<String> = emptyList(),
    ): EasyAuditReport {
        val assessment = TamperAssessmentEngine.scan(report, workspace)
        val sweep = FlagSweepEngine.scan(workspace, customFlags)
        val assessmentCategories = assessment.categories.map { it.category }.toSet()
        val flagByCategory = sweep.matches.groupBy { it.category }
        val dexLabels = report.dex?.methods.orEmpty().map { "${it.declaringClass}->${it.name}${it.prototype}" }
        val nativeLabels = report.native?.libraries.orEmpty().flatMap { lib ->
            listOf(lib.entryName) + lib.importedSymbols.map { it.name } + lib.exportedSymbols.map { it.name } + lib.jniSymbols
        }
        val dependencyLabels = report.supplyChain?.components.orEmpty().flatMap { component ->
            listOf(component.name, component.id, component.ecosystem, component.version.orEmpty())
        }
        val findingLabels = report.findings.map { finding ->
            "${finding.id} ${finding.title} ${finding.category} ${finding.description} ${finding.remediation}"
        }

        fun sampleFlags(vararg categories: String): List<String> = categories.flatMap { category ->
            flagByCategory[category].orEmpty().take(4).map { match ->
                "${match.term} @ ${match.entryName} (${match.source})"
            }
        }.distinct().take(8)

        fun sampleAssessment(category: String): List<String> = assessment.hits.asSequence()
            .filter { it.category == category }
            .take(4)
            .map { "${it.kind}: ${it.location}" }
            .toList()

        fun containsAny(values: List<String>, needles: List<String>): Boolean {
            if (values.isEmpty()) return false
            val lowered = needles.map { it.lowercase(Locale.ROOT) }
            return values.any { value ->
                val text = value.lowercase(Locale.ROOT)
                lowered.any(text::contains)
            }
        }

        val checks = mutableListOf<AuditCheck>()

        val adSdkObserved = containsAny(
            dexLabels + dependencyLabels + nativeLabels,
            listOf("admob", "google.android.gms.ads", "com/google/android/gms/ads", "interstitial", "rewardedad", "applovin", "ironsource", "unityads"),
        )
        val adFlags = sampleFlags("ADS", "ENTITLEMENT")
        if (adSdkObserved || adFlags.isNotEmpty()) {
            val locallyControlledAdState = adFlags.any { evidence ->
                val lower = evidence.lowercase(Locale.ROOT)
                listOf("no_ads", "noads", "adfree", "ad_free", "remove_ads", "removeads", "showads", "adsenabled").any(lower::contains)
            }
            checks += AuditCheck(
                id = "ADS_TRUST",
                title = "Реклама / ad-free trust boundary",
                status = if (locallyControlledAdState) "EXPOSED_SURFACE" else "REVIEW",
                severity = if (locallyControlledAdState) "HIGH" else "MEDIUM",
                evidence = (adFlags + if (adSdkObserved) listOf("В коде/зависимостях обнаружена рекламная SDK/интеграция") else emptyList()).take(10),
                explanation = "Проверяется не возможность автоматически убрать рекламу, а то, не решает ли клиент сам, кому показывать/не показывать её и связано ли это с локальным premium-флагом.",
                actions = listOf(
                    "Если отсутствие рекламы является платным правом, получать entitlement от сервера после серверной проверки покупки.",
                    "Не использовать единственный локальный boolean adFree/noAds как источник истины для оплаченного доступа.",
                    "Разделить техническую доступность рекламной SDK и бизнес-право пользователя на ad-free режим.",
                ),
            )
        } else {
            checks += noSurface("ADS_TRUST", "Реклама / ad-free trust boundary", "Рекламные SDK и характерные ad-free флаги не найдены в доступном индексе.")
        }

        val billingEvidence = sampleFlags("BILLING", "ENTITLEMENT") + sampleAssessment("ENTITLEMENT_TRUST")
        val billingSdkObserved = containsAny(
            dexLabels + dependencyLabels + findingLabels,
            listOf("billingclient", "com/android/billingclient", "querypurchases", "acknowledgepurchase", "purchase", "entitlement", "subscription"),
        )
        if (billingSdkObserved || billingEvidence.isNotEmpty()) {
            checks += AuditCheck(
                id = "BILLING_ENTITLEMENT",
                title = "Покупки / premium / entitlement",
                status = if ("ENTITLEMENT_TRUST" in assessmentCategories) "EXPOSED_SURFACE" else "REVIEW",
                severity = if ("ENTITLEMENT_TRUST" in assessmentCategories) "HIGH" else "MEDIUM",
                evidence = (billingEvidence + if (billingSdkObserved) listOf("Обнаружены billing/purchase API или связанные зависимости") else emptyList()).distinct().take(12),
                explanation = "Easy Audit проверяет, не доверяет ли приложение локальному результату покупки, premium-флагу или client-side entitlement. Эмуляция покупки не выполняется.",
                actions = listOf(
                    "Проверять purchase token/transaction на backend и связывать entitlement с серверной учётной записью.",
                    "Считать callbacks BillingClient недоверенным клиентским вводом до серверной верификации.",
                    "Выдавать короткоживущий подписанный entitlement и проверять его срок/аудиторию/пользователя.",
                ),
            )
        } else {
            checks += noSurface("BILLING_ENTITLEMENT", "Покупки / premium / entitlement", "Billing/entitlement поверхности не найдены в доступном индексе.")
        }

        val secretEvidence = assessment.secrets.take(8).map { "${it.kind} @ ${it.location}: ${it.redactedPreview}" }
        val apiFlags = sampleFlags("API_TRUST")
        val hasHttp = report.dex?.httpUrls.orEmpty().isNotEmpty()
        val hasHttps = report.dex?.httpsUrls.orEmpty().isNotEmpty()
        if (secretEvidence.isNotEmpty() || apiFlags.isNotEmpty() || hasHttp || hasHttps) {
            checks += AuditCheck(
                id = "API_TRUST",
                title = "API / endpoints / client credentials",
                status = if (secretEvidence.isNotEmpty()) "EXPOSED_SURFACE" else "REVIEW",
                severity = if (secretEvidence.isNotEmpty()) "CRITICAL" else "MEDIUM",
                evidence = (secretEvidence + apiFlags + listOfNotNull(
                    if (hasHttp) "Найдены HTTP URL" else null,
                    if (hasHttps) "Найдены HTTPS URL" else null,
                )).take(12),
                explanation = "Наличие endpoint само по себе не уязвимость. Риск возникает, когда APK содержит общий секрет или backend принимает привилегированное решение только по данным, которые полностью контролирует клиент.",
                actions = listOf(
                    "Не хранить серверные private keys и общие API secrets внутри APK/DEX/.so/assets.",
                    "Авторизацию и критичные бизнес-инварианты проверять на backend, а не доверять параметрам из клиента.",
                    "Ротировать подтверждённые встроенные секреты; per-install credentials хранить через Android Keystore.",
                ),
            )
        } else {
            checks += noSurface("API_TRUST", "API / endpoints / client credentials", "Характерные API/secret поверхности не найдены в доступном индексе.")
        }

        val localStateEvidence = sampleFlags("LOCAL_STATE") + sampleAssessment("LOCAL_STATE")
        if (localStateEvidence.isNotEmpty() || "LOCAL_STATE" in assessmentCategories) {
            checks += AuditCheck(
                id = "LOCAL_STATE",
                title = "Локальные значения: HP / валюта / score / cooldown",
                status = "EXPOSED_SURFACE",
                severity = "HIGH",
                evidence = localStateEvidence.distinct().take(12),
                explanation = "Найдены значения/имена, которые часто становятся целью локального изменения. Это не означает, что значение уже эксплуатируемо, но показывает места для проверки trust boundary.",
                actions = listOf(
                    "Экономику, соревновательные результаты и критичные игровые расчёты подтверждать сервером.",
                    "На backend проверять допустимые диапазоны, скорость изменения и связанные инварианты.",
                    "Для offline-only данных использовать целостность/подпись как defense-in-depth, понимая, что клиент остаётся недоверенной средой.",
                ),
            )
        } else {
            checks += noSurface("LOCAL_STATE", "Локальные значения: HP / валюта / score / cooldown", "Характерные state/economy/gameplay флаги не найдены.")
        }

        val configEvidence = sampleFlags("FEATURE_CONFIG") + sampleAssessment("FEATURE_CONFIG")
        if (configEvidence.isNotEmpty() || "FEATURE_CONFIG" in assessmentCategories) {
            checks += AuditCheck(
                id = "FEATURE_CONFIG",
                title = "Feature flags / local config",
                status = "REVIEW",
                severity = "MEDIUM",
                evidence = configEvidence.distinct().take(12),
                explanation = "Локальные feature/config флаги удобны для продукта, но security-critical право нельзя основывать только на изменяемой конфигурации клиента.",
                actions = listOf(
                    "Security-critical remote config подписывать и проверять подпись/версию/срок действия.",
                    "Не смешивать UX feature flag и право пользователя на платную/привилегированную операцию.",
                    "На backend повторно проверять право на действие независимо от клиентского UI/config.",
                ),
            )
        } else {
            checks += noSurface("FEATURE_CONFIG", "Feature flags / local config", "Характерные feature/config поверхности не найдены.")
        }

        val integrityEvidence = sampleFlags("INTEGRITY") + sampleAssessment("INTEGRITY")
        val hasSigningInfo = report.manifest?.signingCertificates.orEmpty().isNotEmpty() || report.manifest?.signingSchemes.orEmpty().isNotEmpty()
        if (integrityEvidence.isNotEmpty() || hasSigningInfo) {
            checks += AuditCheck(
                id = "REPACKAGING_RESILIENCE",
                title = "Перепаковка / подпись / integrity",
                status = if (integrityEvidence.isNotEmpty()) "REVIEW" else "OBSERVED",
                severity = "MEDIUM",
                evidence = (integrityEvidence + if (hasSigningInfo) listOf("Подпись APK проанализирована; схема: ${report.manifest?.signingSchemes.orEmpty().joinToString().ifBlank { "не указана" }}") else emptyList()).take(12),
                explanation = "Локальная self-check полезна как defense-in-depth, но сама находится в изменяемом клиенте. Более сильная граница появляется, когда backend учитывает app integrity/attestation и серверные инварианты.",
                actions = listOf(
                    "Использовать Play Integrity/attestation как серверный risk signal для чувствительных операций.",
                    "Не делать локальную signature/checksum проверку единственным условием выдачи ценности.",
                    "После hardening повторять этот же Easy Audit и сравнивать результат оригинала и лабораторной сборки.",
                ),
            )
        } else {
            checks += noSurface("REPACKAGING_RESILIENCE", "Перепаковка / подпись / integrity", "Явные integrity/self-check поверхности не найдены; это не доказывает устойчивость к перепаковке.")
        }

        if (secretEvidence.isNotEmpty()) {
            checks += AuditCheck(
                id = "EMBEDDED_SECRETS",
                title = "Встроенные secret/key candidates",
                status = "EXPOSED_SURFACE",
                severity = "CRITICAL",
                evidence = secretEvidence,
                explanation = "Любой общий секрет, доставленный пользователю внутри APK, следует считать потенциально извлекаемым. В интерфейсе показывается только redacted preview и fingerprint.",
                actions = listOf(
                    "Подтвердить candidate вручную и, если это реальный секрет, немедленно ротировать его.",
                    "Перенести привилегированную операцию и секрет на backend/broker.",
                    "Не путать публичный API identifier с секретом; классифицировать найденные значения по назначению.",
                ),
            )
        }

        val traceHooks = assessment.hookProposals.asSequence()
            .filter { it.category in setOf("ENTITLEMENT_TRUST", "LOCAL_STATE", "FEATURE_CONFIG", "INTEGRITY", "AUTH_SESSION") }
            .take(MAX_EASY_TRACE_HOOKS)
            .toList()

        val score = checks.sumOf { checkScore(it) }.coerceIn(0, 100)
        return EasyAuditReport(
            score = score,
            band = when {
                score >= 75 -> "HIGH"
                score >= 45 -> "MEDIUM"
                score >= 20 -> "LOW"
                else -> "MINIMAL"
            },
            checks = checks.sortedWith(compareBy<AuditCheck> { severityOrdinal(it.severity) }.thenBy { it.title }),
            flagSweep = sweep,
            traceHooks = traceHooks,
        )
    }

    private fun noSurface(id: String, title: String, evidence: String) = AuditCheck(
        id = id,
        title = title,
        status = "NO_SURFACE_FOUND",
        severity = "INFORMATIONAL",
        evidence = listOf(evidence),
        explanation = "Отсутствие сигнала в статическом индексе не является доказательством защищённости; возможны динамически загружаемый код, шифрованные данные и серверная логика.",
        actions = listOf("При необходимости дополнить проверку runtime-наблюдением и серверным тестовым сценарием."),
    )

    private fun checkScore(check: AuditCheck): Int {
        if (check.status == "NO_SURFACE_FOUND") return 0
        return when (check.severity) {
            "CRITICAL" -> 26
            "HIGH" -> 18
            "MEDIUM" -> 10
            "LOW" -> 4
            else -> 1
        }
    }

    private fun severityOrdinal(value: String): Int = when (value) {
        "CRITICAL" -> 0
        "HIGH" -> 1
        "MEDIUM" -> 2
        "LOW" -> 3
        else -> 4
    }

    private const val MAX_EASY_TRACE_HOOKS = 12
}
