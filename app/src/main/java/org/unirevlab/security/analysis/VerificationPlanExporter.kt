package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.StaticAnalysisReport
import java.util.Locale

/**
 * Produces defensive test objectives for a build supplied by its owner. The plan deliberately
 * contains no patch bytes, hook bodies, bypass recipe, or code-injection instructions.
 */
object VerificationPlanExporter {
    fun export(report: StaticAnalysisReport): String {
        val identifiers = buildList {
            report.dex?.classes.orEmpty().forEach { add(it.descriptor) }
            report.dex?.methods.orEmpty().forEach { add("${it.declaringClass} ${it.name}") }
            report.dex?.stringXrefs.orEmpty().forEach { add(it.value) }
        }.asSequence().map { it.lowercase(Locale.ROOT) }.take(MAX_IDENTIFIERS).toList()

        val tests = buildList {
            if (countMatches(identifiers, ENTITLEMENT_TERMS) > 0) add(
                TestCase(
                    id = "ENTITLEMENT-SERVER-AUTHORITY",
                    title = "Премиум и подписка",
                    reason = "В пакете обнаружены признаки клиентской логики entitlement/billing.",
                    secureExpected = "Сервер повторно проверяет покупку и не принимает локальный флаг как доказательство права.",
                    evidence = "Серверный журнал решения, идентификатор транзакции, отрицательный тест на подменённое локальное состояние.",
                    remediation = "Хранить источник истины на сервере, проверять purchase token и связывать entitlement с аккаунтом и устройством риска.",
                )
            )
            if (countMatches(identifiers, ECONOMY_TERMS) > 0) add(
                TestCase(
                    id = "ECONOMY-SERVER-AUTHORITY",
                    title = "Валюта и инвентарь",
                    reason = "Обнаружены признаки локального отображения баланса, валюты или инвентаря.",
                    secureExpected = "Все изменения баланса подтверждаются серверной транзакцией с защитой от повтора.",
                    evidence = "До/после серверного состояния, transaction id, ответ на повтор и конфликт версий.",
                    remediation = "Вести серверный ledger, использовать идемпотентность, версии состояния и проверку допустимости каждой операции.",
                )
            )
            if (countMatches(identifiers, GAMEPLAY_TERMS) > 0) add(
                TestCase(
                    id = "GAMEPLAY-STATE-VALIDATION",
                    title = "Игровые параметры",
                    reason = "Обнаружены признаки клиентских игровых параметров.",
                    secureExpected = "Соревновательные или экономически значимые значения проверяются авторитетной стороной.",
                    evidence = "Телеметрия несовместимого состояния, решение валидатора, безопасное завершение сессии.",
                    remediation = "Проверять инварианты сервером, подписывать критическое состояние и отделять косметические локальные настройки.",
                )
            )
            if (countMatches(identifiers, FLAG_TERMS) > 0) add(
                TestCase(
                    id = "LOCAL-FLAG-TRUST",
                    title = "Локальные флаги и конфигурация",
                    reason = "Есть признаки feature/debug/config flags в клиенте.",
                    secureExpected = "Локальный флаг не открывает привилегию без независимого доверенного решения.",
                    evidence = "Матрица флагов, источник каждого значения, серверное решение и fallback при ошибке подписи.",
                    remediation = "Разделять UX-флаги и полномочия, подписывать конфигурацию, fail closed для чувствительных возможностей.",
                )
            )
            report.manifest?.networkSecurity?.let { network ->
                if (!network.pinSetPresent || network.baseCleartextTrafficPermitted == true) add(
                    TestCase(
                        id = "NETWORK-TRUST-BOUNDARY",
                        title = "Сетевой контур",
                        reason = "Конфигурация доверия требует проверки: pinSet=${network.pinSetPresent}, cleartext=${network.baseCleartextTrafficPermitted}.",
                        secureExpected = "Чувствительные решения проходят только по аутентифицированному защищённому каналу и проверяются сервером.",
                        evidence = "Network Security Config, журнал TLS/серверного решения, отрицательные тесты для недоверенного сертификата и cleartext.",
                        remediation = "Запретить cleartext, ограничить trust anchors, применить корректную TLS-аутентификацию и безопасную ротацию ключей.",
                    )
                )
            }
            if (report.il2cpp?.detected == true) add(
                TestCase(
                    id = "IL2CPP-CLIENT-TRUST",
                    title = "Unity IL2CPP",
                    reason = "Найдены libil2cpp.so и/или global-metadata.dat; клиентская логика остаётся наблюдаемой.",
                    secureExpected = "Изменение клиентского исполнения не позволяет получить серверные полномочия, ценность или доверенный результат.",
                    evidence = "RVA/metadata evidence из отчёта, серверные инварианты, телеметрия целостности и решение backend.",
                    remediation = "Не считать IL2CPP защитной границей; переносить критические решения на сервер и использовать attestation как сигнал риска, а не единственную проверку.",
                )
            )
            if (isEmpty()) add(
                TestCase(
                    id = "BASELINE-CLIENT-TRUST",
                    title = "Базовая модель доверия",
                    reason = "Явная чувствительная поверхность не классифицирована автоматически.",
                    secureExpected = "Клиентские данные не являются единственным доказательством полномочий или ценной операции.",
                    evidence = "Диаграмма потоков доверия, серверные журналы отрицательных тестов, результаты ручного review.",
                    remediation = "Вручную отметить критические пользовательские сценарии и закрепить серверные инварианты для каждого.",
                )
            )
        }

        return JSONObject()
            .put("schemaVersion", "1.0")
            .put("assessmentId", report.assessment.assessmentId)
            .put("artifactSha256", report.artifact.sha256)
            .put("executionStatus", "NOT_EXECUTED")
            .put("scope", "Defensive verification for an owner-supplied or explicitly authorized test build.")
            .put("safety", "No patches, hook implementations, bypass recipes, or injected payloads are included.")
            .put("tests", JSONArray(tests.map(TestCase::toJson)))
            .toString(2)
    }

    private fun countMatches(values: List<String>, terms: Set<String>): Int =
        values.count { value -> terms.any(value::contains) }

    private data class TestCase(
        val id: String,
        val title: String,
        val reason: String,
        val secureExpected: String,
        val evidence: String,
        val remediation: String,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("id", id)
            .put("title", title)
            .put("reason", reason)
            .put("status", "NOT_EXECUTED")
            .put("secureExpected", secureExpected)
            .put("evidenceToCollect", evidence)
            .put("remediation", remediation)
    }

    private val ENTITLEMENT_TERMS = setOf("premium", "subscription", "billing", "purchase", "entitlement", "license")
    private val ECONOMY_TERMS = setOf("coins", "currency", "wallet", "balance", "inventory", "gems", "credits")
    private val GAMEPLAY_TERMS = setOf("health", "damage", "speed", "score", "playerstate", "hitpoints")
    private val FLAG_TERMS = setOf("featureflag", "remoteconfig", "sharedpreferences", "datastore", "debugflag", "unlock")
    private const val MAX_IDENTIFIERS = 100_000
}
