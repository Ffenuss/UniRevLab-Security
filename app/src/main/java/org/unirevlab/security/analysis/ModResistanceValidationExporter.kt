package org.unirevlab.security.analysis

import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Produces a customer-executable defensive validation playbook.
 *
 * The playbook deliberately uses owner-controlled source seams, test doubles and QA builds.
 * It never emits binary patches, hook implementations, runtime injection instructions,
 * payment bypasses, response-rewrite recipes or a modified application artifact.
 */
object ModResistanceValidationExporter {
    fun export(
        report: StaticAnalysisReport,
        actionMap: JSONObject = CustomerActionMapExporter.build(report),
        languageCode: String = "ru",
    ): String = if (languageCode == "en") exportEnglish(report, actionMap) else exportRussian(report, actionMap)

    private fun exportRussian(report: StaticAnalysisReport, actionMap: JSONObject) = buildString {
        appendLine("# Пошаговая проверка устойчивости к мод-меню")
        appendLine()
        appendLine("- Assessment ID: `${md(report.assessment.assessmentId)}`")
        appendLine("- Артефакт: `${md(report.artifact.displayName)}`")
        appendLine("- SHA-256: `${report.artifact.sha256}`")
        appendLine("- Анализатор: `${md(report.engineVersion)}`")
        appendLine()
        appendLine("## Назначение и граница метода")
        appendLine()
        appendLine("Этот документ помогает владельцу продукта проверить, сможет ли изменение недоверенного Android-клиента повлиять на покупку, premium-доступ, валюту, инвентарь, прогресс, бой, конфигурацию или сетевое решение. Проверка выполняется в исходном коде владельца, отдельной QA/debug-сборке, на тестовых аккаунтах и изолированном стенде.")
        appendLine()
        appendLine("Документ не является инструкцией по созданию или распространению рабочего мода. В нём намеренно отсутствуют готовые хуки, адреса для инъекции, байтовые патчи, переподпись изменённого APK, подмена платёжных ответов и обход серверной авторизации.")
        appendLine()
        appendLine("## Что считать результатом")
        appendLine()
        appendLine("| Статус | Значение | Действие |")
        appendLine("|---|---|---|")
        appendLine("| `STATIC_FACT_CONFIRMED` | Конфигурация или компонент подтверждены статически | Исправить либо обосновать принятие риска |")
        appendLine("| `STATIC_COORDINATE_CONFIRMED` | Координата/идентичность подтверждена, влияние ещё не доказано | Проследить до доверенного sink в исходниках |")
        appendLine("| `CLIENT_AUTHORITY_RISK` | Решение выглядит локально авторитетным | Перенести окончательное решение в доверенную сторону |")
        appendLine("| `SERVER_ENFORCEMENT_REVIEW_REQUIRED` | Есть и клиентские, и серверные признаки | Доказать серверный fail-closed для каждой операции |")
        appendLine("| `SERVER_GATED_STATIC_SIGNAL` | Найден серверный gate, но динамика не выполнена | Выполнить негативные API-тесты |")
        appendLine("| `REVIEW_REQUIRED` | Данных недостаточно | Не объявлять уязвимостью до трассировки |")
        appendLine()
        appendRussianWorkflow()
        appendLine("## Карта файлов доказательств")
        appendLine()
        appendReportGuide(actionMap.getJSONArray("reportGuide"))
        appendLine()
        appendLine("## Индивидуальные карточки проверки")
        appendLine()
        val items = actionMap.getJSONArray("items")
        if (items.length() == 0) {
            appendLine("Статических карточек риска не сформировано. Это не доказывает отсутствие риска: проверьте ограничения покрытия в `customer-report.md` и `full-report.json`.")
        } else {
            for (index in 0 until items.length()) appendRussianItem(index + 1, items.getJSONObject(index))
        }
        appendLine()
        appendRussianAcceptance()
    }

    private fun StringBuilder.appendRussianWorkflow() {
        appendLine("## Порядок работы заказчика")
        appendLine()
        appendLine("1. **Зафиксировать область.** Записать версию, SHA-256, package ID, ABI, окружение, тестовые аккаунты, разрешённые API и срок проверки. Не смешивать результаты разных сборок.")
        appendLine("2. **Сохранить эталон.** Заархивировать исходную release/QA-сборку, backend-конфигурацию, схему данных и ожидаемые значения критичных операций.")
        appendLine("3. **Составить список защищаемых активов.** Отдельно перечислить entitlement/premium, покупки, валюту, инвентарь, прогресс, боевые параметры, feature flags, сохранения и удалённую конфигурацию. Для каждого назвать доверенный источник истины.")
        appendLine("4. **Начать с `customer-action-map.json`.** Для каждой карточки открыть перечисленные evidence-файлы и убедиться, что selector действительно указывает на тот же класс, метод, поле, компонент или библиотеку.")
        appendLine("5. **Проверить качество доказательства.** Отличить имя/строку/metadata token от подтверждённого метода, RVA или field offset. Статический сигнал не считать доказанным влиянием.")
        appendLine("6. **Найти решение в исходниках владельца.** Проследить цепочку от UI/ввода через getter, cache, billing callback, repository или native bridge до операции, которая реально выдаёт ценность. Зафиксировать последний доверенный sink и владельца кода.")
        appendLine("7. **Создать безопасную QA-точку.** В отдельной ветке добавить compile-time test seam, dependency injection, fake provider или test double, который имитирует только итог недоверенного клиента. Точка должна отсутствовать в release-варианте и не должна принимать команды из внешнего overlay, сокета или файла.")
        appendLine("8. **Смоделировать результат, а не технику взлома.** В QA-сборке поочерёдно вернуть локальный success, изменённый cache, невозможное числовое значение, устаревшую конфигурацию и ошибочный сетевой результат. Не патчить APK и не вмешиваться в чужой процесс.")
        appendLine("9. **Наблюдать доверенный sink.** Проверить, изменился ли серверный ledger, entitlement, выдача контента, матчевое состояние или иная ценность. Одно изменение UI не считать полным воздействием.")
        appendLine("10. **Выполнить негативные тесты.** Проверить missing/stale/replayed/wrong-account/wrong-product proof, повтор запроса, нарушение порядка, невозможный диапазон, неверную подпись, schema mismatch и отсутствие сети. Ожидаемое поведение — fail closed.")
        appendLine("11. **Исправить архитектуру.** Клиент передаёт намерение, а не авторитетный результат; сервер атомарно проверяет право, состояние, версию и инварианты. Локальные флаги остаются только cache/UI.")
        appendLine("12. **Добавить телеметрию.** Логировать отказ без секретов: assessment/build, account pseudonym, rule, state version, nonce/idempotency key и причину отклонения.")
        appendLine("13. **Пересобрать и повторить.** Запустить тот же набор негативных тестов, затем новый UniRevLab-анализ исправленной сборки и сравнение отчётов по идентификаторам findings.")
        appendLine("14. **Закрыть карточку только по критерию.** Риск закрыт, когда защищённая операция отклоняет поддельное клиентское состояние, тест автоматизирован, а новый evidence-пакет привязан к новому SHA-256.")
        appendLine()
    }

    private fun StringBuilder.appendRussianItem(number: Int, item: JSONObject) {
        val id = item.optString("id", "item-$number")
        appendLine("### $number. `${md(id)}` — ${md(item.optString("subject", "Без названия"))}")
        appendLine()
        appendLine("- Статус: `${md(item.optString("status", "REVIEW_REQUIRED"))}`")
        item.optString("authorityAssessment").takeIf { it.isNotBlank() }?.let { appendLine("- Оценка authority: `${md(it)}`") }
        item.optString("priority").takeIf { it.isNotBlank() }?.let { appendLine("- Приоритет: `${md(it)}`") }
        item.optString("confidence").takeIf { it.isNotBlank() }?.let { appendLine("- Уверенность: `${md(it)}`") }
        appendLine("- Риск-сценарий: ${md(item.optString("potentialTamperingClass", item.optString("risk")))}")
        appendLine("- Основание: ${md(item.optString("risk", "Не указано"))}")
        appendLine("- Изменение у владельца: ${md(item.optString("customerChange", "Требуется ручная трассировка"))}")
        appendLine("- Безопасная проверка: ${md(item.optString("verification", "Повторить анализ после исправления"))}")
        appendLine("- Эксплуатационные инструкции включены: `${item.optBoolean("operationalExploitInstructionsIncluded", false)}`")
        appendLine("- Где взять доказательство:")
        val sources = item.optJSONArray("evidenceSources") ?: JSONArray()
        if (sources.length() == 0) appendLine("  - Источник не указан; оставить карточку в `REVIEW_REQUIRED`.")
        for (i in 0 until sources.length()) {
            val source = sources.getJSONObject(i)
            appendLine("  - `${md(source.optString("report"))}` → `${md(source.optString("selector"))}`: ${md(source.optString("contains"))}")
        }
        appendLine()
    }

    private fun StringBuilder.appendRussianAcceptance() {
        appendLine("## Общие критерии приёмки")
        appendLine()
        appendLine("- Изменение локального UI/cache не выдаёт защищённую ценность.")
        appendLine("- Backend повторно проверяет право и объект операции, а не доверяет клиентскому `success`.")
        appendLine("- Повтор, перестановка, устаревшая версия и неверная привязка не меняют состояние.")
        appendLine("- Критичные операции идемпотентны и атомарны; диапазоны и переходы состояния проверяются.")
        appendLine("- Ошибка проверки не переводит систему в разрешающий режим.")
        appendLine("- QA test seam отсутствует в release artifact и контролируется тестом сборки.")
        appendLine("- Новый отчёт не содержит необъяснённых `CLIENT_AUTHORITY_RISK`; исключения оформлены как принятый риск.")
        appendLine("- Evidence package и протокол теста привязаны к хэшу исправленной сборки.")
    }

    private fun exportEnglish(report: StaticAnalysisReport, actionMap: JSONObject) = buildString {
        appendLine("# Mod-menu resistance validation playbook")
        appendLine()
        appendLine("Artifact: `${md(report.artifact.displayName)}`  ")
        appendLine("SHA-256: `${report.artifact.sha256}`  ")
        appendLine("Assessment: `${md(report.assessment.assessmentId)}`")
        appendLine()
        appendLine("Use this playbook only in an owner-controlled QA/debug build and isolated test environment. It validates attacker-controlled client outcomes through source-level test seams; operational binary-modification steps, hooks, patch bytes, payment bypasses and response-rewrite recipes are intentionally excluded.")
        appendLine()
        appendLine("## Workflow")
        appendLine()
        appendLine("1. Freeze scope, artifact hash, accounts, APIs and expected protected outcomes.")
        appendLine("2. Inventory entitlements, purchases, economy, inventory, progression, combat state, feature flags and remote configuration; name the trusted authority for each.")
        appendLine("3. Use `customer-action-map.json` to locate the exact supporting DEX, ELF, JNI and IL2CPP evidence.")
        appendLine("4. Trace every candidate in owner source to the final trusted sink; do not infer impact from a name or offset alone.")
        appendLine("5. Add a compile-time QA-only dependency-injection seam or test double that simulates an untrusted client result and cannot ship in release.")
        appendLine("6. Simulate local success, modified cache, impossible values, stale configuration and invalid network results; observe whether protected value changes.")
        appendLine("7. Test missing, stale, replayed, wrong-account and wrong-product authorization plus ordering, range, signature and schema failures. Require fail-closed behavior.")
        appendLine("8. Move authority to the trusted backend/simulation, make mutations atomic and idempotent, and keep client state display-only.")
        appendLine("9. Rebuild, rerun every negative test, repeat UniRevLab analysis and bind closure evidence to the new SHA-256.")
        appendLine()
        appendLine("## Evidence map")
        appendLine()
        appendReportGuide(actionMap.getJSONArray("reportGuide"))
        appendLine()
        appendLine("## Risk cards")
        appendLine()
        val items = actionMap.getJSONArray("items")
        if (items.length() == 0) appendLine("No static risk cards were produced. Review analyzer coverage limitations before concluding that risk is absent.")
        for (index in 0 until items.length()) {
            val item = items.getJSONObject(index)
            appendLine("### ${index + 1}. `${md(item.optString("id"))}` — ${md(item.optString("subject"))}")
            appendLine()
            appendLine("- Status: `${md(item.optString("status"))}`")
            appendLine("- Threat scenario: ${md(item.optString("potentialTamperingClass"))}")
            appendLine("- Evidence basis: ${md(item.optString("risk"))}")
            appendLine("- Owner change: ${md(item.optString("customerChange"))}")
            appendLine("- Safe validation: ${md(item.optString("verification"))}")
            appendLine("- Evidence locations:")
            val sources = item.optJSONArray("evidenceSources") ?: JSONArray()
            for (i in 0 until sources.length()) {
                val source = sources.getJSONObject(i)
                appendLine("  - `${md(source.optString("report"))}` → `${md(source.optString("selector"))}`: ${md(source.optString("contains"))}")
            }
            appendLine()
        }
    }

    private fun StringBuilder.appendReportGuide(guide: JSONArray) {
        appendLine("| Файл / File | Назначение / Use | Содержимое / Contents |")
        appendLine("|---|---|---|")
        for (index in 0 until guide.length()) {
            val row = guide.getJSONObject(index)
            appendLine("| `${md(row.optString("report"))}` | ${cell(row.optString("use"))} | ${cell(row.optString("contains"))} |")
        }
    }

    private fun md(value: String): String = value.replace("`", "'").replace("\r", " ").replace("\n", " ").trim()
    private fun cell(value: String): String = md(value).replace("|", "\\|")
}
