package org.unirevlab.security.analysis

import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport
import java.time.Instant

object CustomerReportExporter {
    fun export(report: StaticAnalysisReport): String = buildString {
        appendLine("# Отчёт авторизованного аудита приложения")
        appendLine()
        appendLine("- Проект: ${safe(report.assessment.projectName)}")
        appendLine("- Заказчик / владелец: ${safe(report.assessment.organization)}")
        appendLine("- Цель: ${safe(report.assessment.purpose)}")
        appendLine("- Assessment ID: `${report.assessment.assessmentId}`")
        appendLine("- Артефакт: ${safe(report.artifact.displayName)}")
        appendLine("- Package: `${report.manifest?.packageName ?: report.artifact.sourcePackageName ?: "не определён"}`")
        appendLine("- SHA-256: `${report.artifact.sha256}`")
        appendLine("- Время формирования: ${Instant.now()}")
        appendLine("- Движок: `${report.engineVersion}`")
        appendLine()
        appendLine("## Результат")
        appendLine()
        appendLine("Статический анализ выполнен без запуска или изменения целевого APK. Сформированы воспроизводимые evidence-файлы, перечень runtime-артефактов, RVA/offset evidence и план проверок для тестовой сборки владельца.")
        appendLine()
        appendLine("| Метрика | Значение |")
        appendLine("|---|---:|")
        appendLine("| Findings | ${report.findings.size} |")
        appendLine("| Critical | ${report.findings.count { it.severity == Severity.CRITICAL }} |")
        appendLine("| High | ${report.findings.count { it.severity == Severity.HIGH }} |")
        appendLine("| Medium | ${report.findings.count { it.severity == Severity.MEDIUM }} |")
        appendLine("| DEX methods indexed | ${report.dex?.methodsIndexed ?: 0} |")
        appendLine("| Native libraries | ${report.native?.librariesScanned ?: 0} |")
        appendLine("| IL2CPP | ${if (report.il2cpp?.detected == true) "обнаружен" else "не обнаружен"} |")
        appendLine()
        appendLine("## Вывод о доверии к клиенту")
        appendLine()
        if (report.il2cpp?.detected == true) {
            appendLine("Наличие IL2CPP не делает критическую клиентскую логику доверенной: `libil2cpp.so` и metadata автоматически обнаружены и отражены в evidence. Критические полномочия и ценные операции должны подтверждаться сервером.")
        } else {
            appendLine("Независимо от runtime, клиентская логика и локальное состояние не должны быть единственным источником истины для полномочий, оплаты, баланса или доверенного результата.")
        }
        appendLine()
        appendLine("## Findings и исправления")
        appendLine()
        if (report.findings.isEmpty()) {
            appendLine("Автоматические правила не сформировали findings. Это не является доказательством отсутствия уязвимостей; выполните проверки из `verification-plan.json`.")
        } else {
            report.findings.take(MAX_FINDINGS).forEachIndexed { index, finding ->
                appendLine("### ${index + 1}. ${safe(finding.title)}")
                appendLine()
                appendLine("- ID: `${finding.id}`")
                appendLine("- Важность: **${finding.severity}**")
                appendLine("- Уверенность: ${finding.confidence}")
                appendLine("- Категория: ${safe(finding.category)}")
                appendLine()
                appendLine(safe(finding.description))
                appendLine()
                appendLine("Рекомендация: ${safe(finding.remediation)}")
                appendLine()
            }
            if (report.findings.size > MAX_FINDINGS) {
                appendLine("Остальные ${report.findings.size - MAX_FINDINGS} findings доступны в `full-report.json`.")
                appendLine()
            }
        }
        appendLine("## Состав evidence-пакета")
        appendLine()
        appendLine("- `full-report.json` — полный структурированный отчёт.")
        appendLine("- `customer-report.md` — этот отчёт.")
        appendLine("- `offset-evidence.json` — статические RVA, metadata offsets и tokens с явной семантикой адресов.")
        appendLine("- `analysis-artifacts.zip` — автоматически найденные DEX/native/runtime inputs.")
        appendLine("- `verification-plan.json` — безопасные ожидаемые результаты проверок для сборки владельца.")
        appendLine("- `evidence-manifest.json` и `evidence-signature.json` — хеши и локальная криптографическая подпись.")
        appendLine()
        appendLine("## Ограничение метода")
        appendLine()
        appendLine("Пакет не содержит модифицированного APK, внедрённого mod-menu, рабочих bypass-патчей или hook-кода. Активные проверки выполняются в отдельной тестовой сборке, которую владелец приложения собирает и подписывает своим тестовым ключом.")
    }

    private fun safe(value: String): String = value.replace('\n', ' ').replace('\r', ' ').trim()
    private const val MAX_FINDINGS = 50
}
