package org.unirevlab.security.data

/** Canonical names stay stable internally; exported/package names follow the selected UI language. */
object AuditOutputNames {
    fun localized(canonicalName: String, languageCode: String): String {
        if (languageCode != "ru") return canonicalName
        return when (canonicalName) {
            AuditJobRepository.REPORT_JSON -> "полный-отчёт.json"
            AuditJobRepository.CUSTOMER_REPORT -> "отчёт-заказчику.md"
            AuditJobRepository.OFFSET_EVIDENCE -> "подтверждённые-офсеты.json"
            AuditJobRepository.OFFSET_READABLE -> "офсеты-понятно.html"
            AuditJobRepository.IL2CPP_DUMP -> "il2cpp-дамп.cs"
            AuditJobRepository.IL2CPP_DUMP_PACKAGE -> "полный-il2cpp-дамп.zip"
            AuditJobRepository.GRADLE_MODULE_EVIDENCE -> "gradle-модули.json"
            AuditJobRepository.VERIFICATION_PLAN -> "план-проверок.json"
            AuditJobRepository.CUSTOMER_ACTION_MAP -> "карта-действий-заказчика.json"
            AuditJobRepository.MOD_RESISTANCE_VALIDATION -> "проверка-устойчивости-к-мод-меню.md"
            AuditJobRepository.ARTIFACT_BUNDLE -> "артефакты-анализа.zip"
            AuditJobRepository.EVIDENCE_MANIFEST -> "манифест-доказательств.json"
            AuditJobRepository.EVIDENCE_SIGNATURE -> "подпись-доказательств.json"
            AuditJobRepository.SIGNED_EVIDENCE_PACKAGE -> "подписанный-пакет-доказательств.zip"
            else -> canonicalName
        }
    }
}
