package org.unirevlab.security.data

import kotlin.test.Test
import kotlin.test.assertEquals

class AuditOutputNamesTest {
    @Test
    fun russianAndEnglishExportNamesAreDeterministic() {
        assertEquals("полный-отчёт.json", AuditOutputNames.localized(AuditJobRepository.REPORT_JSON, "ru"))
        assertEquals("full-report.json", AuditOutputNames.localized(AuditJobRepository.REPORT_JSON, "en"))
        assertEquals("полный-il2cpp-дамп.zip", AuditOutputNames.localized(AuditJobRepository.IL2CPP_DUMP_PACKAGE, "ru"))
    }
}
