package org.unirevlab.security.ai

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ReportContextEngineTest {
    @Test
    fun includesSmallReportVerbatim() {
        val file = temporaryReport("""{"findings":[{"id":"TEST-1","severity":"HIGH"}]}""")
        try {
            val context = ReportContextEngine.build(file, "покажи high", 128_000)
            assertTrue(context.completeFileIncluded)
            assertTrue(context.text.contains("TEST-1"))
        } finally {
            file.delete()
        }
    }

    @Test
    fun scansLargeReportAndFindsEvidenceNearEnd() {
        val marker = "UNIQUE_REMOTE_CONFIG_AUTHORIZATION_FINDING"
        val file = File.createTempFile("unirevlab-large-report", ".json")
        try {
            file.bufferedWriter().use { writer ->
                writer.append("{\n\"padding\":[\n")
                repeat(35_000) { index ->
                    writer.append("{\"id\":\"").append(index.toString()).append("\",\"value\":\"ordinary filler evidence block\"},\n")
                }
                writer.append("{\"id\":\"").append(marker).append("\",\"severity\":\"HIGH\"}\n]}")
            }

            val context = ReportContextEngine.build(file, "remote config authorization", 32_000)

            assertFalse(context.completeFileIncluded)
            assertTrue(context.scannedChunks > context.includedChunks)
            assertTrue(context.text.contains(marker))
        } finally {
            file.delete()
        }
    }

    private fun temporaryReport(content: String): File = File.createTempFile("unirevlab-report", ".json").apply {
        writeText(content, Charsets.UTF_8)
    }
}
