package org.unirevlab.security.data

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.StaticAnalysisReport

class ReportSnapshotCodecTest {
    @Test
    fun roundTripsCompletedReportAndChecksIntegrity() {
        val directory = Files.createTempDirectory("unirevlab-history-test").toFile()
        try {
            val report = report()
            val meta = ReportSnapshotCodec.write(report, directory, "assessment-1.urh.gz")
            val restored = ReportSnapshotCodec.read(
                file = File(directory, meta.fileName),
                expectedSizeBytes = meta.sizeBytes,
                expectedSha256 = meta.sha256,
                expectedFormatVersion = meta.formatVersion,
            )

            assertEquals(report.artifact.sha256, restored.artifact.sha256)
            assertEquals(report.assessment.assessmentId, restored.assessment.assessmentId)
            assertEquals(report.engineVersion, restored.engineVersion)
            assertTrue(meta.sizeBytes > 0)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun rejectsCorruptedSnapshotBeforeDeserialization() {
        val directory = Files.createTempDirectory("unirevlab-history-corrupt").toFile()
        try {
            val meta = ReportSnapshotCodec.write(report(), directory, "assessment-2.urh.gz")
            val file = File(directory, meta.fileName)
            val bytes = file.readBytes()
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
            file.writeBytes(bytes)

            val failure = runCatching {
                ReportSnapshotCodec.read(file, meta.sizeBytes, meta.sha256, meta.formatVersion)
            }.exceptionOrNull()

            assertTrue(failure != null)
            assertTrue(failure?.message.orEmpty().contains("integrity", ignoreCase = true))
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun report() = StaticAnalysisReport(
        engineVersion = "history-test",
        assessment = AssessmentScope(
            assessmentId = "assessment-test",
            projectName = "History Test",
            organization = "UniRevLab",
            purpose = "Regression test",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "sample.apk",
            sizeBytes = 1234,
            sha256 = "0123456789abcdef",
            archiveEntries = 10,
            dexFiles = 1,
            nativeLibraries = 0,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        findings = emptyList(),
    )
}
