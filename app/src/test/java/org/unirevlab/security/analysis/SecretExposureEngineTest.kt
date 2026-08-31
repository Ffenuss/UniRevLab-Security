package org.unirevlab.security.analysis

import java.io.File
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretExposureEngineTest {
    @Test
    fun detectsPlaintextAndReversibleEncodedSecretsWithoutPuttingRawInMetadata() {
        val dir = createTempDirectory("secret-proof").toFile()
        val apk = File(dir, "sample.apk")
        val googleKey = "AIza" + "A".repeat(35)
        val decodedSecret = "server_secret_value_123456789"
        val encodedSecret = Base64.getEncoder().encodeToString(decodedSecret.toByteArray())
        writeZip(
            apk,
            mapOf(
                "assets/config.json" to "{\"api_key\":\"$googleKey\",\"client_secret\":\"$encodedSecret\"}",
                "classes.dex" to "not-a-real-dex but contains ordinary bytes",
            ),
        )

        val artifactSha = "a".repeat(64)
        val report = SecretExposureEngine.scanApk(apk, artifactSha)
        val google = report.hits.first { it.kind == "GOOGLE_API_KEY" && it.exposure == "PLAINTEXT_EXPOSED" }
        assertEquals(1, report.hits.count { it.entryName == google.entryName && it.valueSha256 == google.valueSha256 })
        val encoded = report.hits.first { it.kind == "CLIENT_SECRET" }
        assertEquals("RECOVERABLE_ENCODING", encoded.exposure)
        assertEquals("BASE64", encoded.storage)
        assertTrue(encoded.roundTripVerified)
        assertFalse(encoded.redactedPreview.contains(decodedSecret))
        assertFalse(encoded.redactedPreview.contains(encodedSecret))

        val reveal = SecretExposureEngine.reveal(encoded.id, artifactSha, authorizationConfirmed = true)
        assertEquals(encodedSecret, reveal.rawValue)
        assertEquals(decodedSecret, reveal.recoveredValue)
        assertTrue(reveal.recoverySteps.isNotEmpty())

        val denied = runCatching { SecretExposureEngine.reveal(encoded.id, artifactSha, authorizationConfirmed = false) }
        assertTrue(denied.isFailure)
    }

    @Test
    fun ignoresPrivateKeyMarkerDatabaseButAcceptsStructuredPemBlock() {
        val dir = createTempDirectory("secret-pem").toFile()
        val markerApk = File(dir, "marker.apk")
        val begin = "-----BEGIN " + "PRIVATE KEY-----"
        val end = "-----END " + "PRIVATE KEY-----"
        writeZip(
            markerApk,
            mapOf("org/apache/tika/mime/tika-mimetypes.xml" to "signature example: $begin and no actual material"),
        )
        val markerReport = SecretExposureEngine.scanApk(markerApk, "b".repeat(64))
        assertTrue(markerReport.hits.none { it.kind == "PRIVATE_KEY_MATERIAL" })

        val der = ByteArray(131)
        der[0] = 0x30
        der[1] = 0x81.toByte()
        der[2] = 0x80.toByte()
        for (i in 3 until der.size) der[i] = ((i * 17) and 0xff).toByte()
        val pemBody = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
        val pem = "$begin\n$pemBody\n$end"
        val pemApk = File(dir, "pem.apk")
        writeZip(pemApk, mapOf("assets/credentials.pem" to pem))
        val pemReport = SecretExposureEngine.scanApk(pemApk, "c".repeat(64))
        val hit = pemReport.hits.firstOrNull { it.kind == "PRIVATE_KEY_MATERIAL" }
        assertNotNull(hit)
        assertTrue(requireNotNull(hit).structurallyValid)
        assertEquals("STRUCTURALLY_VALID", hit.exposure)
    }

    private fun writeZip(file: File, entries: Map<String, String>) {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            entries.forEach { (name, value) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(value.toByteArray())
                zip.closeEntry()
            }
        }
    }
}
