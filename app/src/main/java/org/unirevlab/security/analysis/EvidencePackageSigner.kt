package org.unirevlab.security.analysis

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.time.Instant
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

data class SignedEvidenceResult(
    val filesSigned: Int,
    val packageSizeBytes: Long,
    val manifestSha256: String,
)

/** Creates an integrity envelope for the audit outputs using a device-local Android Keystore key. */
object EvidencePackageSigner {
    fun create(
        inputs: List<File>,
        manifestFile: File,
        signatureFile: File,
        packageFile: File,
        assessmentId: String,
        artifactSha256: String,
        packageEntryNames: Map<String, String> = emptyMap(),
        cancelled: () -> Boolean = { false },
    ): SignedEvidenceResult {
        require(inputs.isNotEmpty()) { "Нет файлов для evidence-пакета" }
        require(inputs.all { it.isFile && it.parentFile == manifestFile.parentFile }) {
            "Evidence-файлы должны существовать в каталоге задания"
        }
        val orderedInputs = inputs.sortedBy(File::getName)
        val fileRecords = orderedInputs.map { file ->
            ensureActive(cancelled)
            val exportedName = packageEntryNames[file.name] ?: file.name
            JSONObject()
                .put("name", exportedName)
                .put("canonicalName", file.name)
                .put("sizeBytes", file.length())
                .put("sha256", sha256(file, cancelled))
        }
        val manifest = JSONObject()
            .put("schemaVersion", "1.0")
            .put("assessmentId", assessmentId)
            .put("artifactSha256", artifactSha256)
            .put("generatedAt", Instant.now().toString())
            .put("integrityScope", "Audit outputs listed below; the original target APK is not repackaged or modified.")
            .put("files", JSONArray(fileRecords))
            .toString(2)
            .toByteArray(Charsets.UTF_8)
        manifestFile.writeBytes(manifest)

        val manifestSha256 = sha256(manifest)
        val signature = sign(manifest)
        val manifestEntryName = packageEntryNames[manifestFile.name] ?: manifestFile.name
        val certificate = androidKeyStore().getCertificate(KEY_ALIAS)
            ?: error("Сертификат evidence-подписи недоступен")
        signatureFile.writeText(
            JSONObject()
                .put("schemaVersion", "1.0")
                .put("algorithm", SIGNATURE_ALGORITHM)
                .put("keyAlias", KEY_ALIAS)
                .put("manifest", manifestEntryName)
                .put("manifestSha256", manifestSha256)
                .put("publicKeySha256", sha256(certificate.publicKey.encoded))
                .put("publicKeyFormat", certificate.publicKey.format)
                .put("publicKeyDerBase64", Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP))
                .put("signatureBase64", Base64.encodeToString(signature, Base64.NO_WRAP))
                .put("verification", "Verify SHA-256 of $manifestEntryName, decode the X.509 public key, then verify signatureBase64 with SHA256withECDSA.")
                .toString(2),
            Charsets.UTF_8,
        )

        val packaged = orderedInputs + manifestFile + signatureFile
        packageFile.outputStream().buffered().use { raw ->
            ZipOutputStream(raw).use { zip ->
                packaged.forEach { file ->
                    ensureActive(cancelled)
                    zip.putNextEntry(ZipEntry(packageEntryNames[file.name] ?: file.name).apply { time = 0L })
                    file.inputStream().buffered().use { input ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            ensureActive(cancelled)
                            val read = input.read(buffer)
                            if (read <= 0) break
                            zip.write(buffer, 0, read)
                        }
                    }
                    zip.closeEntry()
                }
            }
        }
        return SignedEvidenceResult(packaged.size, packageFile.length(), manifestSha256)
    }

    private fun sign(bytes: ByteArray): ByteArray {
        ensureSigningKey()
        val key = androidKeyStore().getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            ?: error("Ключ evidence-подписи недоступен")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(key)
            update(bytes)
            sign()
        }
    }

    private fun ensureSigningKey() {
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) return
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).setDigests(KeyProperties.DIGEST_SHA256).build()
            )
            generateKeyPair()
        }
    }

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun sha256(file: File, cancelled: () -> Boolean): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                ensureActive(cancelled)
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().toHex()
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun ensureActive(cancelled: () -> Boolean) {
        if (cancelled()) throw java.util.concurrent.CancellationException("Подписание отменено")
    }

    private const val KEY_ALIAS = "unirevlab_evidence_signing_v1"
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
}
