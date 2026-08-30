package org.unirevlab.security.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature

data class AgreementReceipt(
    val version: String,
    val acceptedAtEpochMs: Long,
    val signerName: String,
    val agreementTextSha256: String,
    val signatureBase64: String,
)

class AgreementStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isAccepted(): Boolean = loadReceipt()?.let(::verifyReceipt) == true

    fun loadReceipt(): AgreementReceipt? {
        val version = preferences.getString(KEY_VERSION, null) ?: return null
        val signer = preferences.getString(KEY_SIGNER_NAME, null)?.takeIf { it.isNotBlank() } ?: return null
        val hash = preferences.getString(KEY_TEXT_HASH, null) ?: return null
        val signature = preferences.getString(KEY_SIGNATURE, null) ?: return null
        val acceptedAt = preferences.getLong(KEY_ACCEPTED_AT, -1L).takeIf { it > 0 } ?: return null
        return AgreementReceipt(version, acceptedAt, signer, hash, signature)
    }

    fun accept(signerName: String): AgreementReceipt {
        val signer = signerName.trim().replace(Regex("\\s+"), " ")
        require(signer.length in 2..160) { "Укажите имя подписанта" }

        val acceptedAt = System.currentTimeMillis()
        val receipt = AgreementReceipt(
            version = CURRENT_AGREEMENT_VERSION,
            acceptedAtEpochMs = acceptedAt,
            signerName = signer,
            agreementTextSha256 = AGREEMENT_TEXT_SHA256,
            signatureBase64 = sign(canonicalReceipt(CURRENT_AGREEMENT_VERSION, acceptedAt, signer, AGREEMENT_TEXT_SHA256)),
        )
        preferences.edit()
            .putString(KEY_VERSION, receipt.version)
            .putLong(KEY_ACCEPTED_AT, receipt.acceptedAtEpochMs)
            .putString(KEY_SIGNER_NAME, receipt.signerName)
            .putString(KEY_TEXT_HASH, receipt.agreementTextSha256)
            .putString(KEY_SIGNATURE, receipt.signatureBase64)
            .apply()
        return receipt
    }

    fun verifyReceipt(receipt: AgreementReceipt): Boolean {
        if (receipt.version != CURRENT_AGREEMENT_VERSION) return false
        if (receipt.agreementTextSha256 != AGREEMENT_TEXT_SHA256) return false
        return runCatching {
            val keyStore = androidKeyStore()
            val certificate = keyStore.getCertificate(KEY_ALIAS) ?: return false
            val verifier = Signature.getInstance(SIGNATURE_ALGORITHM)
            verifier.initVerify(certificate.publicKey)
            verifier.update(
                canonicalReceipt(
                    receipt.version,
                    receipt.acceptedAtEpochMs,
                    receipt.signerName,
                    receipt.agreementTextSha256,
                ).toByteArray(Charsets.UTF_8)
            )
            verifier.verify(Base64.decode(receipt.signatureBase64, Base64.NO_WRAP))
        }.getOrDefault(false)
    }

    fun reset() {
        preferences.edit().clear().apply()
    }

    private fun sign(canonical: String): String {
        ensureSigningKey()
        val keyStore = androidKeyStore()
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            ?: error("Не удалось получить ключ подписи соглашения")
        val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(privateKey)
        signer.update(canonical.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(signer.sign(), Base64.NO_WRAP)
    }

    private fun ensureSigningKey() {
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) return
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        generator.generateKeyPair()
    }

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    companion object {
        const val CURRENT_AGREEMENT_VERSION = "2026-08-28-v2"
        const val AGREEMENT_TEXT = """UniRevLab Security предназначен исключительно для законного и явно авторизованного анализа безопасности приложений, систем и инфраструктуры. Пользователь подтверждает, что является владельцем выбранной цели либо получил достаточное разрешение владельца на каждый выполняемый вид анализа и обязан соблюдать применимое законодательство, договорные ограничения и согласованный scope. Запрещается использовать официальный клиент для несанкционированного доступа, кражи данных, скрытого контроля устройств, распространения вредоносного ПО, нарушения доступности сторонних систем или иных незаконных действий. Активные проверки допускаются только внутри явно созданного Assessment Scope. Неизвестные анализируемые артефакты считаются недоверенными входными данными."""

        val AGREEMENT_TEXT_SHA256: String by lazy {
            MessageDigest.getInstance("SHA-256")
                .digest(AGREEMENT_TEXT.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
        }

        private const val PREFS = "authorization_agreement"
        private const val KEY_VERSION = "agreement_version"
        private const val KEY_ACCEPTED_AT = "accepted_at"
        private const val KEY_SIGNER_NAME = "signer_name"
        private const val KEY_TEXT_HASH = "agreement_text_sha256"
        private const val KEY_SIGNATURE = "agreement_signature_b64"
        private const val KEY_ALIAS = "unirevlab_agreement_receipt_v1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        private fun canonicalReceipt(version: String, acceptedAt: Long, signerName: String, textHash: String): String =
            listOf(version, acceptedAt.toString(), signerName, textHash).joinToString("\n")
    }
}
