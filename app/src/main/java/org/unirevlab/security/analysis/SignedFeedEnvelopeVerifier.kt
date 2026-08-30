package org.unirevlab.security.analysis

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.json.JSONObject

/** Optional detached Ed25519 provenance envelope for advisory feeds or package-index snapshots. */
object SignedFeedEnvelopeVerifier {
    const val ENVELOPE_SCHEMA = "1.0"
    const val ALGORITHM = "ED25519"

    data class VerifiedPayload(
        val bytes: ByteArray,
        val payloadType: String,
        val payloadSha256: String,
        val keyId: String,
        val envelopeSha256: String,
    )

    data class Limits(val maxPayloadBytes: Int = 32 * 1024 * 1024, val maxEnvelopeBytes: Int = 64 * 1024)

    fun verify(
        payload: InputStream,
        envelope: InputStream,
        trustedPublicKeys: Map<String, ByteArray>,
        limits: Limits = Limits(),
    ): VerifiedPayload {
        val payloadBytes = readBounded(payload, limits.maxPayloadBytes)
        val envelopeBytes = readBounded(envelope, limits.maxEnvelopeBytes)
        val json = JSONObject(envelopeBytes.toString(Charsets.UTF_8))
        require(json.optString("schemaVersion") == ENVELOPE_SCHEMA) { "Unsupported signed envelope schema" }
        val payloadType = json.optString("payloadType").trim()
        require(payloadType in setOf("ADVISORY_FEED", "PACKAGE_INDEX")) { "Unsupported signed payload type" }
        require(json.optString("algorithm").uppercase() == ALGORITHM) { "Unsupported signature algorithm" }
        val keyId = json.optString("keyId").trim()
        require(keyId.isNotBlank() && keyId.length <= 128) { "Invalid signing key id" }
        val expectedHash = json.optString("payloadSha256").lowercase()
        require(expectedHash.matches(Regex("^[0-9a-f]{64}$"))) { "Invalid payload hash" }
        val actualHash = sha256(payloadBytes)
        require(MessageDigest.isEqual(expectedHash.toByteArray(), actualHash.toByteArray())) { "Signed payload SHA-256 mismatch" }
        val signatureBytes = runCatching { Base64.getDecoder().decode(json.optString("signatureBase64")) }
            .getOrElse { throw IllegalArgumentException("Invalid signature encoding", it) }
        require(signatureBytes.size in 32..256) { "Unexpected signature length" }
        val publicKeyBytes = trustedPublicKeys[keyId] ?: error("Signing key is not trusted: $keyId")
        val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(publicKeyBytes))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(publicKey)
        verifier.update(signingMessage(payloadType, actualHash))
        require(verifier.verify(signatureBytes)) { "Detached feed signature verification failed" }
        return VerifiedPayload(
            bytes = payloadBytes,
            payloadType = payloadType,
            payloadSha256 = actualHash,
            keyId = keyId,
            envelopeSha256 = sha256(envelopeBytes),
        )
    }

    fun parseVerifiedAdvisoryFeed(
        payload: InputStream,
        envelope: InputStream,
        trustedPublicKeys: Map<String, ByteArray>,
        limits: Limits = Limits(),
    ): VulnerabilityAdvisoryCorrelator.Feed {
        val verified = verify(payload, envelope, trustedPublicKeys, limits)
        require(verified.payloadType == "ADVISORY_FEED") { "Signed payload is not an advisory feed" }
        val parsed = ExternalAdvisoryFeedImporter.parse(ByteArrayInputStream(verified.bytes))
        require(parsed.provenance.sha256 == verified.payloadSha256) { "Imported feed hash differs from signed payload" }
        return parsed.copy(
            provenance = parsed.provenance.copy(
                signatureVerified = true,
                signingKeyId = verified.keyId,
                signatureAlgorithm = ALGORITHM,
                envelopeSha256 = verified.envelopeSha256,
            )
        )
    }

    fun signingMessage(payloadType: String, payloadSha256: String): ByteArray =
        "UNIREVLAB-SIGNED-PAYLOAD-1\n$payloadType\n${payloadSha256.lowercase()}\n".toByteArray(Charsets.UTF_8)

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= maxBytes) { "Signed provenance input exceeds bounded limit" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
