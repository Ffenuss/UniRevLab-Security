package org.unirevlab.security.analysis

import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedFeedEnvelopeVerifierTest {
    @Test fun verifiesDetachedEd25519EnvelopeAndPreservesProvenance() {
        val payload = """{"schemaVersion":"1.0","feedId":"fixture","source":"fixture","generatedAt":"2026-08-30T00:00:00Z","advisories":[]}""".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(pair.private)
        signer.update(SignedFeedEnvelopeVerifier.signingMessage("ADVISORY_FEED", digest))
        val envelope = JSONObject()
            .put("schemaVersion", "1.0")
            .put("payloadType", "ADVISORY_FEED")
            .put("payloadSha256", digest)
            .put("keyId", "fixture-key")
            .put("algorithm", "ED25519")
            .put("signatureBase64", Base64.getEncoder().encodeToString(signer.sign()))
            .toString().toByteArray()
        val feed = SignedFeedEnvelopeVerifier.parseVerifiedAdvisoryFeed(
            ByteArrayInputStream(payload),
            ByteArrayInputStream(envelope),
            mapOf("fixture-key" to pair.public.encoded),
        )
        assertTrue(feed.provenance.signatureVerified)
        assertEquals("fixture-key", feed.provenance.signingKeyId)
        assertEquals("ED25519", feed.provenance.signatureAlgorithm)
        assertEquals(digest, feed.provenance.sha256)
    }
}
