package org.unirevlab.security.analysis

import java.security.MessageDigest

/** Shared high-signal secret pattern classifier. Raw candidate material must not be persisted. */
object SensitiveStringClassifier {
    fun detectKind(value: String): String? {
        // Most DEX strings are class names, resources or ordinary literals. Avoid allocating
        // trim() results and invoking regex engines unless a cheap marker can possibly match.
        if (value.indexOf("PRIVATE KEY", ignoreCase = false) >= 0 && PRIVATE_KEY_MARKERS.any { value.contains(it) }) {
            return "PRIVATE_KEY_MATERIAL"
        }
        if (value.indexOf("eyJ", ignoreCase = false) >= 0 && JWT_REGEX.containsMatchIn(value)) return "JWT_LIKE_TOKEN"
        if (value.indexOf("AIza", ignoreCase = false) >= 0 && GOOGLE_API_KEY_REGEX.containsMatchIn(value)) return "GOOGLE_API_KEY_LIKE"
        if ((value.indexOf("AKIA", ignoreCase = false) >= 0 || value.indexOf("ASIA", ignoreCase = false) >= 0) &&
            AWS_ACCESS_KEY_REGEX.containsMatchIn(value)
        ) return "AWS_ACCESS_KEY_ID_LIKE"
        return null
    }

    fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    fun redacted(value: String): String = "<redacted:length=${value.length}>"

    private val JWT_REGEX = Regex("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b")
    private val GOOGLE_API_KEY_REGEX = Regex("\\bAIza[0-9A-Za-z_-]{35}\\b")
    private val AWS_ACCESS_KEY_REGEX = Regex("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b")
    private fun privateKeyMarker(prefix: String): String = "-----BEGIN " + prefix + "PRIVATE KEY-----"
    private val PRIVATE_KEY_MARKERS = listOf("", "RSA ", "EC ", "OPENSSH ").map(::privateKeyMarker)
}
