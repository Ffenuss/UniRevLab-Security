package org.unirevlab.security.analysis

object ArchiveClassifier {
    fun isSuspiciousPath(name: String): Boolean {
        if (name.startsWith("/") || name.startsWith("\\")) return true
        val normalized = name.replace('\\', '/')
        return normalized.split('/').any { it == ".." }
    }

    fun isDex(name: String): Boolean = name.lowercase().endsWith(".dex")

    fun isNativeLibrary(name: String): Boolean =
        name.lowercase().endsWith(".so")

    fun isStandardNativeLibraryPath(name: String): Boolean {
        // Installed-app analysis prefixes entries with the split container, for example
        // "split:split_config.arm64_v8a.apk!/lib/arm64-v8a/libgame.so".  Classification must
        // apply to the path inside that APK, not to the provenance prefix.
        val archivePath = name.replace('\\', '/').substringAfterLast("!/")
        val segments = archivePath.split('/')
        return segments.size >= 3 &&
            segments[0].equals("lib", ignoreCase = true) &&
            segments[1].isNotBlank() &&
            segments.last().endsWith(".so", ignoreCase = true)
    }
}
