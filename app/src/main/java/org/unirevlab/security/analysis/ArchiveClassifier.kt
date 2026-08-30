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

    fun isStandardNativeLibraryPath(name: String): Boolean =
        name.startsWith("lib/") && name.count { it == '/' } >= 2 && name.lowercase().endsWith(".so")
}
