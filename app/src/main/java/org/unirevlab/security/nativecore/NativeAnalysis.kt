package org.unirevlab.security.nativecore

/**
 * Optional narrow JNI bridge to the Rust analysis core.
 *
 * The Android client can continue to use PackageManager-based metadata if the native library is
 * unavailable. This prevents a packaging problem from blocking the whole assessment workflow.
 */
object NativeAnalysis {
    val isAvailable: Boolean by lazy {
        runCatching {
            System.loadLibrary("unirevlab_native_core")
            true
        }.getOrDefault(false)
    }

    external fun parseAxmlJson(input: ByteArray): String

    fun tryParseAxmlJson(input: ByteArray): String? {
        if (!isAvailable) return null
        return runCatching { parseAxmlJson(input) }.getOrNull()
    }
}
