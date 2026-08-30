package org.unirevlab.security.model

/** Snapshot of one package visible to UniRevLab through Android PackageManager. */
data class InstalledAppDescriptor(
    val label: String,
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val isSystem: Boolean,
    val isEnabled: Boolean,
    val baseApkPath: String,
    val splitApkPaths: List<String> = emptyList(),
    val installerPackageName: String? = null,
) : java.io.Serializable {
    val apkCount: Int get() = 1 + splitApkPaths.size
}
