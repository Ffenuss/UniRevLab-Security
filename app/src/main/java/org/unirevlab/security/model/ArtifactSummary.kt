package org.unirevlab.security.model

data class ArtifactSummary(
    val displayName: String,
    val sizeBytes: Long?,
    val sha256: String,
    val archiveEntries: Int?,
    val dexFiles: Int?,
    val nativeLibraries: Int?,
    val hasAndroidManifest: Boolean?,
    val suspiciousArchivePaths: Int?,
    val truncatedArchiveScan: Boolean,
    val sourceKind: String = "FILE",
    val sourcePackageName: String? = null,
    val sourceInstallerPackageName: String? = null,
    val splitApkCount: Int = 0,
) : java.io.Serializable
