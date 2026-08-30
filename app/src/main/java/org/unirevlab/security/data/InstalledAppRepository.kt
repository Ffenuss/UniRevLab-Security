package org.unirevlab.security.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import org.unirevlab.security.model.InstalledAppDescriptor

class InstalledAppRepository(private val context: Context) {
    private val packageManager = context.packageManager

    @Suppress("DEPRECATION")
    fun load(): List<InstalledAppDescriptor> {
        val apps = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else {
            packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        }
        return apps.asSequence()
            .mapNotNull(::toDescriptor)
            .sortedWith(compareBy<InstalledAppDescriptor> { it.label.lowercase(java.util.Locale.ROOT) }.thenBy { it.packageName })
            .toList()
    }

    @Suppress("DEPRECATION")
    private fun toDescriptor(app: ApplicationInfo): InstalledAppDescriptor? {
        val basePath = app.publicSourceDir?.takeIf { it.isNotBlank() } ?: app.sourceDir?.takeIf { it.isNotBlank() } ?: return null
        val packageInfo = runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageInfo(app.packageName, PackageManager.PackageInfoFlags.of(0L))
            } else {
                packageManager.getPackageInfo(app.packageName, 0)
            }
        }.getOrNull() ?: return null

        val installer = if (Build.VERSION.SDK_INT >= 30) {
            runCatching { packageManager.getInstallSourceInfo(app.packageName).installingPackageName }.getOrNull()
        } else {
            runCatching { packageManager.getInstallerPackageName(app.packageName) }.getOrNull()
        }
        return InstalledAppDescriptor(
            label = runCatching { packageManager.getApplicationLabel(app).toString() }.getOrDefault(app.packageName),
            packageName = app.packageName,
            versionName = packageInfo.versionName,
            versionCode = if (Build.VERSION.SDK_INT >= 28) packageInfo.longVersionCode else packageInfo.versionCode.toLong(),
            isSystem = app.flags and ApplicationInfo.FLAG_SYSTEM != 0 || app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0,
            isEnabled = app.enabled,
            baseApkPath = basePath,
            splitApkPaths = (app.splitPublicSourceDirs ?: app.splitSourceDirs).orEmpty().filter { it.isNotBlank() }.distinct().sorted(),
            installerPackageName = installer,
        )
    }
}
