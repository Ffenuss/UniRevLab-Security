package org.unirevlab.security.analysis

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory

class GradleModuleEvidenceExporterTest {
    @Test
    fun recoversDynamicFeatureAndAgpMetadata() {
        val directory = createTempDirectory("gradle-evidence-test").toFile()
        val apk = directory.resolve("payments.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(
                """<manifest split="payments" android:isFeatureSplit="true" xmlns:android="http://schemas.android.com/apk/res/android" xmlns:dist="http://schemas.android.com/apk/distribution"><dist:module><dist:on-demand/></dist:module></manifest>"""
                    .toByteArray(),
            )
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/com/android/build/gradle/app-metadata.properties"))
            zip.write("gradleVersion=9.0\nandroidGradlePluginVersion=9.0.0\n".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/payments.kotlin_module"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }
        val output = directory.resolve("gradle-module-evidence.json")

        val result = GradleModuleEvidenceExporter.exportFilesForTesting(listOf(apk), output)
        val json = JSONObject(output.readText())

        assertEquals(1, result.modulesDetected)
        assertEquals(1, result.dynamicFeaturesDetected)
        assertEquals(0, result.assetPacksDetected)
        assertEquals(2, result.metadataMarkersDetected)
        assertFalse(result.truncated)
        assertEquals("DYNAMIC_FEATURE", json.getJSONArray("modules").getJSONObject(0).getString("kind"))
        assertTrue(output.readText().contains("androidGradlePluginVersion"))
    }

    @Test
    fun distinguishesAssetPackAndReadsPlainVersionMarkers() {
        val directory = createTempDirectory("gradle-asset-pack-test").toFile()
        val apk = directory.resolve("BinaryAssets.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(
                """<manifest split="BinaryAssets" android:isFeatureSplit="true" xmlns:android="http://schemas.android.com/apk/res/android" xmlns:dist="http://schemas.android.com/apk/distribution"><dist:module dist:type="asset-pack"><dist:install-time/></dist:module></manifest>"""
                    .toByteArray(),
            )
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/androidx.core_core.version"))
            zip.write("1.15.0\n".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/androidx.browser_browser.version"))
            zip.write("task ':browser:writeVersionFile' property 'version'\n".toByteArray())
            zip.closeEntry()
        }
        val output = directory.resolve("gradle-module-evidence.json")

        val result = GradleModuleEvidenceExporter.exportFilesForTesting(listOf(apk), output)
        val json = JSONObject(output.readText())

        assertEquals(1, result.assetPacksDetected)
        assertEquals(0, result.dynamicFeaturesDetected)
        assertEquals("ASSET_PACK", json.getJSONArray("modules").getJSONObject(0).getString("kind"))
        val markers = json.getJSONArray("markers")
        assertEquals("1.15.0", markers.getJSONObject(0).getJSONObject("properties").getString("version"))
        assertEquals("NO_SAFE_VERSION_VALUE", markers.getJSONObject(1).getString("parseStatus"))
    }
}
