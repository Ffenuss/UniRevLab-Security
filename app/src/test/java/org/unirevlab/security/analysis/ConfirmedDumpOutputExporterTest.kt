package org.unirevlab.security.analysis

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject

class ConfirmedDumpOutputExporterTest {
    @Test
    fun completedExportUsesOnlyAggregateProducedByRealDump() {
        val root = createTempDirectory("confirmed-dump-").toFile()
        try {
            val row = JSONObject()
                .put("abi", "arm64-v8a")
                .put("domain", "GAME")
                .put("category", "HEALTH_DAMAGE")
                .put("addressKind", "METHOD_RVA")
                .put("address", "0x1234")
                .put("namespace", "Game.Core")
                .put("className", "Player")
                .put("memberKind", "METHOD")
                .put("memberName", "TakeDamage")
                .put("declaredType", "void")
                .put("managedSignature", "public void TakeDamage(int value)")
                .put("addressFormula", "moduleBase(lib/arm64-v8a/libil2cpp.so) + 0x1234")
                .put("runtimeAddressStatus", "REQUIRES_RUNTIME_MODULE_BASE")
                .put("confidence", "HIGH")
                .put("managedIdentity", "Player.TakeDamage(int)")
            File(root, "confirmed-offsets-all-abi.json").writeText(
                JSONObject()
                    .put("schemaVersion", "1.0")
                    .put("gameplayOffsets", JSONArray().put(row))
                    .put("applicationAndMonetizationOffsets", JSONArray())
                    .toString(),
            )
            val result = completedResult(root)
            val jsonOutput = File(root, "job-offsets.json")
            val htmlOutput = File(root, "job-offsets.html")

            ConfirmedDumpOutputExporter.write(result, root, jsonOutput, htmlOutput, "ru")

            val exported = JSONObject(jsonOutput.readText())
            assertEquals("COMPLETE", exported.getString("status"))
            assertEquals("0x1234", exported.getJSONArray("gameplayOffsets").getJSONObject(0).getString("address"))
            assertTrue(htmlOutput.readText().contains("TakeDamage"))
            assertTrue(htmlOutput.readText().contains("Game.Core"))
            assertTrue(htmlOutput.readText().contains("Формула адреса"))
            assertTrue(htmlOutput.readText().contains("moduleBase(lib/arm64-v8a/libil2cpp.so) + 0x1234"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun failedDumpExportsNoAddresses() {
        val root = createTempDirectory("failed-dump-").toFile()
        try {
            val jsonOutput = File(root, "job-offsets.json")
            val htmlOutput = File(root, "job-offsets.html")

            ConfirmedDumpOutputExporter.write(null, root, jsonOutput, htmlOutput, "en")

            val exported = JSONObject(jsonOutput.readText())
            assertEquals("NOT_AVAILABLE", exported.getString("status"))
            assertEquals(0, exported.getJSONArray("gameplayOffsets").length())
            assertEquals(0, exported.getJSONArray("applicationAndMonetizationOffsets").length())
            assertFalse(htmlOutput.readText().contains("0x1234"))
        } finally {
            root.deleteRecursively()
        }
    }

    private fun completedResult(root: File) = RealIl2CppDumpEngine.Result(
        complete = true,
        status = "COMPLETE",
        error = null,
        engine = "il2cpp-dumper-rs",
        engineRevision = "test",
        metadataVersion = 31.0,
        architecture = "AARCH64",
        typeCount = 1,
        methodCount = 1,
        codeRegistration = "0x1000",
        metadataRegistration = "0x2000",
        registrationStrategy = "test",
        dumpCsFile = File(root, "dump.cs"),
        packageFile = File(root, "dump.zip"),
        manifestFile = File(root, "manifest.json"),
        generatedFiles = emptyList(),
        successfulAbis = listOf("arm64-v8a"),
    )
}
