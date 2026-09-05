package org.unirevlab.security.analysis

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfirmedIl2CppSurfaceExporterTest {
    @Test
    fun exportsOnlyConfirmedAddressesAndSeparatesDomains() {
        val dir = Files.createTempDirectory("confirmed-il2cpp").toFile()
        val dump = dir.resolve("dump.cs")
        dump.writeText(
            """
            public class PlayerStats
            {
                // RVA: 0x1234 Offset: 0x1234 VA: 0x1234
                public void ApplyDamage(int value) { }
                public int Health; // 0x18
            }
            public class Account
            {
                // RVA: 0x7777 Offset: 0x7777 VA: 0x7777
                public bool IsPremium() { }
                // RVA: 0x9999 Offset: 0x9999 VA: 0x9999
                public void HarmlessTelemetry() { }
            }
            """.trimIndent(),
        )
        val summary = ConfirmedIl2CppSurfaceExporter.export(dump, dir)
        val json = summary.outputJson.readText()
        assertEquals(2, summary.gameplayCount)
        assertEquals(1, summary.applicationCount)
        assertTrue(json.contains("0x1234"))
        assertTrue(json.contains("0x18"))
        assertTrue(json.contains("0x7777"))
        assertFalse(json.contains("0x9999"))
    }
}
