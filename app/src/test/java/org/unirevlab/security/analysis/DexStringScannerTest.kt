package org.unirevlab.security.analysis

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DexStringScannerTest {
    @Test
    fun scansUrlsAndRedactsSecretCandidate() {
        val file = tempDex(
            listOf(
                "https://user:pass@api.example.org/login?token=must-not-leak",
                "http://legacy.example.org/v1",
                "eyJabcdefghijk.abcdefghijkl.mnopqrstuvwxyz",
                "ordinary",
            )
        )
        try {
            val scan = DexStringScanner.scan("classes.dex", file)
            assertEquals(4, scan.stringsDeclared)
            assertEquals("https://api.example.org/login", scan.httpsUrls.single().value)
            assertEquals("http://legacy.example.org/v1", scan.httpUrls.single().value)
            assertTrue(scan.secretCandidates.any { it.kind == "JWT_LIKE_TOKEN" })
            assertTrue(scan.secretCandidates.all { it.redactedPreview.startsWith("<redacted:length=") })
        } finally {
            file.delete()
        }
    }



    @Test
    fun decodesModifiedUtf8NullAndUnicode() {
        val file = mutf8Dex()
        try {
            val scan = DexStringScanner.scan("classes.dex", file)
            assertEquals(1, scan.stringsDeclared)
            assertEquals(1, scan.stringsScanned)
        } finally {
            file.delete()
        }
    }

    @Test
    fun indexesClassesMethodsAndNativeDeclarations() {
        val file = indexedNativeDex()
        try {
            val scan = DexStringScanner.scan("classes.dex", file)
            assertEquals(3, scan.typesDeclared)
            assertEquals(1, scan.classesDeclared)
            assertEquals(1, scan.methodsDeclared)
            assertEquals("Lcom/example/NativeBridge;", scan.classes.single().descriptor)
            assertEquals("nativeCheck", scan.methods.single().name)
            assertEquals("()V", scan.methods.single().prototype)
            assertEquals("nativeCheck", scan.nativeMethods.single().name)
        } finally {
            file.delete()
        }
    }

    @Test(expected = DexStringScanner.DexFormatException::class)
    fun rejectsInvalidMagic() {
        val file = File.createTempFile("bad-dex", ".dex")
        file.writeBytes(ByteArray(0x70))
        try {
            DexStringScanner.scan("classes.dex", file)
        } finally {
            file.delete()
        }
    }

    @Test(expected = DexStringScanner.DexFormatException::class)
    fun rejectsOutOfBoundsMethodTable() {
        val file = tempDex(listOf("ordinary"))
        try {
            java.io.RandomAccessFile(file, "rw").use { raf ->
                raf.seek(0x58)
                raf.write(byteArrayOf(1, 0, 0, 0)) // method_ids_size = 1
                raf.write(byteArrayOf(0x7f, 0x7f, 0x7f, 0x7f)) // impossible method_ids_off
            }
            DexStringScanner.scan("classes.dex", file)
        } finally {
            file.delete()
        }
    }



    private fun mutf8Dex(): File {
        // DEX MUTF-8 for "A\u0000Ж": UTF-16 units=3, bytes 41 C0 80 D0 96, terminator 00.
        val headerSize = 0x70
        val stringIdsOff = headerSize
        val stringDataOff = headerSize + 4
        val payload = byteArrayOf(0x03, 0x41, 0xC0.toByte(), 0x80.toByte(), 0xD0.toByte(), 0x96.toByte(), 0x00)
        val total = stringDataOff + payload.size
        val bytes = ByteArray(total)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
        b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
        b.position(0x38); b.putInt(1); b.putInt(stringIdsOff)
        b.putInt(stringIdsOff, stringDataOff)
        payload.copyInto(bytes, stringDataOff)
        return File.createTempFile("mutf8", ".dex").apply { writeBytes(bytes) }
    }

    private fun indexedNativeDex(): File {
        val strings = listOf(
            "Lcom/example/NativeBridge;",
            "Ljava/lang/Object;",
            "V",
            "nativeCheck",
        )
        val headerSize = 0x70
        val stringIdsOff = headerSize
        val typeIdsOff = stringIdsOff + strings.size * 4
        val protoIdsOff = typeIdsOff + 3 * 4
        val methodIdsOff = protoIdsOff + 12
        val classDefsOff = methodIdsOff + 8
        val classDataOff = classDefsOff + 32
        val classData = byteArrayOf(
            0x00, // static fields
            0x00, // instance fields
            0x01, // direct methods
            0x00, // virtual methods
            0x00, // method_idx_diff = 0
            0x81.toByte(), 0x02, // access_flags = public | native = 0x101
            0x00, // code_off = 0
        )
        val stringDataOff = classDataOff + classData.size
        val stringData = mutableListOf<Byte>()
        val stringOffsets = mutableListOf<Int>()
        for (value in strings) {
            stringOffsets += stringDataOff + stringData.size
            require(value.length < 0x80)
            stringData += value.length.toByte()
            value.toByteArray(Charsets.UTF_8).forEach { stringData += it }
            stringData += 0
        }
        val total = stringDataOff + stringData.size
        val bytes = ByteArray(total)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
        b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
        b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff)
        b.putInt(3); b.putInt(typeIdsOff)
        b.putInt(1); b.putInt(protoIdsOff)
        b.putInt(0); b.putInt(0) // field_ids
        b.putInt(1); b.putInt(methodIdsOff)
        b.putInt(1); b.putInt(classDefsOff)
        stringOffsets.forEachIndexed { i, off -> b.putInt(stringIdsOff + i * 4, off) }
        // type_ids: class, super, void
        b.putInt(typeIdsOff + 0, 0)
        b.putInt(typeIdsOff + 4, 1)
        b.putInt(typeIdsOff + 8, 2)
        // proto: shorty string V, return type V, no params
        b.putInt(protoIdsOff + 0, 2)
        b.putInt(protoIdsOff + 4, 2)
        b.putInt(protoIdsOff + 8, 0)
        // method_id: class_idx=0, proto_idx=0, name_idx=3
        b.putShort(methodIdsOff + 0, 0)
        b.putShort(methodIdsOff + 2, 0)
        b.putInt(methodIdsOff + 4, 3)
        // class_def
        b.putInt(classDefsOff + 0, 0)
        b.putInt(classDefsOff + 4, 1)
        b.putInt(classDefsOff + 8, 1)
        b.putInt(classDefsOff + 12, 0)
        b.putInt(classDefsOff + 16, 0xffffffff.toInt())
        b.putInt(classDefsOff + 20, 0)
        b.putInt(classDefsOff + 24, classDataOff)
        b.putInt(classDefsOff + 28, 0)
        classData.forEachIndexed { i, v -> bytes[classDataOff + i] = v }
        stringData.forEachIndexed { i, v -> bytes[stringDataOff + i] = v }
        return File.createTempFile("indexed-native", ".dex").apply { writeBytes(bytes) }
    }

    private fun tempDex(strings: List<String>): File {
        val headerSize = 0x70
        val idsSize = strings.size * 4
        val data = mutableListOf<Byte>()
        val offsets = mutableListOf<Int>()
        val base = headerSize + idsSize
        for (value in strings) {
            offsets += base + data.size
            require(value.length < 0x80)
            data += value.length.toByte() // uleb128 UTF-16 length for ASCII fixture
            value.toByteArray(Charsets.UTF_8).forEach { data += it }
            data += 0
        }
        val total = headerSize + idsSize + data.size
        val bytes = ByteArray(total)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
        buffer.position(0x20); buffer.putInt(total)
        buffer.putInt(0x70)
        buffer.putInt(0x12345678)
        buffer.position(0x38); buffer.putInt(strings.size); buffer.putInt(0x70)
        offsets.forEachIndexed { index, offset -> buffer.putInt(0x70 + index * 4, offset) }
        data.forEachIndexed { index, value -> bytes[base + index] = value }
        return File.createTempFile("fixture", ".dex").apply { writeBytes(bytes) }
    }
}
