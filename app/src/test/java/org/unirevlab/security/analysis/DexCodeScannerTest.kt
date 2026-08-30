package org.unirevlab.security.analysis

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DexCodeScannerTest {
    @Test
    fun buildsBoundedMethodStringAndTypeXrefs() {
        val file = fixtureDex()
        try {
            val scan = DexCodeScanner.scan("classes.dex", file)
            assertEquals("caller", scan.codeMethods.single().name)
            assertEquals("callee", scan.callXrefs.single().calleeName)
            assertEquals("http://code.invalid/path", scan.stringXrefs.single().value)
            assertEquals("CONST_CLASS", scan.typeXrefs.single().kind)
            assertEquals(0, scan.decodeErrors)
            assertTrue(!scan.truncated)
        } finally {
            file.delete()
        }
    }

    private fun uleb(value: Int): ByteArray {
        var v = value
        val out = mutableListOf<Byte>()
        do {
            var b = v and 0x7f
            v = v ushr 7
            if (v != 0) b = b or 0x80
            out += b.toByte()
        } while (v != 0)
        return out.toByteArray()
    }

    private fun fixtureDex(): File {
        val strings = listOf(
            "Lcom/example/CodeBridge;", "Ljava/lang/Object;", "V", "caller", "callee",
            "http://code.invalid/path?token=must-not-persist",
        )
        val headerSize = 0x70
        val stringIdsOff = headerSize
        val typeIdsOff = stringIdsOff + strings.size * 4
        val protoIdsOff = typeIdsOff + 3 * 4
        val methodIdsOff = protoIdsOff + 12
        val classDefsOff = methodIdsOff + 16
        val classDataOff = classDefsOff + 32
        var classData = byteArrayOf()
        var codeOff = 0
        repeat(4) {
            val body = mutableListOf<Byte>()
            body += byteArrayOf(0, 0, 2, 0).toList()
            body += uleb(0).toList(); body += uleb(1).toList(); body += uleb(codeOff).toList()
            body += uleb(1).toList(); body += uleb(1).toList(); body += uleb(0).toList()
            classData = body.toByteArray()
            codeOff = (classDataOff + classData.size + 3) and -4
        }
        val stringDataOff = codeOff + 16 + 8 * 2
        val data = mutableListOf<Byte>()
        val offsets = mutableListOf<Int>()
        for (value in strings) {
            offsets += stringDataOff + data.size
            data += value.length.toByte(); value.toByteArray().forEach { data += it }; data += 0
        }
        val total = stringDataOff + data.size
        val bytes = ByteArray(total)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
        b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
        b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff)
        b.putInt(3); b.putInt(typeIdsOff); b.putInt(1); b.putInt(protoIdsOff)
        b.putInt(0); b.putInt(0); b.putInt(2); b.putInt(methodIdsOff); b.putInt(1); b.putInt(classDefsOff)
        offsets.forEachIndexed { i, off -> b.putInt(stringIdsOff + i * 4, off) }
        b.putInt(typeIdsOff, 0); b.putInt(typeIdsOff + 4, 1); b.putInt(typeIdsOff + 8, 2)
        b.putInt(protoIdsOff, 2); b.putInt(protoIdsOff + 4, 2); b.putInt(protoIdsOff + 8, 0)
        b.putShort(methodIdsOff, 0); b.putShort(methodIdsOff + 2, 0); b.putInt(methodIdsOff + 4, 3)
        b.putShort(methodIdsOff + 8, 0); b.putShort(methodIdsOff + 10, 0); b.putInt(methodIdsOff + 12, 4)
        b.putInt(classDefsOff, 0); b.putInt(classDefsOff + 4, 1); b.putInt(classDefsOff + 8, 1)
        b.putInt(classDefsOff + 12, 0); b.putInt(classDefsOff + 16, -1); b.putInt(classDefsOff + 20, 0)
        b.putInt(classDefsOff + 24, classDataOff); b.putInt(classDefsOff + 28, 0)
        classData.forEachIndexed { i, v -> bytes[classDataOff + i] = v }
        b.putShort(codeOff, 1); b.putShort(codeOff + 2, 0); b.putShort(codeOff + 4, 0); b.putShort(codeOff + 6, 0)
        b.putInt(codeOff + 8, 0); b.putInt(codeOff + 12, 8)
        intArrayOf(0x001a, 5, 0x0071, 1, 0, 0x001c, 0, 0x000e).forEachIndexed { i, unit ->
            b.putShort(codeOff + 16 + i * 2, unit.toShort())
        }
        data.forEachIndexed { i, v -> bytes[stringDataOff + i] = v }
        return File.createTempFile("dex-code-xref", ".dex").apply { writeBytes(bytes) }
    }
    @Test
    fun buildsFieldCfgAndConstantEvidence() {
        val file = fixtureDexAdvanced()
        try {
            val scan = DexCodeScanner.scan("classes.dex", file)
            assertEquals("STATIC_GET", scan.fieldXrefs.single().kind)
            assertEquals("enabled", scan.fieldXrefs.single().fieldName)
            assertEquals("1", scan.constants.single().value)
            assertTrue(scan.basicBlocks.size >= 2)
            assertTrue(scan.basicBlocks.any { it.terminalKind == "CONDITIONAL" && it.successorCodeUnits.isNotEmpty() })
        } finally { file.delete() }
    }

    private fun fixtureDexAdvanced(): File {
        val strings = listOf("Lcom/example/Cfg;", "Ljava/lang/Object;", "I", "V", "run", "enabled")
        val headerSize=0x70; val stringIdsOff=headerSize; val typeIdsOff=stringIdsOff+strings.size*4
        val protoIdsOff=typeIdsOff+4*4; val fieldIdsOff=protoIdsOff+12; val methodIdsOff=fieldIdsOff+8
        val classDefsOff=methodIdsOff+8; val classDataOff=classDefsOff+32
        var classData=byteArrayOf(); var codeOff=0
        repeat(4) {
            val body=mutableListOf<Byte>(); body += byteArrayOf(0,0,1,0).toList()
            body += uleb(0).toList(); body += uleb(1).toList(); body += uleb(codeOff).toList()
            classData=body.toByteArray(); codeOff=(classDataOff+classData.size+3) and -4
        }
        val units=intArrayOf(0x1012, 0x0060, 0, 0x0038, 2, 0x000e, 0x000e) // const/4 v0,#1; sget v0,field@0; if-eqz v0,+2; return; return
        val stringDataOff=codeOff+16+units.size*2
        val data=mutableListOf<Byte>(); val offsets=mutableListOf<Int>()
        for(v in strings){ offsets += stringDataOff+data.size; data += v.length.toByte(); v.toByteArray().forEach{data+=it}; data+=0 }
        val total=stringDataOff+data.size; val bytes=ByteArray(total); val b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1)); b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
        b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff); b.putInt(4); b.putInt(typeIdsOff); b.putInt(1); b.putInt(protoIdsOff)
        b.putInt(1); b.putInt(fieldIdsOff); b.putInt(1); b.putInt(methodIdsOff); b.putInt(1); b.putInt(classDefsOff)
        offsets.forEachIndexed{i,o->b.putInt(stringIdsOff+i*4,o)}
        b.putInt(typeIdsOff,0); b.putInt(typeIdsOff+4,1); b.putInt(typeIdsOff+8,2); b.putInt(typeIdsOff+12,3)
        b.putInt(protoIdsOff,3); b.putInt(protoIdsOff+4,3); b.putInt(protoIdsOff+8,0)
        b.putShort(fieldIdsOff,0); b.putShort(fieldIdsOff+2,2); b.putInt(fieldIdsOff+4,5)
        b.putShort(methodIdsOff,0); b.putShort(methodIdsOff+2,0); b.putInt(methodIdsOff+4,4)
        b.putInt(classDefsOff,0); b.putInt(classDefsOff+4,1); b.putInt(classDefsOff+8,1); b.putInt(classDefsOff+12,0); b.putInt(classDefsOff+16,-1); b.putInt(classDefsOff+20,0); b.putInt(classDefsOff+24,classDataOff); b.putInt(classDefsOff+28,0)
        classData.forEachIndexed{i,v->bytes[classDataOff+i]=v}
        b.putShort(codeOff,1); b.putShort(codeOff+2,0); b.putShort(codeOff+4,0); b.putShort(codeOff+6,0); b.putInt(codeOff+8,0); b.putInt(codeOff+12,units.size)
        units.forEachIndexed{i,u->b.putShort(codeOff+16+i*2,u.toShort())}; data.forEachIndexed{i,v->bytes[stringDataOff+i]=v}
        return File.createTempFile("dex-cfg-field", ".dex").apply{writeBytes(bytes)}
    }

}
