import org.unirevlab.security.analysis.ApkSigningSchemeScanner
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

fun main() {
    val unsigned = ByteArrayOutputStream().also { out ->
        ZipOutputStream(out).use { zip ->
            fun add(name:String, data:String){ zip.putNextEntry(ZipEntry(name)); zip.write(data.toByteArray()); zip.closeEntry() }
            add("AndroidManifest.xml","x")
            add("META-INF/MANIFEST.MF","Manifest-Version: 1.0")
            add("META-INF/CERT.SF","Signature-Version: 1.0")
            add("META-INF/CERT.RSA","fixture")
        }
    }.toByteArray()
    val signed = injectBlock(unsigned, listOf(ApkSigningSchemeScanner.APK_SIGNATURE_SCHEME_V2_BLOCK_ID, ApkSigningSchemeScanner.APK_SIGNATURE_SCHEME_V3_BLOCK_ID, ApkSigningSchemeScanner.APK_SIGNATURE_SCHEME_V31_BLOCK_ID))
    val f=File.createTempFile("unirevlab-signing-", ".apk"); f.writeBytes(signed)
    val s=ApkSigningSchemeScanner.scan(f)
    check(s.schemes.containsAll(listOf("V1_JAR","V2","V3","V3.1"))) { s }
    check(s.signingBlockIds.size==3)
    check(s.v1SignatureFiles.any{it.endsWith("CERT.RSA")})
    f.delete()
    println("APK signing scheme smoke: PASS; ${s.schemes}")
}

private fun injectBlock(zip:ByteArray, ids:List<Long>):ByteArray{
    val eocd=findEocd(zip); val cd=u32(zip,eocd+16).toInt()
    val pairs=ByteArrayOutputStream()
    for(id in ids){ put64(pairs,4); put32(pairs,id); }
    val size=8L+pairs.size()+24L-8L // bytes after first size field: pairs + footer(size+magic)
    val block=ByteArrayOutputStream(); put64(block,size); block.write(pairs.toByteArray()); put64(block,size); block.write("APK Sig Block 42".toByteArray())
    val inserted=block.toByteArray()
    val out=ByteArray(zip.size+inserted.size)
    System.arraycopy(zip,0,out,0,cd); System.arraycopy(inserted,0,out,cd,inserted.size); System.arraycopy(zip,cd,out,cd+inserted.size,zip.size-cd)
    val newEocd=eocd+inserted.size; write32(out,newEocd+16,(cd+inserted.size).toLong())
    return out
}
private fun findEocd(b:ByteArray):Int{for(i in b.size-22 downTo 0)if(u32(b,i)==0x06054b50L)return i; error("EOCD")}
private fun u32(b:ByteArray,o:Int):Long=(b[o].toLong()and 255)or((b[o+1].toLong()and 255)shl 8)or((b[o+2].toLong()and 255)shl 16)or((b[o+3].toLong()and 255)shl 24)
private fun put32(o:ByteArrayOutputStream,v:Long){repeat(4){o.write(((v ushr(it*8))and 255).toInt())}}
private fun put64(o:ByteArrayOutputStream,v:Long){repeat(8){o.write(((v ushr(it*8))and 255).toInt())}}
private fun write32(b:ByteArray,o:Int,v:Long){repeat(4){b[o+it]=((v ushr(it*8))and 255).toByte()}}
