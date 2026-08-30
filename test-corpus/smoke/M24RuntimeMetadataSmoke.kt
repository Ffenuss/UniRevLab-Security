import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.unirevlab.security.analysis.RuntimeArtifactScanner
import org.unirevlab.security.analysis.SupplyChainScanner
import org.unirevlab.security.model.*

private fun managedAssembly(): ByteArray {
    val bytes = ByteArray(0x700); val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    bytes[0]='M'.code.toByte(); bytes[1]='Z'.code.toByte(); b.putInt(0x3c,0x80)
    bytes[0x80]='P'.code.toByte(); bytes[0x81]='E'.code.toByte(); b.putShort(0x84,0x14c.toShort()); b.putShort(0x86,1); b.putShort(0x94,0xE0.toShort())
    val opt=0x98; b.putShort(opt,0x10b.toShort()); b.putInt(opt+92,16)
    val cliDir=opt+96+14*8; b.putInt(cliDir,0x2000); b.putInt(cliDir+4,0x48)
    val sec=opt+0xE0; b.putInt(sec+8,0x500); b.putInt(sec+12,0x2000); b.putInt(sec+16,0x500); b.putInt(sec+20,0x200)
    val cli=0x200; b.putInt(cli,0x48); b.putInt(cli+8,0x2080); b.putInt(cli+12,0x180)
    val md=0x280; b.putInt(md,0x424A5342); b.putShort(md+4,1); b.putShort(md+6,1)
    val ver="v4.0.30319\u0000".toByteArray(); b.putInt(md+12,ver.size); ver.copyInto(bytes,md+16)
    val dir=md+28; b.putShort(dir,0); b.putShort(dir+2,1)
    b.putInt(dir+4,0x40); b.putInt(dir+8,0x60); "#~\u0000".toByteArray().copyInto(bytes,dir+12)
    val t=md+0x40; b.putInt(t,0); bytes[t+4]=2; bytes[t+5]=0; bytes[t+6]=0; bytes[t+7]=1
    val valid=(1L shl 2) or (1L shl 6) or (1L shl 10) or (1L shl 32) or (1L shl 35)
    b.putLong(t+8,valid); b.putLong(t+16,0)
    var c=t+24; listOf(3,9,5,1,4).forEach { b.putInt(c,it); c+=4 }
    "Assembly-CSharp.dll\u0000Game.PlayerController\u0000".toByteArray().copyInto(bytes,md+0xB0)
    return bytes
}
private fun native(): NativeSummary {
    fun lib(name:String, needed:List<String> = emptyList())=NativeLibrarySummary("lib/arm64-v8a/$name","arm64-v8a","ELF64","AARCH64","DYN",1,null,needed,emptyList(),emptyList(),emptyList(),false,false,false,true,true,true,true,emptyList())
    val libs=listOf(lib("libflutter.so",listOf("libc.so")),lib("libapp.so"),lib("libmono.so"),lib("libunity.so"),lib("libUnreal.so"))
    return NativeSummary(libs.size,libs.size,libs,parseErrors=0,truncated=false)
}
fun main(){
    val apk=File.createTempFile("m24-runtime", ".apk")
    ZipOutputStream(apk.outputStream()).use { z ->
        fun e(n:String,b:ByteArray){z.putNextEntry(ZipEntry(n));z.write(b);z.closeEntry()}
        e("assets/flutter_assets/AssetManifest.bin", byteArrayOf(1))
        e("assets/flutter_assets/vm_snapshot_data", "snapshot-data".toByteArray())
        e("assets/bin/Data/Managed/Assembly-CSharp.dll", managedAssembly())
        e("assets/Game/Paks/chunk0.pak", ByteArray(64){it.toByte()})
    }
    val r=requireNotNull(RuntimeArtifactScanner.scanApk(apk,native()))
    check(r.flutter!!.artifactFingerprints.single().sha256.length==64)
    val a=r.unityMono!!.assemblies.single(); check(a.metadataStreams.any{it.name=="#~"})
    check(a.metadataTables.first{it.name=="TypeDef"}.rowCount==3L); check(a.metadataTables.first{it.name=="MethodDef"}.rowCount==9L)
    check(r.unreal!!.containers.single().probeSha256?.length==64)
    val dex=DexSummary(1,1,0,0,classes=listOf(DexClassReference("classes.dex",0,"Lokhttp3/OkHttpClient;",null,1)),httpUrls=emptyList(),httpsUrls=emptyList(),secretCandidates=emptyList(),parseErrors=0,truncated=false)
    val sc=SupplyChainScanner.scan(apk,dex,native(),null,r); check(sc.components.any{it.name=="OkHttp"}); check("libc.so" in sc.nativeDependencies)
    println("M2.4 runtime metadata + supply chain smoke PASS")
    apk.delete()
}
