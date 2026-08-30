import org.unirevlab.security.analysis.NetworkSecurityConfigScanner
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private const val NO=-1
private const val XML=3
private const val SP=1
private const val START=0x0102
private const val END=0x0103

data class A(val ns:Int,val name:Int,val raw:Int,val type:Int,val data:Int)

fun main(){
    val strings=listOf("network-security-config","base-config","cleartextTrafficPermitted","trust-anchors","certificates","src","user","debug-overrides","pin-set")
    val chunks=listOf(
        start(0, emptyList()),
        start(1,listOf(A(NO,2,NO,0x12,1))),
        start(3,emptyList()), start(4,listOf(A(NO,5,6,0x03,6))), end(4), end(3),
        start(8,emptyList()), end(8),
        end(1), end(0)
    )
    val pool=pool(strings); val total=8+pool.size+chunks.sumOf{it.size}; val xml=ArrayList<Byte>();p16(xml,XML);p16(xml,8);p32(xml,total);xml.addAll(pool.toList());chunks.forEach{xml.addAll(it.toList())}
    val apk=File.createTempFile("unirevlab-nsc-", ".apk")
    ZipOutputStream(apk.outputStream()).use { z -> z.putNextEntry(ZipEntry("res/xml/network_security_config.xml"));z.write(xml.toByteArray());z.closeEntry() }
    val s=checkNotNull(NetworkSecurityConfigScanner.scan(apk,"@0x7f120001"))
    check(s.baseCleartextTrafficPermitted==true)
    check(s.trustAnchors.any{it.source=="user"&&!it.inDebugOverrides})
    check(s.pinSetPresent)
    check(s.configEntries==listOf("res/xml/network_security_config.xml"))
    apk.delete()
    println("network security config smoke: PASS")
}
private fun pool(ss:List<String>):ByteArray{val h=28;val start=h+ss.size*4;val payload=ArrayList<Byte>();val offs=ArrayList<Int>();for(s in ss){offs+=payload.size;payload+=s.length.toByte();payload+=s.toByteArray().size.toByte();payload.addAll(s.toByteArray().toList());payload+=0};while(payload.size%4!=0)payload+=0;val o=ArrayList<Byte>();p16(o,SP);p16(o,h);p32(o,start+payload.size);p32(o,ss.size);p32(o,0);p32(o,0x100);p32(o,start);p32(o,0);offs.forEach{p32(o,it)};o.addAll(payload);return o.toByteArray()}
private fun start(name:Int,a:List<A>):ByteArray{val o=ArrayList<Byte>();val sz=16+20+a.size*20;p16(o,START);p16(o,16);p32(o,sz);p32(o,1);p32(o,NO);p32(o,NO);p32(o,name);p16(o,20);p16(o,20);p16(o,a.size);p16(o,0);p16(o,0);p16(o,0);for(x in a){p32(o,x.ns);p32(o,x.name);p32(o,x.raw);p16(o,8);o+=0;o+=x.type.toByte();p32(o,x.data)};return o.toByteArray()}
private fun end(name:Int):ByteArray{val o=ArrayList<Byte>();p16(o,END);p16(o,16);p32(o,24);p32(o,1);p32(o,NO);p32(o,NO);p32(o,name);return o.toByteArray()}
private fun p16(o:MutableList<Byte>,v:Int){o+=(v and 255).toByte();o+=((v ushr 8)and 255).toByte()}
private fun p32(o:MutableList<Byte>,v:Int){repeat(4){o+=((v ushr(it*8))and 255).toByte()}}
