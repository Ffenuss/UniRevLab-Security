import org.unirevlab.security.analysis.KotlinAxmlManifestParser

private const val NO = -1
private const val RES_XML_TYPE = 0x0003
private const val RES_STRING_POOL_TYPE = 0x0001
private const val START = 0x0102
private const val END = 0x0103

fun main() {
    val strings = listOf(
        "manifest", "application", "fullBackupContent", "false", "networkSecurityConfig", "@0x7f120001",
        "activity", "name", ".MainActivity", "intent-filter", "autoVerify", "true", "action",
        "android.intent.action.VIEW", "category", "android.intent.category.BROWSABLE", "data", "scheme", "https", "host", "example.com",
        "http://schemas.android.com/apk/res/android"
    )
    val ns = 21
    val chunks = listOf(
        start(0, emptyList()),
        start(1, listOf(Attr(ns,2,3,0x03,3), Attr(ns,4,5,0x03,5))),
        start(6, listOf(Attr(ns,7,8,0x03,8))),
        start(9, listOf(Attr(ns,10,11,0x12,1))),
        start(12, listOf(Attr(ns,7,13,0x03,13))), end(12),
        start(14, listOf(Attr(ns,7,15,0x03,15))), end(14),
        start(16, listOf(Attr(ns,17,18,0x03,18), Attr(ns,19,20,0x03,20))), end(16),
        end(9), end(6), end(1), end(0),
    )
    val pool = pool(strings)
    val total = 8 + pool.size + chunks.sumOf { it.size }
    val out = ArrayList<Byte>(total)
    put16(out, RES_XML_TYPE); put16(out, 8); put32(out, total); out.addAll(pool.toList()); chunks.forEach { out.addAll(it.toList()) }
    val overlay = checkNotNull(KotlinAxmlManifestParser.parse(out.toByteArray()))
    check(overlay.fullBackupContentConfigured == false)
    check(overlay.networkSecurityConfigConfigured == true)
    check(overlay.deepLinks.size == 1)
    val link = overlay.deepLinks.single()
    check(link.componentName == ".MainActivity")
    check(link.schemes == listOf("https"))
    check(link.hosts == listOf("example.com"))
    check(link.autoVerify)
    println("kotlin AXML fallback smoke: PASS")
}

private data class Attr(val ns:Int,val name:Int,val raw:Int,val type:Int,val data:Int)
private fun pool(strings: List<String>): ByteArray {
    val header=28; val offsets=strings.size*4; val start=header+offsets
    val payload=ArrayList<Byte>(); val offs=ArrayList<Int>()
    for(s in strings){ offs += payload.size; payload += s.length.toByte(); payload += s.toByteArray().size.toByte(); payload.addAll(s.toByteArray().toList()); payload += 0 }
    while(payload.size%4!=0) payload += 0
    val size=start+payload.size; val o=ArrayList<Byte>(); put16(o,RES_STRING_POOL_TYPE);put16(o,header);put32(o,size);put32(o,strings.size);put32(o,0);put32(o,0x100);put32(o,start);put32(o,0);offs.forEach{put32(o,it)};o.addAll(payload);return o.toByteArray()
}
private fun start(name:Int, attrs:List<Attr>):ByteArray{ val node=16;val ext=20;val asz=20;val size=node+ext+attrs.size*asz;val o=ArrayList<Byte>();put16(o,START);put16(o,node);put32(o,size);put32(o,1);put32(o,NO);put32(o,NO);put32(o,name);put16(o,ext);put16(o,asz);put16(o,attrs.size);put16(o,0);put16(o,0);put16(o,0);for(a in attrs){put32(o,a.ns);put32(o,a.name);put32(o,a.raw);put16(o,8);o+=0;o+=a.type.toByte();put32(o,a.data)};return o.toByteArray() }
private fun end(name:Int):ByteArray{val o=ArrayList<Byte>();put16(o,END);put16(o,16);put32(o,24);put32(o,1);put32(o,NO);put32(o,NO);put32(o,name);return o.toByteArray()}
private fun put16(o:MutableList<Byte>,v:Int){o+=(v and 255).toByte();o+=((v ushr 8) and 255).toByte()}
private fun put32(o:MutableList<Byte>,v:Int){repeat(4){o+=((v ushr (it*8)) and 255).toByte()}}
