package dev.modkit.mobile;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Small bounded structural summaries for binary files opened in File Workspace. */
final class BinaryFormatInspector {
    private BinaryFormatInspector(){}

    static String inspect(FileFormatDetector.Result format,byte[] data,String name){
        if(format==null)return "";try{
            switch(format.kind){
                case DEX:return dex(data);
                case ELF:return elf(data);
                case IL2CPP_METADATA:return metadata(data);
                case SQLITE:return sqlite(data);
                case PNG:return png(data);
                case JPEG:return "JPEG image · "+data.length+" bytes";
                case WEBP:return webp(data);
                case UNITY_BUNDLE:return unity(data);
                case AXML:return "Android Binary XML · "+data.length+" bytes · use decoded resources/Apktool for semantic editing";
                case ARSC:return "Android resources.arsc · "+data.length+" bytes · use Resources/Apktool workspace for decoded values";
                case APK_ZIP:return "APK/ZIP container · "+data.length+" bytes · open as target/archive rather than editing container bytes directly";
                case ZIP:return "ZIP container · "+data.length+" bytes";
                case UNITY_ASSET:return "Unity asset/data · "+data.length+" bytes · use RE Workspace for Unity/Addressables correlation";
                case BINARY:return stringsSummary(data);
                default:return format.label+" · "+data.length+" bytes";
            }
        }catch(Throwable e){return format.label+" · "+data.length+" bytes · inspector: "+e.getClass().getSimpleName();}
    }

    private static String dex(byte[] b){
        if(b.length<112)return "DEX · truncated header · "+b.length+" bytes";
        String version=new String(b,4,3,StandardCharsets.US_ASCII);long fileSize=u32(b,32),headerSize=u32(b,36),endian=u32(b,40);long strings=u32(b,56),types=u32(b,64),protos=u32(b,72),fields=u32(b,80),methods=u32(b,88),classes=u32(b,96),dataSize=u32(b,104);
        return "Android DEX v"+version+" · bytes "+b.length+"\nfile_size="+fileSize+" · header_size="+headerSize+" · endian=0x"+Long.toHexString(endian)+"\nstring_ids="+strings+" · type_ids="+types+" · proto_ids="+protos+" · field_ids="+fields+" · method_ids="+methods+" · class_defs="+classes+" · data_size="+dataSize+"\nДля Java/Smali используйте Decompiler; HEX остаётся доступен для точного byte-level редактирования.";
    }
    private static String elf(byte[] b){
        if(b.length<20)return "ELF · truncated header · "+b.length+" bytes";int cls=b[4]&255,endian=b[5]&255;boolean little=endian==1;int machine=little?u16(b,18):be16(b,18);String arch=machine==183?"AArch64":machine==40?"ARM":machine==62?"x86_64":machine==3?"x86":"machine="+machine;return "ELF"+(cls==2?"64":cls==1?"32":"?")+" · "+arch+" · "+(little?"little-endian":"big-endian")+" · "+b.length+" bytes\nДля symbols/disassembly/RVA/xrefs используйте Native Workspace; HEX доступен для точной рабочей копии.";
    }
    private static String metadata(byte[] b){long version=b.length>=8?u32(b,4):-1;return "IL2CPP global-metadata.dat · version "+version+" · "+b.length+" bytes\nMagic FAB11BAF подтверждён. Для classes/fields/methods/token/RVA correlation используйте RE Workspace.";}
    private static String sqlite(byte[] b){long page=b.length>=18?u16(b,16):-1;if(page==1)page=65536;return "SQLite format 3 · "+b.length+" bytes · page_size="+page+"\nБинарное редактирование в HEX рискованно; структурный просмотр таблиц будет использовать отдельный SQLite viewer.";}
    private static String png(byte[] b){long w=b.length>=24?be32(b,16):-1,h=b.length>=24?be32(b,20):-1;return "PNG · "+w+"×"+h+" · "+b.length+" bytes";}
    private static String webp(byte[] b){String subtype=b.length>=16?new String(b,12,4,StandardCharsets.US_ASCII):"?";return "WebP "+subtype+" · "+b.length+" bytes";}
    private static String unity(byte[] b){int end=0;while(end<b.length&&end<64&&b[end]!=0)end++;String sig=new String(b,0,end,StandardCharsets.US_ASCII);return sig+" Unity bundle · "+b.length+" bytes\nДля Addressables/bundle ownership/serialized assets используйте RE Workspace.";}
    private static String stringsSummary(byte[] b){int hits=0;StringBuilder out=new StringBuilder("Binary · ").append(b.length).append(" bytes");StringBuilder current=new StringBuilder();for(int i=0;i<Math.min(b.length,256*1024)&&hits<12;i++){int v=b[i]&255;if(v>=32&&v<=126){current.append((char)v);if(current.length()>160)current.delete(0,current.length()-160);}else{if(current.length()>=6){out.append("\n• ").append(current);hits++;}current.setLength(0);}}return out.toString();}
    private static int u16(byte[] b,int o){return(b[o]&255)|((b[o+1]&255)<<8);}private static int be16(byte[] b,int o){return((b[o]&255)<<8)|(b[o+1]&255);}private static long u32(byte[] b,int o){return((long)b[o]&255)|(((long)b[o+1]&255)<<8)|(((long)b[o+2]&255)<<16)|(((long)b[o+3]&255)<<24);}private static long be32(byte[] b,int o){return(((long)b[o]&255)<<24)|(((long)b[o+1]&255)<<16)|(((long)b[o+2]&255)<<8)|((long)b[o+3]&255);}
}