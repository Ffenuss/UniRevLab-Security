package dev.modkit.mobile;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Magic-first file classifier used by File Workspace. */
final class FileFormatDetector {
    enum Kind { TEXT, JSON, XML, YAML, TOML, INI, PROPERTIES, DEX, ELF, APK_ZIP, ZIP, AXML, ARSC, SQLITE, PNG, JPEG, WEBP, UNITY_BUNDLE, UNITY_ASSET, IL2CPP_METADATA, BINARY }
    static final class Result {
        final Kind kind;final String label;final boolean textEditable;final boolean defaultHex;final String route;
        Result(Kind kind,String label,boolean textEditable,boolean defaultHex,String route){this.kind=kind;this.label=label;this.textEditable=textEditable;this.defaultHex=defaultHex;this.route=route;}
    }
    private FileFormatDetector(){}

    static Result detect(String path,byte[] data){
        String name=path==null?"":path.toLowerCase(Locale.ROOT);int n=data==null?0:data.length;
        // Binary magic always wins over an extension or printable-byte heuristic.
        if(n>=8&&data[0]=='d'&&data[1]=='e'&&data[2]=='x'&&data[3]=='\n')return r(Kind.DEX,"Android DEX",false,true,"Decompiler · Java/Smali");
        if(n>=4&&data[0]==0x7f&&data[1]=='E'&&data[2]=='L'&&data[3]=='F')return r(Kind.ELF,"ELF native library",false,true,"Native Workspace");
        if(n>=16&&starts(data,"SQLite format 3\0"))return r(Kind.SQLITE,"SQLite database",false,true,"SQLite structure");
        if(n>=8&&(data[0]&255)==0x89&&data[1]=='P'&&data[2]=='N'&&data[3]=='G')return r(Kind.PNG,"PNG image",false,true,"Image preview/metadata");
        if(n>=3&&(data[0]&255)==0xff&&(data[1]&255)==0xd8&&(data[2]&255)==0xff)return r(Kind.JPEG,"JPEG image",false,true,"Image preview/metadata");
        if(n>=12&&starts(data,"RIFF")&&ascii(data,8,4).equals("WEBP"))return r(Kind.WEBP,"WebP image",false,true,"Image preview/metadata");
        if(n>=7&&starts(data,"UnityFS"))return r(Kind.UNITY_BUNDLE,"UnityFS bundle",false,true,"Unity bundle inspector");
        if(n>=4&&le32(data,0)==0xFAB11BAFL)return r(Kind.IL2CPP_METADATA,"IL2CPP global-metadata",false,true,"RE Workspace / metadata inspector");
        if(n>=4&&u16(data,0)==0x0003&&u16(data,2)==0x0008)return r(Kind.AXML,"Android binary XML",false,true,"Decoded AXML");
        if(n>=4&&u16(data,0)==0x0002&&(u16(data,2)==0x000c||u16(data,2)==0x0008))return r(Kind.ARSC,"Android resources table",false,true,"Resources inspector");
        if(n>=4&&data[0]=='P'&&data[1]=='K'&&((data[2]==3&&data[3]==4)||(data[2]==5&&data[3]==6)||(data[2]==7&&data[3]==8))){boolean apk=name.endsWith(".apk")||name.contains("androidmanifest.xml");return r(apk?Kind.APK_ZIP:Kind.ZIP,apk?"APK/ZIP container":"ZIP container",false,true,"Archive tree");}
        if(name.endsWith(".assets")||name.endsWith(".resource")||name.endsWith(".ress")||name.endsWith(".lpak")||name.contains("globalgamemanagers"))return r(Kind.UNITY_ASSET,"Unity asset/data",false,true,"Unity asset inspector");

        boolean text=looksText(data);
        if(text){
            String trimmed=new String(data,0,Math.min(n,8192),StandardCharsets.UTF_8).trim();
            if(trimmed.startsWith("{")||trimmed.startsWith("[")){
                // A .toml/.ini file can legitimately begin with [section], so an explicit
                // textual extension takes precedence over JSON's broad '[' heuristic.
                if(name.endsWith(".toml"))return r(Kind.TOML,"TOML text",true,false,"Text editor");
                if(name.endsWith(".ini")||name.endsWith(".cfg"))return r(Kind.INI,"INI/config text",true,false,"Text editor");
                return r(Kind.JSON,"JSON text",true,false,"Text editor");
            }
            if(trimmed.startsWith("<?xml")||trimmed.startsWith("<manifest")||trimmed.startsWith("<resources")||name.endsWith(".xml"))return r(Kind.XML,"XML text",true,false,"Text editor");
            if(name.endsWith(".yaml")||name.endsWith(".yml")||trimmed.startsWith("---\n")||trimmed.startsWith("%YAML"))return r(Kind.YAML,"YAML text",true,false,"Text editor");
            if(name.endsWith(".toml"))return r(Kind.TOML,"TOML text",true,false,"Text editor");
            if(name.endsWith(".ini")||name.endsWith(".cfg"))return r(Kind.INI,"INI/config text",true,false,"Text editor");
            if(name.endsWith(".properties")||name.endsWith("gradle.properties"))return r(Kind.PROPERTIES,"Java/Gradle properties",true,false,"Text editor");
            return r(Kind.TEXT,"UTF-8 text",true,false,"Text editor");
        }
        return r(Kind.BINARY,"Binary",false,true,"HEX/strings");
    }
    private static Result r(Kind k,String label,boolean text,boolean hex,String route){return new Result(k,label,text,hex,route);}
    static boolean looksText(byte[] b){int n=Math.min(b==null?0:b.length,8192),bad=0;if(n==0)return true;for(int i=0;i<n;i++){int v=b[i]&255;if(v==0)return false;if(v<9||(v>13&&v<32))bad++;}return bad<n/30+1;}
    private static boolean starts(byte[] b,String s){byte[] x=s.getBytes(StandardCharsets.US_ASCII);if(b.length<x.length)return false;for(int i=0;i<x.length;i++)if(b[i]!=x[i])return false;return true;}
    private static String ascii(byte[] b,int off,int len){if(off<0||off+len>b.length)return "";return new String(b,off,len,StandardCharsets.US_ASCII);}
    private static int u16(byte[] b,int off){if(off+2>b.length)return-1;return(b[off]&255)|((b[off+1]&255)<<8);}
    private static long le32(byte[] b,int off){if(off+4>b.length)return-1;return((long)b[off]&255)|(((long)b[off+1]&255)<<8)|(((long)b[off+2]&255)<<16)|(((long)b[off+3]&255)<<24);}
}
