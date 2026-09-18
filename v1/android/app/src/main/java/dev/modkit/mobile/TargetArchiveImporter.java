package dev.modkit.mobile;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Imports a single APK or a ZIP-style APK set (.apk+, .apks, .xapk, .apkm, .zip). */
final class TargetArchiveImporter {
    interface Progress { void progress(String text); }
    static final class Result {
        final boolean apkSet;
        final JSONObject manifest;
        final String summary;
        Result(boolean apkSet,JSONObject manifest,String summary){this.apkSet=apkSet;this.manifest=manifest;this.summary=summary;}
    }
    private TargetArchiveImporter(){}

    static Result importSelected(Context context,File selected,String display,File filesDir,AtomicBoolean cancelled,Progress progress)throws Exception{
        if(selected==null||!selected.isFile()||selected.length()<=0)throw new IOException("Выбран пустой или недоступный файл");
        if(isApk(selected)){
            File installed=new File(filesDir,"installed-apks");deleteTree(installed);
            copy(selected,new File(filesDir,"game.apk"),cancelled);
            return new Result(false,null,"APK готов: "+display);
        }
        List<String> entries=apkEntries(selected);
        if(entries.isEmpty())throw new IOException("Файл не является APK и не содержит APK-set (.apk+/.apks/.xapk/.apkm/ZIP)");
        entries=selectCoherentSet(entries);
        if(entries.isEmpty())throw new IOException("В архиве не найден пригодный APK-set");
        int baseIndex=findBase(entries);String baseEntry=entries.get(baseIndex);
        ArrayList<String> ordered=new ArrayList<>();ordered.add(baseEntry);for(String e:entries)if(!e.equals(baseEntry))ordered.add(e);

        File installed=new File(filesDir,"installed-apks");deleteTree(installed);if(!installed.mkdirs()&&!installed.isDirectory())throw new IOException("Не удалось создать installed-apks");
        JSONArray splits=new JSONArray();File baseFile=null;
        try(ZipFile archive=new ZipFile(selected)){
            for(int i=0;i<ordered.size();i++){
                check(cancelled);String entryName=ordered.get(i);ZipEntry entry=archive.getEntry(entryName);if(entry==null||entry.isDirectory())throw new IOException("APK entry отсутствует: "+entryName);
                String name=i==0?"base.apk":String.format(Locale.ROOT,"split-%03d-%s",i,safe(new File(entryName).getName()));File out=new File(installed,name);
                if(progress!=null)progress.progress("Импорт APK-set: "+(i+1)+"/"+ordered.size()+" · "+entryName);
                try(InputStream in=new BufferedInputStream(archive.getInputStream(entry));FileOutputStream dest=new FileOutputStream(out)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){check(cancelled);dest.write(buf,0,n);}}
                if(!isApk(out))throw new IOException("Вложенный файл не является APK: "+entryName);
                String hash=sha256(out,cancelled);splits.put(new JSONObject().put("index",i).put("name",name).put("archiveEntry",entryName).put("path",out.getCanonicalPath()).put("size",out.length()).put("sha256",hash).put("dexCount",0).put("nativeCount",0));if(i==0)baseFile=out;
            }
        }
        if(baseFile==null)throw new IOException("Base APK не определён");copy(baseFile,new File(filesDir,"game.apk"),cancelled);

        PackageInfo pi=archiveInfo(context,baseFile);String pkg=pi==null?"":String.valueOf(pi.packageName==null?"":pi.packageName);String versionName=pi==null||pi.versionName==null?"":pi.versionName;long versionCode=pi==null?0L:versionCode(pi);String label=label(context,pi);
        String fp=fingerprint(pkg,versionCode,splits);boolean requiresWholeSetSigning=ordered.size()>1;
        JSONObject target=new JSONObject()
                .put("schema","modkit-target-selection-1.1")
                .put("preparedOnly",true).put("analysisPerformed",false)
                .put("sourceKind","archive-apk-set").put("sourceDisplayName",display==null?selected.getName():display)
                .put("packageName",pkg).put("label",label).put("versionName",versionName).put("versionCode",versionCode)
                .put("targetId",fp.substring(0,24)).put("fingerprintSha256",fp)
                .put("scanCompleteness","COMPLETE").put("expectedApkCount",ordered.size()).put("copiedApkCount",ordered.size())
                .put("copyErrors",new JSONArray()).put("buildMode",requiresWholeSetSigning?"apk-set":"single-apk").put("requiresWholeSetSigning",requiresWholeSetSigning)
                .put("fullIl2cppPair",false).put("pairConfidence","UNSCANNED")
                .put("splits",splits);
        return new Result(true,target,"APK-set готов: "+ordered.size()+" APK"+(pkg.isEmpty()?"":" · "+pkg));
    }

    private static PackageInfo archiveInfo(Context context,File apk){try{return context.getPackageManager().getPackageArchiveInfo(apk.getAbsolutePath(),0);}catch(Exception e){return null;}}
    private static String label(Context context,PackageInfo info){
        if(info==null||info.applicationInfo==null)return "";try{ApplicationInfo ai=info.applicationInfo;ai.sourceDir=ai.publicSourceDir=new File(context.getFilesDir(),"game.apk").getAbsolutePath();CharSequence label=context.getPackageManager().getApplicationLabel(ai);return label==null?"":label.toString();}catch(Exception e){return "";}
    }
    @SuppressWarnings("deprecation") private static long versionCode(PackageInfo info){return Build.VERSION.SDK_INT>=Build.VERSION_CODES.P?info.getLongVersionCode():(long)info.versionCode;}

    static boolean isApk(File file){
        try(ZipFile zip=new ZipFile(file)){ZipEntry manifest=zip.getEntry("AndroidManifest.xml");return manifest!=null&&!manifest.isDirectory();}catch(Exception e){return false;}
    }
    private static List<String> apkEntries(File archive)throws IOException{
        ArrayList<String> all=new ArrayList<>();try(ZipFile zip=new ZipFile(archive)){Enumeration<? extends ZipEntry> it=zip.entries();while(it.hasMoreElements()){ZipEntry e=it.nextElement();if(e.isDirectory())continue;String n=e.getName();if(n.toLowerCase(Locale.ROOT).endsWith(".apk"))all.add(n);}}Collections.sort(all,String.CASE_INSENSITIVE_ORDER);return all;
    }
    private static List<String> selectCoherentSet(List<String> all){
        ArrayList<String> splitDir=new ArrayList<>();for(String n:all){String lower=n.toLowerCase(Locale.ROOT);if(lower.startsWith("splits/")||lower.contains("/splits/"))splitDir.add(n);}if(splitDir.size()>1)return splitDir;
        ArrayList<String> nonStandalone=new ArrayList<>();for(String n:all){String lower=n.toLowerCase(Locale.ROOT);if(lower.startsWith("standalones/")||lower.contains("/standalones/"))continue;nonStandalone.add(n);}return nonStandalone.isEmpty()?all:nonStandalone;
    }
    private static int findBase(List<String> entries){int best=0,bestScore=Integer.MIN_VALUE;for(int i=0;i<entries.size();i++){String base=new File(entries.get(i)).getName().toLowerCase(Locale.ROOT);int score;if(base.equals("base.apk"))score=1000;else if(base.equals("base-master.apk"))score=950;else if(base.startsWith("base-master"))score=900;else if(base.startsWith("base")&&!base.contains("config"))score=850;else if(base.contains("master"))score=800;else if(base.contains("config")||base.startsWith("split_config")||base.contains("arm64")||base.contains("armeabi")||base.contains("x86")||base.contains("dpi"))score=100;else score=500;if(score>bestScore){bestScore=score;best=i;}}return best;}
    private static String safe(String value){String s=value==null?"split.apk":value.replaceAll("[^A-Za-z0-9._-]+","_");return s.isEmpty()?"split.apk":s;}
    private static void check(AtomicBoolean cancelled)throws java.io.InterruptedIOException{if((cancelled!=null&&cancelled.get())||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("cancelled");}
    private static void copy(File source,File dest,AtomicBoolean cancelled)throws Exception{try(FileInputStream in=new FileInputStream(source);FileOutputStream out=new FileOutputStream(dest)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){check(cancelled);out.write(buf,0,n);}}}
    private static String sha256(File file,AtomicBoolean cancelled)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(FileInputStream in=new FileInputStream(file)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){check(cancelled);d.update(buf,0,n);}}StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b));return s.toString();}
    private static String fingerprint(String pkg,long versionCode,JSONArray splits)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");d.update((pkg==null?"":pkg).getBytes(StandardCharsets.UTF_8));d.update((byte)0);d.update(Long.toString(versionCode).getBytes(StandardCharsets.US_ASCII));for(int i=0;i<splits.length();i++){JSONObject row=splits.getJSONObject(i);d.update((byte)0);d.update(row.optString("name","").getBytes(StandardCharsets.UTF_8));d.update((byte)0);d.update(row.optString("sha256","").getBytes(StandardCharsets.US_ASCII));}StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b));return s.toString();}
    private static void deleteTree(File file)throws IOException{if(file==null||!file.exists())return;if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);}if(!file.delete()&&file.exists())throw new IOException("Не удалось очистить "+file.getName());}
}