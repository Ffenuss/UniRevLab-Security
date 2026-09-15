package dev.modkit.mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Canonical target view shared by every workspace.
 *
 * No consumer should silently assume game.apk == the entire target. When an
 * installed/imported APK set exists, all members are resolved from the manifest.
 */
final class TargetResolver {
    static final class Member {
        final int index;final String name;final File file;final String sha256;final int nativeCount,dexCount;
        Member(int index,String name,File file,String sha256,int nativeCount,int dexCount){this.index=index;this.name=name;this.file=file;this.sha256=sha256;this.nativeCount=nativeCount;this.dexCount=dexCount;}
    }

    static final class Target {
        final App app;final JSONObject manifest;final List<Member> members;final String packageName,targetId,fingerprint;final boolean apkSet;
        Target(App app,JSONObject manifest,List<Member> members,String packageName,String targetId,String fingerprint,boolean apkSet){this.app=app;this.manifest=manifest;this.members=members;this.packageName=packageName;this.targetId=targetId;this.fingerprint=fingerprint;this.apkSet=apkSet;}
        File baseApk(){return members.isEmpty()?app.file("game.apk"):members.get(0).file;}
        List<File> apkFiles(){ArrayList<File> out=new ArrayList<>();for(Member member:members)out.add(member.file);return out;}
        boolean hasManifest(){return manifest!=null;}
        File patchOwnerApk(){
            if(manifest!=null){JSONObject owner=manifest.optJSONObject("patchOwner");if(owner!=null){int idx=owner.optInt("splitIndex",-1);for(Member m:members)if(m.index==idx)return m.file;String path=owner.optString("path","");if(!path.isEmpty()){File f=new File(path);if(f.isFile())return f;}}}
            return baseApk();
        }
        File selectedMetadataCopy(){File f=app.file("metadata.bin");return f.isFile()?f:null;}
        File selectedLibraryCopy(){File f=app.file("library.so");return f.isFile()?f:null;}
    }

    interface Progress { void progress(String text); }
    private TargetResolver(){}

    static Target resolve(App app)throws Exception{
        File manifestFile=app.file("installed-target.json");
        JSONObject manifest=manifestFile.isFile()?new JSONObject(Io.readUtf8(manifestFile)):null;
        ArrayList<Member> members=new ArrayList<>();
        if(manifest!=null){
            JSONArray splits=manifest.optJSONArray("splits");
            if(splits!=null){
                for(int i=0;i<splits.length();i++){
                    JSONObject row=splits.optJSONObject(i);if(row==null)continue;String path=row.optString("path","");if(path.isEmpty())continue;File file=new File(path);if(!file.isFile())throw new IOException("Target split отсутствует: "+row.optString("name",file.getName()));
                    members.add(new Member(row.optInt("index",i),row.optString("name",file.getName()),file,row.optString("sha256",""),row.optInt("nativeCount",0),row.optInt("dexCount",0)));
                }
            }
        }
        if(members.isEmpty()){
            File single=app.file("game.apk");if(!single.isFile())throw new IOException("Target APK не выбран");members.add(new Member(0,single.getName(),single,"",0,0));
        }
        members.sort(Comparator.comparingInt(m->m.index));
        String packageName=manifest==null?"":manifest.optString("packageName","");
        String targetId=manifest==null?"":manifest.optString("targetId","");
        String fingerprint=manifest==null?"":manifest.optString("fingerprintSha256","");
        boolean apkSet=members.size()>1||manifest!=null&&"apk-set".equals(manifest.optString("buildMode"));
        return new Target(app,manifest,members,packageName,targetId,fingerprint,apkSet);
    }

    static File prepareAnalysisContainer(Target target,AtomicBoolean cancelled,Progress progress)throws Exception{
        if(!target.apkSet)return target.baseApk();
        File output=target.app.file("installed-apk-set.zip"),tmp=target.app.file("installed-apk-set.zip.tmp");
        String expected=targetDigest(target,cancelled);File sidecar=target.app.file("installed-apk-set.digest");
        if(output.isFile()&&sidecar.isFile()){
            try{String existing=Io.readUtf8(sidecar).trim();if(expected.equals(existing))return output;}catch(Exception ignored){}
        }
        Files.deleteIfExists(tmp.toPath());
        try(ZipOutputStream zip=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
            zip.setLevel(0);byte[] buffer=new byte[1024*1024];int pos=0;
            for(Member member:target.members){check(cancelled);if(progress!=null)progress.progress("APK-set container: "+(++pos)+"/"+target.members.size()+" · "+member.name);ZipEntry entry=new ZipEntry(member.name);entry.setTime(0L);zip.putNextEntry(entry);try(InputStream in=new BufferedInputStream(new FileInputStream(member.file))){int n;while((n=in.read(buffer))!=-1){check(cancelled);zip.write(buffer,0,n);}}zip.closeEntry();}
        }catch(Throwable e){Files.deleteIfExists(tmp.toPath());throw e;}
        Files.move(tmp.toPath(),output.toPath(),StandardCopyOption.REPLACE_EXISTING);Files.write(sidecar.toPath(),expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));return output;
    }

    static String targetDigest(Target target,AtomicBoolean cancelled)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[1024*1024];
        for(Member member:target.members){check(cancelled);digest.update(Integer.toString(member.index).getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);digest.update(member.name.getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);if(member.sha256!=null&&!member.sha256.isEmpty())digest.update(member.sha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII));else try(FileInputStream in=new FileInputStream(member.file)){int n;while((n=in.read(buffer))!=-1){check(cancelled);digest.update(buffer,0,n);}}}
        StringBuilder out=new StringBuilder();for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }

    static JSONObject describe(Target target){
        JSONObject out=new JSONObject();JSONArray members=new JSONArray();try{out.put("schema","modkit-target-resolver-1.0").put("packageName",target.packageName).put("targetId",target.targetId).put("fingerprintSha256",target.fingerprint).put("apkSet",target.apkSet).put("memberCount",target.members.size());for(Member member:target.members)members.put(new JSONObject().put("index",member.index).put("name",member.name).put("path",member.file.getAbsolutePath()).put("sha256",member.sha256).put("nativeCount",member.nativeCount).put("dexCount",member.dexCount));out.put("members",members).put("patchOwner",target.patchOwnerApk().getAbsolutePath());}catch(Exception ignored){}return out;
    }

    private static void check(AtomicBoolean cancelled)throws java.io.InterruptedIOException{if((cancelled!=null&&cancelled.get())||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("cancelled");}
}