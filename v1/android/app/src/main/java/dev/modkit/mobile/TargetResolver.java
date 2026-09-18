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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
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
            String schema=manifest.optString("schema","");
            boolean selection="modkit-target-selection-1.1".equals(schema),analyzed="modkit-package-target-1.1".equals(schema);
            if(!selection&&!analyzed)throw new IOException("Target manifest schema не поддерживается: "+schema);
            if(selection&&!manifest.optBoolean("preparedOnly",false))throw new IOException("Target selection manifest не помечен preparedOnly");
            JSONArray splits=manifest.optJSONArray("splits");
            if(splits==null||splits.length()==0)throw new IOException("Target manifest не содержит APK/split members; fallback на base.apk запрещён");
            if(!"COMPLETE".equals(manifest.optString("scanCompleteness","")))throw new IOException("Target APK-set не помечен COMPLETE");
            JSONArray copyErrors=manifest.optJSONArray("copyErrors");if(copyErrors==null||copyErrors.length()!=0)throw new IOException("Target manifest содержит copyErrors или повреждённое поле copyErrors");
            if(analyzed){JSONArray normalizationErrors=manifest.optJSONArray("normalizationErrors");if(normalizationErrors==null||normalizationErrors.length()!=0)throw new IOException("Target manifest содержит normalizationErrors или повреждённое поле normalizationErrors");}
            int expected=requireNonNegativeInt(manifest,"expectedApkCount");int copied=requireNonNegativeInt(manifest,"copiedApkCount");if(expected<=0||copied!=expected||splits.length()!=expected)throw new IOException("Target APK-set неполон: copied="+copied+" / expected="+expected+" / manifest="+splits.length());
            Set<Integer> seenIndexes=new HashSet<>();Set<String> seenPaths=new HashSet<>();Set<String> seenNames=new HashSet<>();String installedRoot=app.file("installed-apks").getCanonicalPath()+File.separator;
            for(int i=0;i<splits.length();i++){
                JSONObject row=splits.optJSONObject(i);if(row==null)throw new IOException("Target manifest содержит повреждённую split row #"+i);
                int index=requireNonNegativeInt(row,"index");if(!seenIndexes.add(index))throw new IOException("Target manifest содержит duplicate split index: "+index);
                String name=row.optString("name","");validateMemberName(name);if(!seenNames.add(name))throw new IOException("Target manifest содержит duplicate split name: "+name);
                String path=row.optString("path","");if(path.isEmpty())throw new IOException("Target split #"+index+" не содержит path");
                File file=new File(path);String canonical=file.getCanonicalPath();if(!canonical.startsWith(installedRoot))throw new IOException("Target split находится вне canonical installed-apks: "+name);if(!seenPaths.add(canonical))throw new IOException("Target manifest повторно ссылается на один APK: "+canonical);
                if(!file.isFile())throw new IOException("Target split отсутствует: "+name);
                String sha=requireSha256(row,"sha256");
                members.add(new Member(index,name,file,sha,optionalNonNegativeInt(row,"nativeCount"),optionalNonNegativeInt(row,"dexCount")));
            }
            String expectedMode=splits.length()>1?"apk-set":"single-apk";if(!expectedMode.equals(manifest.optString("buildMode","")))throw new IOException("Target buildMode не соответствует числу APK members");
            Object signing=manifest.opt("requiresWholeSetSigning");if(!(signing instanceof Boolean)||((Boolean)signing)!=(splits.length()>1))throw new IOException("Target requiresWholeSetSigning не соответствует APK-set");
            long versionCode=requireNonNegativeLong(manifest,"versionCode");String packageName=manifest.optString("packageName","");String actualFingerprint=manifestFingerprint(packageName,versionCode,splits);String fingerprint=requireSha256(manifest,"fingerprintSha256");if(!fingerprint.equalsIgnoreCase(actualFingerprint))throw new IOException("Target fingerprint не соответствует member identity");String targetId=manifest.optString("targetId","");if(!actualFingerprint.substring(0,24).equals(targetId))throw new IOException("TargetId не соответствует fingerprint");
        }else{
            File single=app.file("game.apk");if(!single.isFile())throw new IOException("Target APK не выбран");members.add(new Member(0,single.getName(),single,"",0,0));
        }
        members.sort(Comparator.comparingInt(m->m.index));
        String packageName=manifest==null?"":manifest.optString("packageName","");
        String targetId=manifest==null?"":manifest.optString("targetId","");
        String fingerprint=manifest==null?"":manifest.optString("fingerprintSha256","");
        boolean apkSet=members.size()>1||manifest!=null&&"apk-set".equals(manifest.optString("buildMode"));
        return new Target(app,manifest,members,packageName,targetId,fingerprint,apkSet);
    }

    static JSONObject verify(Target target,AtomicBoolean cancelled)throws Exception{
        JSONArray rows=new JSONArray();boolean ok=true;int patchOwnerIndex=-1;boolean fullIl2cppPair=false;
        if(target.manifest!=null){JSONObject owner=target.manifest.optJSONObject("patchOwner");if(owner!=null)patchOwnerIndex=owner.optInt("splitIndex",-1);fullIl2cppPair=target.manifest.optBoolean("fullIl2cppPair",false);}
        boolean patchOwnerSeen=patchOwnerIndex<0;
        for(Member member:target.members){
            check(cancelled);JSONObject row=new JSONObject().put("index",member.index).put("name",member.name).put("path",member.file.getAbsolutePath()).put("expectedSha256",member.sha256).put("size",member.file.length());
            if(!member.file.isFile()){row.put("ok",false).put("reason","missing");ok=false;rows.put(row);continue;}
            String actual=sha256(member.file,cancelled);boolean match=member.sha256==null||member.sha256.isEmpty()||member.sha256.equalsIgnoreCase(actual);
            row.put("actualSha256",actual).put("ok",match);if(!match){row.put("reason","sha256-mismatch");ok=false;}if(member.index==patchOwnerIndex)patchOwnerSeen=true;rows.put(row);
        }
        if(!patchOwnerSeen||fullIl2cppPair&&patchOwnerIndex<0)ok=false;
        if(target.manifest!=null&&"PARTIAL".equals(target.manifest.optString("scanCompleteness")))ok=false;
        return new JSONObject().put("schema","modkit-target-resolver-verify-1.1").put("ok",ok&&rows.length()>0).put("targetId",target.targetId).put("apkSet",target.apkSet).put("memberCount",rows.length()).put("fullIl2cppPair",fullIl2cppPair).put("patchOwnerIndex",patchOwnerIndex).put("patchOwnerPresent",patchOwnerSeen).put("currentTargetDigest",targetDigest(target,cancelled)).put("members",rows);
    }

    static JSONObject requireVerified(Target target,AtomicBoolean cancelled)throws Exception{
        JSONObject verified=verify(target,cancelled);if(!verified.optBoolean("ok"))throw new IOException("Canonical target изменился, неполон или не совпадает с сохранёнными SHA-256. Выберите target заново перед продолжением.");return verified;
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
        }catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}
        catch(Error e){try{Files.deleteIfExists(tmp.toPath());}catch(Exception ignored){}throw e;}
        Files.move(tmp.toPath(),output.toPath(),StandardCopyOption.REPLACE_EXISTING);Files.write(sidecar.toPath(),expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));return output;
    }

    static String targetDigest(Target target,AtomicBoolean cancelled)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[1024*1024];
        for(Member member:target.members){check(cancelled);digest.update(Integer.toString(member.index).getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);digest.update(member.name.getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);digest.update(Long.toString(member.file.length()).getBytes(java.nio.charset.StandardCharsets.US_ASCII));digest.update((byte)0);try(FileInputStream in=new FileInputStream(member.file)){int n;while((n=in.read(buffer))!=-1){check(cancelled);digest.update(buffer,0,n);}}}
        StringBuilder out=new StringBuilder();for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }

    static JSONObject describe(Target target){
        JSONObject out=new JSONObject();JSONArray members=new JSONArray();try{out.put("schema","modkit-target-resolver-1.1").put("packageName",target.packageName).put("targetId",target.targetId).put("fingerprintSha256",target.fingerprint).put("apkSet",target.apkSet).put("memberCount",target.members.size());for(Member member:target.members)members.put(new JSONObject().put("index",member.index).put("name",member.name).put("path",member.file.getAbsolutePath()).put("sha256",member.sha256).put("nativeCount",member.nativeCount).put("dexCount",member.dexCount));out.put("members",members).put("patchOwner",target.patchOwnerApk().getAbsolutePath());}catch(Exception ignored){}return out;
    }

    private static int requireNonNegativeInt(JSONObject object,String key)throws IOException{Object raw=object.opt(key);if(!(raw instanceof Number))throw new IOException("Target manifest содержит некорректное целое поле: "+key);Number number=(Number)raw;double d=number.doubleValue();long value=number.longValue();if(!Double.isFinite(d)||d!=(double)value||value<0||value>Integer.MAX_VALUE)throw new IOException("Target manifest содержит некорректное целое поле: "+key);return (int)value;}
    private static long requireNonNegativeLong(JSONObject object,String key)throws IOException{Object raw=object.opt(key);if(!(raw instanceof Number))throw new IOException("Target manifest содержит некорректное целое поле: "+key);Number number=(Number)raw;double d=number.doubleValue();long value=number.longValue();if(!Double.isFinite(d)||d!=(double)value||value<0)throw new IOException("Target manifest содержит некорректное целое поле: "+key);return value;}
    private static int optionalNonNegativeInt(JSONObject object,String key)throws IOException{if(!object.has(key)||object.isNull(key))return 0;return requireNonNegativeInt(object,key);}
    private static String requireSha256(JSONObject object,String key)throws IOException{String value=object.optString(key,"");if(!value.matches("(?i)[0-9a-f]{64}"))throw new IOException("Target manifest содержит некорректный SHA-256: "+key);return value;}
    private static void validateMemberName(String name)throws IOException{if(name==null||name.isEmpty()||name.contains("/")||name.contains("\\")||".".equals(name)||"..".equals(name))throw new IOException("Target split name небезопасен или пуст");}
    private static String manifestFingerprint(String packageName,long versionCode,JSONArray splits)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");d.update((packageName==null?"":packageName).getBytes(java.nio.charset.StandardCharsets.UTF_8));d.update((byte)0);d.update(Long.toString(versionCode).getBytes(java.nio.charset.StandardCharsets.US_ASCII));for(int i=0;i<splits.length();i++){JSONObject row=splits.getJSONObject(i);d.update((byte)0);d.update(row.getString("name").getBytes(java.nio.charset.StandardCharsets.UTF_8));d.update((byte)0);d.update(row.getString("sha256").getBytes(java.nio.charset.StandardCharsets.US_ASCII));}StringBuilder out=new StringBuilder(64);for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();}

    private static String sha256(File file,AtomicBoolean cancelled)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[1024*1024];try(FileInputStream in=new FileInputStream(file)){int n;while((n=in.read(buffer))!=-1){check(cancelled);digest.update(buffer,0,n);}}StringBuilder out=new StringBuilder();for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();}
    private static void check(AtomicBoolean cancelled)throws java.io.InterruptedIOException{if((cancelled!=null&&cancelled.get())||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("cancelled");}
}
