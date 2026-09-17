package dev.modkit.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.DocumentsContract;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Verifies that a File Workspace patch still belongs to the current canonical target before build. */
public class WorkspaceBuildGuardService extends Service {
    private static final int NOTE_ID=100;
    private static final int MAX_MANIFEST_BYTES=1024*1024;
    private static final long MAX_EDIT_BYTES=16L*1024L*1024L;
    private App app;private PowerManager.WakeLock wake;

    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("workspace-build-guard","File Workspace build verification",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,WorkspaceBuildGuardService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,FileWorkspaceActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"workspace-build-guard").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · File Workspace build gate").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    private void check()throws java.io.InterruptedIOException{if(app.cancelled.get()||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("Workspace build cancelled");}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("File Workspace build: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Проверяю canonical target и Patch Pack…"));wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:workspace-build-guard");wake.acquire(20L*60L*1000L);getSharedPreferences("state",0).edit().putBoolean("running",true).apply();final Intent request=intent;
        new Thread(()->{boolean handedOff=false;Uri destination=null;try{
            String uriText=request==null?null:request.getStringExtra("uri");if(uriText==null||uriText.isEmpty())throw new IOException("Не выбран файл назначения");destination=Uri.parse(uriText);check();File bindingFile=app.file("workspace-source.json");File patch=app.file("workspace-patch.zip");if(!bindingFile.isFile()||!patch.isFile())throw new IOException("Workspace patch/binding отсутствует; подготовьте Patch Pack заново");JSONObject binding=new JSONObject(Io.readUtf8(bindingFile));
            TargetResolver.Target target=TargetResolver.resolve(app);JSONObject verification=TargetResolver.requireVerified(target,app.cancelled);check();TargetResolver.Member member=verifyBinding(target,verification,binding);JSONObject patchVerification=verifyPatchArtifact(patch,member.file,binding);String source=member.file.getCanonicalPath();
            progress("File Workspace build: target + entry + Patch Pack SHA verified · передаю в patch/signing pipeline…");Intent worker=new Intent(this,WorkerService.class).putExtra("op","workspace_build").putExtra("source",source).putExtra("uri",destination.toString());startForegroundService(worker);handedOff=true;AnalysisJournal.append(this,"WORKSPACE_BUILD_HANDOFF","File Workspace target and patch artifact verified",new JSONObject().put("targetDigest",verification.optString("currentTargetDigest")).put("sourceApk",source).put("targetEntry",binding.getString("targetEntry")).put("patchSha256",patchVerification.getString("patchSha256")).put("editedEntrySha256",patchVerification.getString("editedEntrySha256")));
        }catch(Throwable e){AnalysisJournal.exception(this,"WORKSPACE_BUILD_BLOCKED",e);if(destination!=null&&!handedOff)try{DocumentsContract.deleteDocument(getContentResolver(),destination);}catch(Exception ignored){}progress(app.cancelled.get()?"File Workspace build отменён.":"File Workspace build заблокирован: "+safeMessage(e));}
        finally{if(wake!=null&&wake.isHeld())wake.release();if(!handedOff){getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;}stopForeground(true);stopSelf();}},"modkit-workspace-build-guard").start();return START_NOT_STICKY;
    }

    private TargetResolver.Member verifyBinding(TargetResolver.Target target,JSONObject verification,JSONObject binding)throws Exception{
        if(!"modkit-workspace-source-1.1".equals(binding.optString("schema")))throw new IOException("Workspace binding schema повреждена или устарела");
        for(String key:new String[]{"targetId","targetFingerprint","targetDigest","sourceApk","sourceSplitIndex","sourceSplitName","sourceSplitExpectedSha256","targetEntry","originalEntrySha256","editedEntrySha256"})if(!binding.has(key)||binding.isNull(key))throw new IOException("Workspace binding не содержит обязательное поле: "+key);
        String expectedId=binding.getString("targetId");if(!expectedId.equals(target.targetId))throw new IOException("Workspace patch относится к другому targetId");
        String expectedFingerprint=binding.getString("targetFingerprint");if(!expectedFingerprint.equals(target.fingerprint))throw new IOException("Workspace patch относится к другой версии APK-set");
        String expectedDigest=requireSha(binding,"targetDigest");if(!expectedDigest.equalsIgnoreCase(verification.optString("currentTargetDigest","")))throw new IOException("Workspace target digest изменился после подготовки Patch Pack");
        String source=binding.getString("sourceApk");if(source.isEmpty())throw new IOException("Workspace source APK не записан");String canonical=new File(source).getCanonicalPath();int expectedIndex=binding.getInt("sourceSplitIndex");String expectedName=binding.getString("sourceSplitName");String expectedMemberSha=binding.getString("sourceSplitExpectedSha256");TargetResolver.Member found=null;
        for(TargetResolver.Member member:target.members)if(member.file.getCanonicalPath().equals(canonical)){found=member;break;}
        if(found==null)throw new IOException("Workspace source APK больше не принадлежит текущему target");
        if(found.index!=expectedIndex)throw new IOException("Workspace split index изменился");
        if(!found.name.equals(expectedName))throw new IOException("Workspace split name изменился");
        if(!safe(found.sha256).equals(expectedMemberSha))throw new IOException("Workspace split expected SHA-256 изменился");
        validateTargetEntry(binding.getString("targetEntry"));requireSha(binding,"originalEntrySha256");requireSha(binding,"editedEntrySha256");check();return found;
    }

    private JSONObject verifyPatchArtifact(File patch,File sourceApk,JSONObject binding)throws Exception{
        check();String patchSha=sha256File(patch);check();String targetEntry=binding.getString("targetEntry");String originalSha=requireSha(binding,"originalEntrySha256");String editedSha=requireSha(binding,"editedEntrySha256");
        JSONObject manifest;String actualEdited;
        try(ZipFile zip=new ZipFile(patch)){
            Set<String> names=new HashSet<>();int files=0;Enumeration<? extends ZipEntry> entries=zip.entries();while(entries.hasMoreElements()){check();ZipEntry row=entries.nextElement();if(row.isDirectory())continue;files++;String name=row.getName();if(!names.add(name))throw new IOException("Workspace Patch Pack содержит duplicate ZIP entry: "+name);if(!"files/edit.bin".equals(name)&&!"modkit-workspace.json".equals(name))throw new IOException("Workspace Patch Pack содержит неожиданный entry: "+name);}
            if(files!=2||!names.contains("files/edit.bin")||!names.contains("modkit-workspace.json"))throw new IOException("Workspace Patch Pack неполон или содержит лишние entries");
            ZipEntry meta=zip.getEntry("modkit-workspace.json"),edit=zip.getEntry("files/edit.bin");if(meta==null||edit==null)throw new IOException("Workspace Patch Pack не содержит manifest/edit payload");
            manifest=new JSONObject(readUtf8Bounded(zip.getInputStream(meta),MAX_MANIFEST_BYTES));if(!"modkit-workspace-patch-1.1".equals(manifest.optString("schema")))throw new IOException("Workspace Patch Pack manifest schema повреждена");
            JSONObject embedded=manifest.optJSONObject("target");if(embedded==null)throw new IOException("Workspace Patch Pack не содержит target binding");verifyEmbeddedBinding(binding,embedded);
            JSONArray rows=manifest.optJSONArray("entries");if(rows==null||rows.length()!=1)throw new IOException("Workspace Patch Pack должен содержать ровно одну редактируемую entry");JSONObject row=rows.optJSONObject(0);if(row==null)throw new IOException("Workspace Patch Pack entry manifest повреждён");if(!"files/edit.bin".equals(row.optString("packPath")))throw new IOException("Workspace Patch Pack payload path не совпадает");if(!targetEntry.equals(row.optString("targetPath")))throw new IOException("Workspace Patch Pack target entry изменился");if(!originalSha.equalsIgnoreCase(row.optString("originalSha256")))throw new IOException("Workspace Patch Pack original entry SHA не совпадает с binding");if(!editedSha.equalsIgnoreCase(row.optString("editedSha256")))throw new IOException("Workspace Patch Pack edited entry SHA не совпадает с binding");
            actualEdited=sha256Stream(zip.getInputStream(edit),MAX_EDIT_BYTES);if(!editedSha.equalsIgnoreCase(actualEdited))throw new IOException("Workspace Patch Pack edit payload изменился после подготовки");
        }
        String actualOriginal=sha256ApkEntry(sourceApk,targetEntry);if(!originalSha.equalsIgnoreCase(actualOriginal))throw new IOException("Исходный APK entry изменился или Patch Pack был подготовлен не из текущего entry");
        return new JSONObject().put("schema","modkit-workspace-build-verify-1.0").put("patchSha256",patchSha).put("targetEntry",targetEntry).put("originalEntrySha256",actualOriginal).put("editedEntrySha256",actualEdited);
    }

    private void verifyEmbeddedBinding(JSONObject expected,JSONObject actual)throws Exception{
        if(!"modkit-workspace-source-1.1".equals(actual.optString("schema")))throw new IOException("Workspace Patch Pack embedded binding schema повреждена");
        for(String key:new String[]{"targetId","targetFingerprint","targetDigest","sourceApk","sourceSplitIndex","sourceSplitName","sourceSplitExpectedSha256","targetEntry","originalEntrySha256","editedEntrySha256"}){
            if(!actual.has(key)||actual.isNull(key))throw new IOException("Workspace Patch Pack embedded binding не содержит: "+key);
            if(!String.valueOf(expected.get(key)).equals(String.valueOf(actual.get(key))))throw new IOException("Workspace Patch Pack embedded binding не совпадает: "+key);
        }
    }

    private String sha256ApkEntry(File apk,String entryName)throws Exception{
        try(ZipFile zip=new ZipFile(apk)){
            ZipEntry selected=null;int matches=0;Enumeration<? extends ZipEntry> rows=zip.entries();while(rows.hasMoreElements()){check();ZipEntry row=rows.nextElement();if(!row.isDirectory()&&entryName.equals(row.getName())){selected=row;matches++;}}
            if(matches!=1||selected==null)throw new IOException(matches==0?"Исходный APK больше не содержит entry: "+entryName:"Исходный APK содержит duplicate entry: "+entryName);
            return sha256Stream(zip.getInputStream(selected),MAX_EDIT_BYTES);
        }
    }

    private String sha256File(File file)throws Exception{try(InputStream in=new FileInputStream(file)){return sha256Stream(in,MAX_EDIT_BYTES+MAX_MANIFEST_BYTES+4L*1024L*1024L);}}
    private String sha256Stream(InputStream in,long maxBytes)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[256*1024];long total=0;try(InputStream stream=in){int n;while((n=stream.read(buffer))!=-1){check();total+=n;if(total>maxBytes)throw new IOException("Workspace artifact превышает допустимый размер");digest.update(buffer,0,n);}}StringBuilder out=new StringBuilder(64);for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();}
    private String readUtf8Bounded(InputStream in,int maxBytes)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[32*1024];int total=0;try(InputStream stream=in){int n;while((n=stream.read(buffer))!=-1){check();total+=n;if(total>maxBytes)throw new IOException("Workspace manifest слишком велик");out.write(buffer,0,n);}}return out.toString(StandardCharsets.UTF_8.name());}
    private static String requireSha(JSONObject object,String key)throws IOException{String value=object.optString(key,"");if(!value.matches("(?i)[0-9a-f]{64}"))throw new IOException("Workspace binding содержит некорректный SHA-256: "+key);return value;}
    private static void validateTargetEntry(String value)throws IOException{if(value==null||value.isEmpty()||value.startsWith("/")||value.contains("\\")||value.indexOf('\0')>=0){throw new IOException("Workspace target entry некорректен");}for(String part:value.split("/"))if(part.isEmpty()||".".equals(part)||"..".equals(part))throw new IOException("Workspace target entry небезопасен");}
    private static String safe(String value){return value==null?"":value;}
    private static String safeMessage(Throwable e){String m=e==null?null:e.getMessage();return m==null?(e==null?"unknown":e.getClass().getSimpleName()):m;}
}
