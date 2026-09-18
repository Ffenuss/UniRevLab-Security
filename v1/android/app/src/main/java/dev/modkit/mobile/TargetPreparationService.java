package dev.modkit.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Copies/records the selected target only; analysis starts later in FullAnalysisService. */
public class TargetPreparationService extends Service {
    private static final int NOTE_ID=94;private App app;private PowerManager.WakeLock wake;
    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("target-preparation","Подготовка target",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,TargetSelectionActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"target-preparation").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · выбор target").setContentText(text).setContentIntent(open).setOngoing(true).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    private boolean persistPreparationState(boolean running){return getSharedPreferences("state",0).edit().putBoolean("running",running).putBoolean("target.preparing",running).commit();}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        startForeground(NOTE_ID,note("Подготовка target…"));
        if(wake==null||!wake.isHeld()){wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:target-preparation");wake.acquire(30L*60L*1000L);}
        if(!persistPreparationState(true)){
            progress("Подготовка target не запущена: не удалось надёжно сохранить recovery marker.");
            if(wake!=null&&wake.isHeld())wake.release();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();return START_NOT_STICKY;
        }
        new Thread(()->{try{String kind=intent==null?"":intent.getStringExtra("kind");if("installed".equals(kind))prepareInstalled(intent.getStringExtra("package"),intent.getStringExtra("label"));else if("apk".equals(kind))prepareApk(intent.getStringExtra("uri"),intent.getStringExtra("display"));else throw new IllegalArgumentException("Неизвестный тип target");}catch(Exception e){AnalysisJournal.exception(this,"TARGET_PREPARATION_FAILED",e);try{cleanupFailedPreparation();}catch(Exception cleanup){progress("Target не подготовлен: "+e.getMessage()+" · cleanup: "+cleanup.getMessage());return;}progress(app.cancelled.get()?"Подготовка target отменена. Старый/частичный target очищен.":"Target не подготовлен: "+e.getMessage()+" · частичный target очищен.");}finally{if(wake!=null&&wake.isHeld())wake.release();if(!persistPreparationState(false))progress("Target подготовлен, но recovery marker не удалось надёжно сбросить; при следующем старте будет применена fail-closed очистка.");app.busy.set(false);app.revision++;stopForeground(true);stopSelf();}},"modkit-target-preparation").start();return START_NOT_STICKY;
    }

    private void writeAtomicJson(String name,JSONObject value)throws Exception{
        File temp=app.file(name+".part"),dest=app.file(name);Files.deleteIfExists(temp.toPath());
        try{Files.write(temp.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(temp.toPath(),dest.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        catch(Exception e){Files.deleteIfExists(temp.toPath());throw e;}
    }

    private void prepareInstalled(String packageName,String label)throws Exception{
        if(packageName==null||packageName.isEmpty())throw new IllegalArgumentException("package не указан");
        clearTargetDependentOutputs();
        progress("Копирую APK-set установленного приложения…");PackageManager pm=getPackageManager();ApplicationInfo ai=pm.getApplicationInfo(packageName,0);PackageInfo pi=pm.getPackageInfo(packageName,0);List<File> sources=new ArrayList<>();sources.add(new File(ai.sourceDir));if(ai.splitSourceDirs!=null)for(String path:ai.splitSourceDirs)if(path!=null&&!path.isEmpty())sources.add(new File(path));for(File source:sources)if(!source.isFile())throw new java.io.FileNotFoundException(source.getAbsolutePath());
        File dir=app.file("installed-apks");deleteTree(dir);if(!dir.mkdirs()&&!dir.isDirectory())throw new java.io.IOException("Не удалось создать installed-apks");JSONArray splits=new JSONArray();for(int i=0;i<sources.size();i++){checkCancelled();File source=sources.get(i);String sourceName=source.getName();String name=i==0?"base.apk":String.format(Locale.ROOT,"split-%03d-%s",i,safeName(sourceName));File dest=new File(dir,name);copy(source,dest);splits.put(new JSONObject().put("index",i).put("name",name).put("path",dest.getCanonicalPath()).put("size",dest.length()).put("sha256",sha256(dest)));progress("Копирую APK-set: "+(i+1)+"/"+sources.size());}
        copy(new File(dir,"base.apk"),app.file("game.apk"));checkCancelled();long code=versionCode(pi);String fingerprint=selectionFingerprint(packageName,code,splits);boolean apkSet=sources.size()>1;JSONObject target=new JSONObject().put("schema","modkit-target-selection-1.1").put("preparedOnly",true).put("analysisPerformed",false).put("sourceKind","installed").put("packageName",packageName).put("label",label==null?String.valueOf(pm.getApplicationLabel(ai)):label).put("versionName",pi.versionName).put("versionCode",code).put("targetId",fingerprint.substring(0,24)).put("fingerprintSha256",fingerprint).put("scanCompleteness","COMPLETE").put("expectedApkCount",sources.size()).put("copiedApkCount",sources.size()).put("copyErrors",new JSONArray()).put("buildMode",apkSet?"apk-set":"single-apk").put("requiresWholeSetSigning",apkSet).put("fullIl2cppPair",false).put("pairConfidence","UNSCANNED").put("splits",splits);writeAtomicJson("installed-target.json",target);SharedPreferences.Editor prefs=getSharedPreferences("state",0).edit();prefs.putString("installed.package",packageName).putString("game.apk","base.apk").apply();AnalysisJournal.append(this,"TARGET_READY","Installed target prepared",new JSONObject().put("package",packageName).put("apkCount",sources.size()).put("targetId",target.getString("targetId")));progress("Target готов: "+packageName+" · APK-set "+sources.size()+" · анализ ещё не запускался.");
    }
    private static String selectionFingerprint(String packageName,long versionCode,JSONArray splits)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");d.update((packageName==null?"":packageName).getBytes(StandardCharsets.UTF_8));d.update((byte)0);d.update(Long.toString(versionCode).getBytes(StandardCharsets.US_ASCII));for(int i=0;i<splits.length();i++){JSONObject row=splits.getJSONObject(i);d.update((byte)0);d.update(row.getString("name").getBytes(StandardCharsets.UTF_8));d.update((byte)0);d.update(row.getString("sha256").getBytes(StandardCharsets.US_ASCII));}StringBuilder out=new StringBuilder(64);for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();}
    @SuppressWarnings("deprecation") private static long versionCode(PackageInfo info){return Build.VERSION.SDK_INT>=Build.VERSION_CODES.P?info.getLongVersionCode():(long)info.versionCode;}
    private void prepareApk(String uriText,String display)throws Exception{
        if(uriText==null||uriText.isEmpty())throw new IllegalArgumentException("APK URI не указан");
        clearTargetDependentOutputs();progress("Копирую выбранный файл…");Uri uri=Uri.parse(uriText);File temp=app.file("target-import.part");Files.deleteIfExists(temp.toPath());
        try{
            try(InputStream in=getContentResolver().openInputStream(uri);FileOutputStream out=new FileOutputStream(temp)){if(in==null)throw new java.io.FileNotFoundException("Не удалось открыть выбранный файл");byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){checkCancelled();out.write(buf,0,n);}}
            if(temp.length()==0)throw new java.io.IOException("Выбран пустой файл");checkCancelled();
            String shown=display==null?"target":display;
            TargetArchiveImporter.Result imported=TargetArchiveImporter.importSelected(this,temp,shown,getFilesDir(),app.cancelled,this::progress);
            checkCancelled();
            if(imported.apkSet){writeAtomicJson("installed-target.json",imported.manifest);getSharedPreferences("state",0).edit().remove("installed.package").putString("game.apk",shown).apply();AnalysisJournal.append(this,"TARGET_READY","Archive APK-set prepared",new JSONObject().put("display",shown).put("apkCount",imported.manifest.optInt("expectedApkCount")).put("package",imported.manifest.optString("packageName")));progress(imported.summary+" · анализ ещё не запускался.");}
            else{File dest=app.file("game.apk");String hash=sha256(dest);getSharedPreferences("state",0).edit().remove("installed.package").putString("game.apk",shown).apply();AnalysisJournal.append(this,"TARGET_READY","Single APK prepared",new JSONObject().put("display",shown).put("sha256",hash));progress("Target готов: "+shown+" · SHA-256 "+hash.substring(0,16)+"… · анализ ещё не запускался.");}
        }finally{Files.deleteIfExists(temp.toPath());}
    }

    private void clearTargetDependentOutputs()throws IOException{
        app.result=null;
        String[] names={
            "full-reconstruction.json","full-reconstruction.json.part","modkit-decompiled.zip","modkit-decompiled.zip.tmp","jadx-batch","decompiler","apktool-analysis.json","apktool-analysis.json.part","apktool-workspace",
            "artifact-families.json","embedded-analysis.json","automatic-evidence.json","automatic-evidence.json.part","automod-plan.json","automod-plan.json.part",
            "runtime-session.json","runtime-session.json.part","runtime-correlation.json","runtime-correlation.json.part","runtime-correlation.json.build",
            "il2cpp-crosscheck.json","il2cpp-crosscheck.json.part","il2cpp-crosscheck.methods.jsonl","il2cpp-crosscheck.methods.jsonl.part",
            "il2cpp-metadata-identity.json","il2cpp-metadata-identity.json.part","il2cpp-metadata-identity.methods.jsonl","il2cpp-metadata-identity.methods.jsonl.part",
            "il2cpp-no-rva-native.json","il2cpp-no-rva-native.json.part","il2cpp-no-rva-native.methods.jsonl","il2cpp-no-rva-native.methods.jsonl.part","il2cpp-no-rva-native.failures.jsonl","il2cpp-no-rva-native.failures.jsonl.part",
            "lua-deep.json","hermes-deep","hermes-deep.json","native-deep.json","native-deep-cache","cocos-deep.json","flutter-deep.json","deep-gameplay.json",
            "installed-target.json","installed-target.json.part","installed-apk-set.zip","installed-apk-set.zip.tmp","installed-apk-set.digest","installed-scan.json","installed-apks","target-import.part",
            "metadata.bin","library.so","game.apk","game-native-split.apk","game.apk.part",
            "native-source.so","native-working.so","native-state.json","native-info.json","native-source.json","native-search.json","native-disasm.json","native-xrefs.json",
            "analysis.json","analysis.summary.json","analysis.summary.json.part","analysis.ui.jsonl",
            "analysis.methods.jsonl","analysis.methods.jsonl.idx","analysis.methods.jsonl.rva.idx","analysis.methods.jsonl.pages.idx","analysis.methods.meta.json",
            "analysis.candidates.jsonl","analysis.discoveries.jsonl","analysis.fields.jsonl",
            "analysis.evidence-graph.jsonl","analysis.evidence-graph.jsonl.idx","analysis.evidence-graph.meta.json",
            "analysis.resolver-index.json","analysis.autopilot-index.jsonl","analysis.gameplay-coverage.json",
            "analysis-deep","re-analysis.json","re-analysis.ui.json","re-analysis.menu.json","security-surfaces.json",
            "simple-catalog.json","simple-catalog.json.part","simple-cache.json","simple-progress.json","simple-progress.json.part","rodroid",
            "menu-spec.json","menu-result.json","menu-preflight.json","menu-validation.json","menu-auto-prepare.json","menu-auto-prepare-deep.json","menu-auto-confirm.json","menu-autopilot.json","menu-probe-prepare.json","menu-spec.simple-source.json","menu-native-recovery.json","menu-native-recovery.json.tmp","menu-project",
            "menu-payload-report.json","menu-apk-report.json","menu-payload-build.zip","menu-unsigned.apk",
            "patchpack-report.json","patchpack-unsigned.apk",
            "workspace-patch.zip","workspace-patch.zip.tmp","workspace-patch-stale","workspace-source.json","workspace-source.json.part","workspace-report.json","workspace-edit.bin","workspace-preview.bin","workspace-preview.bin.part","workspace-preview.json","workspace-preview.json.part","workspace-unsigned.apk",
            "target-signed.apk","target-signed.apks","target-signed-set",
            "connected-report.json","connected-report.json.part","connected-report.md","connected-report.md.part","evidence-bundle.zip"
        };
        for(String name:names)deleteTree(app.file(name));
        getSharedPreferences("state",0).edit().remove("selections").remove("active.project").remove("metadata.bin").remove("library.so").remove("native-source.so").remove("installed.package").remove("game.apk").apply();
    }
    private void cleanupFailedPreparation()throws IOException{
        for(String name:new String[]{"installed-target.json","installed-target.json.part","installed-apk-set.zip","installed-apk-set.zip.tmp","installed-apk-set.digest","installed-apks","game.apk","game.apk.part","game-native-split.apk","target-import.part","native-source.so","native-working.so","native-state.json","native-info.json","native-source.json","native-search.json","native-disasm.json","native-xrefs.json"})deleteTree(app.file(name));
        getSharedPreferences("state",0).edit().remove("installed.package").remove("game.apk").remove("native-source.so").apply();
    }
    private void checkCancelled()throws java.io.InterruptedIOException{if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");}
    private static String safeName(String value){String s=value==null?"split.apk":value.replaceAll("[^A-Za-z0-9._-]+","_");return s.isEmpty()?"split.apk":s;}
    private void copy(File source,File dest)throws Exception{try(FileInputStream in=new FileInputStream(source);FileOutputStream out=new FileOutputStream(dest)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){checkCancelled();out.write(buf,0,n);}}}
    private String sha256(File file)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(FileInputStream in=new FileInputStream(file)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){checkCancelled();d.update(buf,0,n);}}StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b));return s.toString();}
    private static void deleteTree(File file)throws IOException{if(file==null||!file.exists())return;if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);}if(!file.delete()&&file.exists())throw new IOException("Не удалось очистить старый target artifact: "+file.getName());}
}
