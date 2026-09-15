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

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Copies/records the selected target only; analysis starts later in FullAnalysisService. */
public class TargetPreparationService extends Service {
    private static final int NOTE_ID=94;private App app;
    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("target-preparation","Подготовка target",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,TargetSelectionActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"target-preparation").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · выбор target").setContentText(text).setContentIntent(open).setOngoing(true).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    @Override public int onStartCommand(Intent intent,int flags,int startId){startForeground(NOTE_ID,note("Подготовка target…"));getSharedPreferences("state",0).edit().putBoolean("running",true).apply();new Thread(()->{try{String kind=intent==null?"":intent.getStringExtra("kind");if("installed".equals(kind))prepareInstalled(intent.getStringExtra("package"),intent.getStringExtra("label"));else if("apk".equals(kind))prepareApk(intent.getStringExtra("uri"),intent.getStringExtra("display"));else throw new IllegalArgumentException("Неизвестный тип target");}catch(Exception e){progress("Target не подготовлен: "+e.getMessage());}finally{getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();}},"modkit-target-preparation").start();return START_NOT_STICKY;}

    private void prepareInstalled(String packageName,String label)throws Exception{
        if(packageName==null||packageName.isEmpty())throw new IllegalArgumentException("package не указан");progress("Копирую APK-set установленного приложения…");PackageManager pm=getPackageManager();ApplicationInfo ai=pm.getApplicationInfo(packageName,0);PackageInfo pi=pm.getPackageInfo(packageName,0);List<File> sources=new ArrayList<>();sources.add(new File(ai.sourceDir));if(ai.splitSourceDirs!=null)for(String path:ai.splitSourceDirs)if(path!=null&&!path.isEmpty())sources.add(new File(path));for(File source:sources)if(!source.isFile())throw new java.io.FileNotFoundException(source.getAbsolutePath());
        clearTargetDependentOutputs();File dir=app.file("installed-apks");deleteTree(dir);if(!dir.mkdirs()&&!dir.isDirectory())throw new java.io.IOException("Не удалось создать installed-apks");JSONArray splits=new JSONArray();for(int i=0;i<sources.size();i++){if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");File source=sources.get(i);String sourceName=source.getName();String name=i==0?"base.apk":String.format(Locale.ROOT,"split-%03d-%s",i,safeName(sourceName));File dest=new File(dir,name);copy(source,dest);splits.put(new JSONObject().put("index",i).put("name",name).put("path",dest.getCanonicalPath()).put("size",dest.length()).put("sha256",sha256(dest)));progress("Копирую APK-set: "+(i+1)+"/"+sources.size());}
        copy(new File(dir,"base.apk"),app.file("game.apk"));JSONObject target=new JSONObject().put("schema","modkit-target-selection-1.0").put("preparedOnly",true).put("analysisPerformed",false).put("packageName",packageName).put("label",label==null?String.valueOf(pm.getApplicationLabel(ai)):label).put("versionName",pi.versionName).put("versionCode",versionCode(pi)).put("expectedApkCount",sources.size()).put("splits",splits);Files.write(app.file("installed-target.json").toPath(),target.toString(2).getBytes(StandardCharsets.UTF_8));SharedPreferences.Editor prefs=getSharedPreferences("state",0).edit();prefs.putString("installed.package",packageName).putString("game.apk","base.apk").apply();progress("Target готов: "+packageName+" · APK-set "+sources.size()+" · анализ ещё не запускался.");
    }
    @SuppressWarnings("deprecation") private static long versionCode(PackageInfo info){return Build.VERSION.SDK_INT>=Build.VERSION_CODES.P?info.getLongVersionCode():(long)info.versionCode;}
    private void prepareApk(String uriText,String display)throws Exception{if(uriText==null||uriText.isEmpty())throw new IllegalArgumentException("APK URI не указан");progress("Копирую выбранный APK…");Uri uri=Uri.parse(uriText);clearTargetDependentOutputs();File installed=app.file("installed-apks");deleteTree(installed);File temp=app.file("game.apk.part");temp.delete();try(InputStream in=getContentResolver().openInputStream(uri);FileOutputStream out=new FileOutputStream(temp)){if(in==null)throw new java.io.FileNotFoundException("Не удалось открыть APK");byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");out.write(buf,0,n);}}if(temp.length()==0)throw new java.io.IOException("Выбран пустой APK");File dest=app.file("game.apk");if(dest.exists()&&!dest.delete())throw new java.io.IOException("Не удалось заменить game.apk");if(!temp.renameTo(dest)){copy(temp,dest);temp.delete();}getSharedPreferences("state",0).edit().remove("installed.package").putString("game.apk",display==null?"target.apk":display).apply();progress("Target готов: "+(display==null?"APK":display)+" · SHA-256 "+sha256(dest).substring(0,16)+"… · анализ ещё не запускался.");}

    private void clearTargetDependentOutputs(){
        app.result=null;
        String[] names={
            "full-reconstruction.json","modkit-decompiled.zip","apktool-analysis.json","apktool-workspace",
            "artifact-families.json","embedded-analysis.json","automatic-evidence.json","automod-plan.json",
            "runtime-session.json","runtime-correlation.json",
            "il2cpp-crosscheck.json","il2cpp-crosscheck.methods.jsonl",
            "il2cpp-metadata-identity.json","il2cpp-metadata-identity.methods.jsonl",
            "il2cpp-no-rva-native.json","il2cpp-no-rva-native.methods.jsonl",
            "lua-deep.json","hermes-deep","hermes-deep.json","native-deep.json","native-deep-cache","cocos-deep.json","flutter-deep.json","deep-gameplay.json",
            "installed-target.json","installed-apk-set.zip","installed-scan.json","installed-apks",
            "metadata.bin","library.so","game.apk","game-native-split.apk","game.apk.part",
            "analysis.json","analysis.summary.json","analysis.ui.jsonl",
            "analysis.methods.jsonl","analysis.methods.jsonl.idx","analysis.methods.jsonl.rva.idx","analysis.methods.jsonl.pages.idx","analysis.methods.meta.json",
            "analysis.candidates.jsonl","analysis.discoveries.jsonl","analysis.fields.jsonl",
            "analysis.evidence-graph.jsonl","analysis.evidence-graph.jsonl.idx","analysis.evidence-graph.meta.json",
            "analysis.resolver-index.json","analysis.autopilot-index.jsonl","analysis.gameplay-coverage.json",
            "analysis-deep","re-analysis.json","re-analysis.ui.json","re-analysis.menu.json","security-surfaces.json",
            "simple-catalog.json","simple-cache.json","simple-progress.json","rodroid",
            "menu-spec.json","menu-result.json","menu-preflight.json","menu-validation.json","menu-auto-prepare.json","menu-auto-confirm.json","menu-autopilot.json","menu-project",
            "menu-payload-report.json","menu-apk-report.json","menu-payload-build.zip","menu-unsigned.apk",
            "target-signed.apk","target-signed.apks","target-signed-set",
            "connected-report.json","connected-report.md","evidence-bundle.zip"
        };
        for(String name:names)deleteTree(app.file(name));
        getSharedPreferences("state",0).edit().remove("selections").remove("active.project").remove("metadata.bin").remove("library.so").apply();
    }
    private static String safeName(String value){String s=value==null?"split.apk":value.replaceAll("[^A-Za-z0-9._-]+","_");return s.isEmpty()?"split.apk":s;}
    private static void copy(File source,File dest)throws Exception{try(FileInputStream in=new FileInputStream(source);FileOutputStream out=new FileOutputStream(dest)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1)out.write(buf,0,n);}}
    private static String sha256(File file)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(FileInputStream in=new FileInputStream(file)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1)d.update(buf,0,n);}StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b));return s.toString();}
    private static void deleteTree(File file){if(file==null||!file.exists())return;if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);}file.delete();}
}
