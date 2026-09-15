package dev.modkit.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;

/** Runs reconstruction backends, then hands off to the isolated automatic evidence service. */
public class FullAnalysisService extends Service {
    private App app;
    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("full-analysis","Полный анализ",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,FullAnalysisService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,92,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,91,new Intent(this,AutoAnalysisActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"full-analysis").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · полный анализ").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(91,note(text));}

    /** Chaquopy callback shared with inventory and embedded backends. */
    public final class Progress {
        public boolean isCancelled(){return app.cancelled.get();}
        public void progress(String text){FullAnalysisService.this.progress(text);}
    }

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("Отмена запрошена — завершаю текущий безопасный шаг…");return START_NOT_STICKY;}
        startForeground(91,note("Подготовка полного анализа…"));
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            boolean chain=true;
            try{
                List<File> inputs=DecompilerEngine.resolveTargetInputs(app);
                if(inputs.isEmpty())throw new java.io.FileNotFoundException("Сначала выберите APK или установленный пакет.");
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));

                progress("1/4 · Inventory: APK/split, DEX, native, Unity/IL2CPP и runtime-маркеры…");
                String scanJson=runInventory(inputs);
                normalizeInstalledTarget(scanJson);
                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}

                progress("Проверяю fingerprint выбранного APK/APK-set…");
                String digest=targetDigest(inputs);
                File manifest=app.file("full-reconstruction.json");
                boolean cached=false;
                if(manifest.isFile()&&app.file("modkit-decompiled.zip").isFile()){
                    try{JSONObject old=new JSONObject(Io.readUtf8(manifest));cached=digest.equals(old.optString("targetDigest"))&&old.optBoolean("complete");}catch(Exception ignored){}
                }
                if(cached)progress("2/4 · JADX: cache hit · target не изменился.");
                else{
                    progress("2/4 · JADX: все classes*.dex и resources во всех split APK…");
                    JSONObject state=new JSONObject().put("schema","modkit-full-reconstruction-1.1").put("targetDigest",digest).put("complete",false).put("startedAtMs",System.currentTimeMillis());
                    Files.write(manifest.toPath(),state.toString(2).getBytes(StandardCharsets.UTF_8));
                    try(DecompilerEngine dec=new DecompilerEngine(this)){
                        dec.open();if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        File zip=dec.exportAllZip(app.cancelled);if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        state.put("complete",true).put("backend",DecompilerEngine.BACKEND).put("classCount",dec.classCount()).put("resourceCount",dec.resourceCount()).put("errors",dec.errorCount()).put("warnings",dec.warnCount()).put("output",zip.getName()).put("finishedAtMs",System.currentTimeMillis());
                        JSONArray names=new JSONArray();for(File f:dec.inputFiles())names.put(f.getName());state.put("inputs",names);
                    }catch(Exception e){
                        state.put("complete",false).put("cancelled",app.cancelled.get()).put("error",String.valueOf(e.getMessage())).put("finishedAtMs",System.currentTimeMillis());
                        if(!app.cancelled.get())progress("JADX частичен: "+e.getMessage()+" · продолжаю остальные backend'ы.");
                    }
                    Files.write(manifest.toPath(),state.toString(2).getBytes(StandardCharsets.UTF_8));
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                progress("3/4 · Apktool "+ApktoolEngine.APKTOOL_VERSION+": resources + manifest + полный smali workspace…");
                try{
                    JSONObject apktool=ApktoolEngine.analyze(this,inputs,app.cancelled);
                    Files.write(app.file("apktool-analysis.json").toPath(),apktool.toString(2).getBytes(StandardCharsets.UTF_8));
                    int failed=apktool.optInt("failed");progress("Apktool: decoded="+apktool.optInt("decoded")+" · cache="+apktool.optInt("cached")+(failed>0?" · errors="+failed:"")+".");
                }catch(Throwable e){
                    JSONObject error=new JSONObject().put("schema","modkit-apktool-analysis-1.0").put("engineId",ApktoolEngine.ENGINE_ID).put("bundled",true).put("status","FAILED").put("error",String.valueOf(e.getMessage()));
                    Files.write(app.file("apktool-analysis.json").toPath(),error.toString(2).getBytes(StandardCharsets.UTF_8));
                    if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                    progress("Apktool частичен: "+e.getMessage()+" · остальные backend'ы продолжаются.");
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                progress("4/4 · Lua/JS/Hermes deep + ARM64 deep + Flutter AOT + Cocos correlation…");
                try{
                    Python.getInstance().getModule("modkit.mobile.embedded_pipeline").callAttr(
                            "run_workspace",getFilesDir().getPath(),
                            app.file("artifact-families.json").getPath(),
                            app.file("embedded-analysis.json").getPath(),new Progress());
                }catch(Throwable e){
                    if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                    progress("Embedded pipeline частичен: "+e.getMessage()+" · Evidence Graph всё равно будет построен.");
                }
                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");}
            }catch(Exception e){
                progress(app.cancelled.get()?"Полный анализ отменён.":"Полный анализ: "+e.getMessage()+" · продолжаю доступными анализаторами.");
                if(app.cancelled.get())chain=false;
            }finally{
                boolean handedOff=false;
                if(chain&&!app.cancelled.get()){
                    progress("Реконструкция готова · передаю в изолированный Evidence Graph pipeline…");
                    try{
                        startForegroundService(new Intent(this,AutomaticEvidenceService.class));
                        handedOff=true;
                    }catch(Exception handoffError){
                        progress("Не удалось запустить Evidence Graph: "+handoffError.getMessage());
                    }
                }
                if(!handedOff){
                    getSharedPreferences("state",0).edit().putBoolean("running",false).apply();
                    app.busy.set(false);app.revision++;
                }
                stopForeground(true);stopSelf();
            }
        },"modkit-full-analysis").start();
        return START_NOT_STICKY;
    }

    private String runInventory(List<File> inputs)throws Exception{
        JSONArray paths=new JSONArray();for(File file:inputs)paths.put(file.getCanonicalPath());
        PyObject module=Python.getInstance().getModule("modkit.mobile.apkset");
        PyObject result=module.callAttr("inspect_apk_paths",paths.toString(),app.file("metadata.bin").getPath(),app.file("library.so").getPath(),app.file("installed-scan.json").getPath(),new Progress(),false);
        String json=result.toString();new JSONObject(json);return json;
    }

    private void normalizeInstalledTarget(String scanJson)throws Exception{
        File targetFile=app.file("installed-target.json");if(!targetFile.isFile())return;
        JSONObject previous=new JSONObject(Io.readUtf8(targetFile));
        String packageName=previous.optString("packageName",previous.optString("package",""));
        if(packageName.isEmpty())return;
        String label=previous.optString("label","");
        String versionName=previous.optString("versionName","");
        long versionCode=previous.optLong("versionCode",0);
        int expected=previous.optInt("expectedApkCount",previous.optJSONArray("splits")!=null?previous.optJSONArray("splits").length():0);
        PyObject result=Python.getInstance().getModule("modkit.mobile.package_target").callAttr("build_target_manifest",scanJson,packageName,label,versionName,versionCode,expected,"[]");
        JSONObject normalized=new JSONObject(result.toString());
        Files.write(targetFile.toPath(),normalized.toString(2).getBytes(StandardCharsets.UTF_8));
    }

    private String targetDigest(List<File> files)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[1024*1024];
        for(File f:files){
            if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
            d.update(f.getCanonicalPath().getBytes(StandardCharsets.UTF_8));d.update(Long.toString(f.length()).getBytes(StandardCharsets.UTF_8));
            try(FileInputStream in=new FileInputStream(f)){
                int n;while((n=in.read(buf))!=-1){if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");d.update(buf,0,n);}
            }
        }
        StringBuilder out=new StringBuilder();for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }
}
