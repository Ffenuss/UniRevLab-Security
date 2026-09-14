package dev.modkit.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

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

/** Runs the complete in-app reconstruction before Simple Mode's evidence pipeline. */
public class FullAnalysisService extends Service {
    private App app;
    @Override public void onCreate(){
        super.onCreate();app=(App)getApplication();
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("full-analysis","Полная реконструкция",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){
        Intent stop=new Intent(this,FullAnalysisService.class).setAction("cancel");
        PendingIntent cancel=PendingIntent.getService(this,92,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open=PendingIntent.getActivity(this,91,new Intent(this,SimpleModeActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"full-analysis").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · полный анализ").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
    }
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(91,note(text));}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){
            app.cancelled.set(true);
            progress("Отмена запрошена — завершаю текущий безопасный шаг…");
            return START_NOT_STICKY;
        }
        startForeground(91,note("Подготовка полного workspace…"));
        new Thread(()->{
            boolean chain=true;
            try{
                List<File> inputs=DecompilerEngine.resolveTargetInputs(app);
                if(inputs.isEmpty())throw new java.io.FileNotFoundException("Сначала выберите APK или установленный пакет.");
                String digest=targetDigest(inputs);
                File manifest=app.file("full-reconstruction.json");
                boolean cached=false;
                if(manifest.isFile()&&app.file("modkit-decompiled.zip").isFile()){
                    try{JSONObject old=new JSONObject(Io.readUtf8(manifest));cached=digest.equals(old.optString("targetDigest"))&&old.optBoolean("complete");}catch(Exception ignored){}
                }
                if(cached){progress("JADX: кэш hit · target не изменился.");}
                else{
                    progress("1/3 · JADX: декомпилирую все classes*.dex и resources во всех split APK…");
                    JSONObject state=new JSONObject().put("schema","modkit-full-reconstruction-1.1").put("targetDigest",digest).put("complete",false).put("startedAtMs",System.currentTimeMillis());
                    Files.write(manifest.toPath(),state.toString(2).getBytes(StandardCharsets.UTF_8));
                    try(DecompilerEngine dec=new DecompilerEngine(this)){
                        dec.open();
                        if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        File zip=dec.exportAllZip(app.cancelled);
                        if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        state.put("complete",true).put("backend",DecompilerEngine.BACKEND).put("classCount",dec.classCount()).put("resourceCount",dec.resourceCount()).put("errors",dec.errorCount()).put("warnings",dec.warnCount()).put("output",zip.getName()).put("finishedAtMs",System.currentTimeMillis());
                        JSONArray names=new JSONArray();for(File f:dec.inputFiles())names.put(f.getName());state.put("inputs",names);
                    }catch(Exception decompileError){
                        state.put("complete",false).put("cancelled",app.cancelled.get()).put("error",String.valueOf(decompileError.getMessage())).put("finishedAtMs",System.currentTimeMillis());
                        if(!app.cancelled.get())progress("JADX частичен: "+decompileError.getMessage()+" · продолжаю встроенные backend'ы.");
                    }
                    Files.write(manifest.toPath(),state.toString(2).getBytes(StandardCharsets.UTF_8));
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}

                progress("2/3 · Apktool 3.0.2: resources + manifest + полный smali workspace…");
                try{
                    JSONObject apktool=ApktoolEngine.analyze(this,inputs,app.cancelled);
                    Files.write(app.file("apktool-analysis.json").toPath(),apktool.toString(2).getBytes(StandardCharsets.UTF_8));
                    int failed=apktool.optInt("failed");
                    progress("Apktool: decoded="+apktool.optInt("decoded")+" · cache="+apktool.optInt("cached")+(failed>0?" · errors="+failed:"")+".");
                }catch(Throwable apktoolError){
                    JSONObject error=new JSONObject().put("schema","modkit-apktool-analysis-1.0").put("engineId",ApktoolEngine.ENGINE_ID).put("bundled",true).put("status","FAILED").put("error",String.valueOf(apktoolError.getMessage()));
                    Files.write(app.file("apktool-analysis.json").toPath(),error.toString(2).getBytes(StandardCharsets.UTF_8));
                    progress("Apktool частичен: "+apktoolError.getMessage()+" · остальные backend'ы продолжаются.");
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));

                progress("3/3 · Встроенные Lua/JS/Hermes deep/Flutter/Cocos backend'ы…");
                try{
                    Python.getInstance().getModule("modkit.mobile.embedded_pipeline").callAttr(
                            "run_workspace",
                            getFilesDir().getPath(),
                            app.file("artifact-families.json").getPath(),
                            app.file("embedded-analysis.json").getPath());
                }catch(Throwable embeddedError){
                    progress("Embedded pipeline частичен: "+embeddedError.getMessage()+" · перехожу к evidence pipeline.");
                }
                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");}
            }catch(Exception e){
                progress(app.cancelled.get()?"Полный анализ отменён.":"Полная реконструкция: "+e.getMessage()+" · перехожу к доступным анализаторам.");
                if(app.cancelled.get())chain=false;
            }finally{
                if(chain&&!app.cancelled.get()){
                    progress("Встроенная реконструкция готова · запускаю Evidence Graph…");
                    Intent next=new Intent(this,WorkerService.class).putExtra("op","simple_prepare");startForegroundService(next);
                }else{
                    app.busy.set(false);app.revision++;
                }
                stopForeground(true);stopSelf();
            }
        },"modkit-full-reconstruction").start();
        return START_NOT_STICKY;
    }

    private static String targetDigest(List<File> files)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[1024*1024];
        for(File f:files){d.update(f.getCanonicalPath().getBytes(StandardCharsets.UTF_8));d.update(Long.toString(f.length()).getBytes(StandardCharsets.UTF_8));try(FileInputStream in=new FileInputStream(f)){int n;while((n=in.read(buf))!=-1)d.update(buf,0,n);}}
        StringBuilder out=new StringBuilder();for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }
}
