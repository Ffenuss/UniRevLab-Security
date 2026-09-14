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

/** Runs the expensive complete reconstruction before Simple Mode's evidence pipeline. */
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
        return new Notification.Builder(this,"full-analysis").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · полная реконструкция").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
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
                if(cached){progress("Полная реконструкция: кэш hit · target не изменился.");}
                else{
                    progress("Полная реконструкция: JADX декомпилирует все classes*.dex и resources во всех split APK…");
                    JSONObject state=new JSONObject().put("schema","modkit-full-reconstruction-1.0").put("targetDigest",digest).put("complete",false).put("startedAtMs",System.currentTimeMillis());
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
                        if(!app.cancelled.get())progress("Полная реконструкция частична: "+decompileError.getMessage()+" · продолжаю остальные анализаторы.");
                    }
                    Files.write(manifest.toPath(),state.toString(2).getBytes(StandardCharsets.UTF_8));
                }
                if(app.cancelled.get()){chain=false;progress("Полная реконструкция отменена пользователем.");return;}
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));
                progress("Полная реконструкция: Lua/JS/Hermes/Flutter/Cocos inventory…");
                Python.getInstance().getModule("modkit.mobile.artifact_families").callAttr("scan_workspace",getFilesDir().getPath(),app.file("artifact-families.json").getPath());
                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");}
            }catch(Exception e){
                progress(app.cancelled.get()?"Полный анализ отменён.":"Полная реконструкция: "+e.getMessage()+" · перехожу к доступным анализаторам.");
                if(app.cancelled.get())chain=false;
            }finally{
                if(chain&&!app.cancelled.get()){
                    progress("Реконструкция готова · запускаю evidence pipeline…");
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
