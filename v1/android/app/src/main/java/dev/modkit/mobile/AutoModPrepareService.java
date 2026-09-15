package dev.modkit.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.PowerManager;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;

/**
 * Foreground AutoMod prepare path which keeps recovered no-RVA addresses inside the
 * existing Deep Resolver -> binding confirmation -> APK ELF preflight gates.
 */
public class AutoModPrepareService extends Service {
    private static final int NOTE_ID=97;
    private App app;
    private PowerManager.WakeLock wake;
    private volatile long lastNote;

    public final class Progress {
        public boolean isCancelled(){return app.cancelled.get();}
        public void progress(String text){app.progress(text);long now=System.currentTimeMillis();if(now-lastNote>1000){lastNote=now;notifyProgress(text);}}
    }

    @Override public void onCreate(){
        super.onCreate();app=(App)getApplication();
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(
                new NotificationChannel("automod-prepare","AutoMod prepare",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public IBinder onBind(Intent intent){return null;}

    private Notification note(String text){
        Intent stop=new Intent(this,AutoModPrepareService.class).setAction("cancel");
        PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,AutoModActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"automod-prepare").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · AutoMod prepare").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
    }
    private void notifyProgress(String text){((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    private void progress(String text){app.progress(text);notifyProgress(text);}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("AutoMod: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Проверка exact recovered RVA и Deep Resolver…"));
        wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:automod-prepare");wake.acquire(45L*60L*1000L);
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            try{prepare();}
            catch(Exception e){
                String cleanup="";
                try{invalidatePreparedState();}catch(Exception cleanupError){cleanup=" · очистка partial prepare: "+String.valueOf(cleanupError.getMessage());}
                AnalysisJournal.exception(this,"AUTOMOD_PREPARE_BLOCKED",e);
                progress((app.cancelled.get()?"AutoMod prepare отменён.":"AutoMod prepare заблокирован: "+String.valueOf(e.getMessage()))+cleanup);
            }
            finally{if(wake!=null&&wake.isHeld())wake.release();getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();}
        },"modkit-automod-prepare").start();
        return START_NOT_STICKY;
    }

    private void prepare()throws Exception{
        check();
        File metadata=app.file("metadata.bin"),library=app.file("library.so"),catalog=app.file("analysis.methods.jsonl");
        if(!metadata.isFile()||!library.isFile()||!catalog.isFile())throw new IOException("Нужен завершённый IL2CPP-анализ: metadata.bin + library.so + method catalog");
        TargetResolver.Target target=TargetResolver.resolve(app);JSONObject targetVerification=TargetResolver.requireVerified(target,app.cancelled);File source=target.patchOwnerApk();
        if(!source.isFile())throw new IOException("Owning APK для подготовки меню не найден");
        invalidatePreparedState();
        progress("AutoMod: canonical target SHA verified · exact CodeGenModule recovery → Deep Resolver → binding/preflight…");
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));
        PyObject result=Python.getInstance().getModule("modkit.mobile.menu_native_recovery").callAttr("prepare_workspace",getFilesDir().getPath(),source.getPath(),new Progress());
        check();
        progress("AutoMod: проверяю exact SHA-256 всех prepare-входов…");
        JSONObject audit=AutoModAuditVerifier.verifyCurrent(app,source,()->app.cancelled.get());
        JSONObject obj=new JSONObject(result.toString());JSONObject confirm=obj.optJSONObject("confirm"),pre=obj.optJSONObject("preflight");JSONArray promoted=confirm==null?null:confirm.optJSONArray("promoted"),rejected=confirm==null?null:confirm.optJSONArray("rejected");
        int promotedCount=promoted==null?0:promoted.length(),rejectedCount=rejected==null?0:rejected.length();boolean ready=pre!=null&&pre.optBoolean("readyForAutoBuild");
        AnalysisJournal.append(this,"AUTOMOD_PREPARE_READY","AutoMod exact prepare finished",new JSONObject().put("targetDigest",targetVerification.optString("currentTargetDigest")).put("sourceApk",source.getAbsolutePath()).put("promoted",promotedCount).put("rejected",rejectedCount).put("ready",ready));
        progress("AutoMod prepare: target + exact SHA verified · audit calls "+audit.optInt("calls")+", подтверждено bindings "+promotedCount+", отклонено "+rejectedCount+", auto-build "+(ready?"READY":"BLOCK/REVIEW")+". Recovered RVA не обходит preflight.");
    }

    private void invalidatePreparedState()throws IOException{
        for(String name:new String[]{"menu-spec.json","menu-preflight.json","menu-validation.json","menu-auto-confirm.json","menu-autopilot.json","menu-native-recovery.json","menu-native-recovery.json.tmp"}){
            File file=app.file(name);if(file.exists()&&!file.delete())throw new IOException("Не удалось инвалидировать старый AutoMod artifact: "+name);
        }
    }

    private void check()throws IOException{if(app.cancelled.get())throw new IOException("Операция отменена");}
}
