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

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;

/** Final exact-SHA gate before handing an AutoMod build to the legacy build worker. */
public class AutoModBuildGuardService extends Service {
    private static final int NOTE_ID=98;
    private App app;
    private PowerManager.WakeLock wake;

    @Override public void onCreate(){
        super.onCreate();app=(App)getApplication();
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(
                new NotificationChannel("automod-build-guard","AutoMod build verification",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public IBinder onBind(Intent intent){return null;}

    private Notification note(String text){
        Intent stop=new Intent(this,AutoModBuildGuardService.class).setAction("cancel");
        PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,AutoModActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"automod-build-guard").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · AutoMod build gate").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
    }
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("AutoMod build: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Проверяю canonical target и exact SHA перед сборкой…"));
        wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:automod-build-guard");wake.acquire(20L*60L*1000L);
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            boolean handedOff=false;
            Uri destination=null;
            try{
                String uriText=intent==null?null:intent.getStringExtra("uri");
                if(uriText==null||uriText.isEmpty())throw new IOException("Не выбран файл назначения AutoMod APK");
                destination=Uri.parse(uriText);
                check();
                TargetResolver.Target target=TargetResolver.resolve(app);JSONObject targetVerification=TargetResolver.requireVerified(target,app.cancelled);File source=target.patchOwnerApk();
                progress("AutoMod build: target SHA verified · пересобираю canonical preflight из текущего MenuSpec/source APK…");
                JSONObject preflight=AutoModAuditVerifier.refreshCanonicalPreflight(app,source,()->app.cancelled.get());
                JSONObject audit=AutoModAuditVerifier.verifyCurrent(app,source,()->app.cancelled.get());
                check();
                if(!preflight.optBoolean("readyForAutoBuild"))throw new IOException("AutoMod preflight больше не READY; повторите Exact prepare");
                JSONObject counts=preflight.optJSONObject("counts");
                int callableVerified=counts==null?0:counts.optInt("callableVerified",0);
                int parameterPending=preflight.optInt("parameterPolicyPending",0);
                Intent worker=new Intent(this,WorkerService.class).putExtra("op","menu_build_apk").putExtra("uri",destination.toString());
                startForegroundService(worker);
                handedOff=true;
                AnalysisJournal.append(this,"AUTOMOD_BUILD_HANDOFF","AutoMod build target + canonical preflight verified",
                        new JSONObject().put("targetDigest",targetVerification.optString("currentTargetDigest"))
                                .put("sourceApk",source.getAbsolutePath())
                                .put("phase7FreshnessPolicy",audit.optString("phase7FreshnessPolicy"))
                                .put("readyForModificationPayload",preflight.optBoolean("readyForModificationPayload"))
                                .put("readyForProbePayload",preflight.optBoolean("readyForProbePayload"))
                                .put("callableVerified",callableVerified)
                                .put("parameterPolicyPending",parameterPending));
                progress("AutoMod build: canonical target + exact SHA + canonical preflight актуальны · передаю в штатную signing сборку…");
            }catch(Exception e){
                AnalysisJournal.exception(this,"AUTOMOD_BUILD_BLOCKED",e);
                if(destination!=null&&!handedOff)try{DocumentsContract.deleteDocument(getContentResolver(),destination);}catch(Exception ignored){}
                progress(app.cancelled.get()?"AutoMod build отменён.":"AutoMod build заблокирован: "+String.valueOf(e.getMessage()));
            }finally{
                if(wake!=null&&wake.isHeld())wake.release();
                if(!handedOff){getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;}
                stopForeground(true);stopSelf();
            }
        },"modkit-automod-build-guard").start();
        return START_NOT_STICKY;
    }

    private void check()throws IOException{if(app.cancelled.get())throw new java.io.InterruptedIOException("AutoMod build cancelled");}
}
