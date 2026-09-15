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

/** Verifies that a File Workspace patch still belongs to the current canonical target before build. */
public class WorkspaceBuildGuardService extends Service {
    private static final int NOTE_ID=100;
    private App app;private PowerManager.WakeLock wake;

    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("workspace-build-guard","File Workspace build verification",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,WorkspaceBuildGuardService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,FileWorkspaceActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"workspace-build-guard").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · File Workspace build gate").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    private void check()throws java.io.InterruptedIOException{if(app.cancelled.get()||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("Workspace build cancelled");}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("File Workspace build: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Проверяю canonical target…"));wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:workspace-build-guard");wake.acquire(20L*60L*1000L);getSharedPreferences("state",0).edit().putBoolean("running",true).apply();final Intent request=intent;
        new Thread(()->{boolean handedOff=false;Uri destination=null;try{
            String uriText=request==null?null:request.getStringExtra("uri");if(uriText==null||uriText.isEmpty())throw new IOException("Не выбран файл назначения");destination=Uri.parse(uriText);check();File bindingFile=app.file("workspace-source.json");File patch=app.file("workspace-patch.zip");if(!bindingFile.isFile()||!patch.isFile())throw new IOException("Workspace patch/binding отсутствует; подготовьте Patch Pack заново");JSONObject binding=new JSONObject(Io.readUtf8(bindingFile));
            TargetResolver.Target target=TargetResolver.resolve(app);JSONObject verification=TargetResolver.requireVerified(target,app.cancelled);check();verifyBinding(target,binding);String source=binding.getString("sourceApk");
            progress("File Workspace build: canonical target SHA verified · передаю в patch/signing pipeline…");Intent worker=new Intent(this,WorkerService.class).putExtra("op","workspace_build").putExtra("source",source).putExtra("uri",destination.toString());startForegroundService(worker);handedOff=true;AnalysisJournal.append(this,"WORKSPACE_BUILD_HANDOFF","File Workspace target verified",new JSONObject().put("targetDigest",verification.optString("currentTargetDigest")).put("sourceApk",source).put("targetEntry",binding.optString("targetEntry")));
        }catch(Throwable e){AnalysisJournal.exception(this,"WORKSPACE_BUILD_BLOCKED",e);if(destination!=null&&!handedOff)try{DocumentsContract.deleteDocument(getContentResolver(),destination);}catch(Exception ignored){}progress(app.cancelled.get()?"File Workspace build отменён.":"File Workspace build заблокирован: "+safeMessage(e));}
        finally{if(wake!=null&&wake.isHeld())wake.release();if(!handedOff){getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;}stopForeground(true);stopSelf();}},"modkit-workspace-build-guard").start();return START_NOT_STICKY;
    }

    private void verifyBinding(TargetResolver.Target target,JSONObject binding)throws Exception{
        String expectedId=binding.optString("targetId","");if(!expectedId.isEmpty()&&!expectedId.equals(target.targetId))throw new IOException("Workspace patch относится к другому targetId");String expectedFingerprint=binding.optString("targetFingerprint","");if(!expectedFingerprint.isEmpty()&&!expectedFingerprint.equals(target.fingerprint))throw new IOException("Workspace patch относится к другой версии APK-set");
        String source=binding.optString("sourceApk","");if(source.isEmpty())throw new IOException("Workspace source APK не записан");String canonical=new File(source).getCanonicalPath();int expectedIndex=binding.optInt("sourceSplitIndex",Integer.MIN_VALUE);boolean found=false;
        for(TargetResolver.Member member:target.members){if(member.file.getCanonicalPath().equals(canonical)){if(expectedIndex!=Integer.MIN_VALUE&&member.index!=expectedIndex)throw new IOException("Workspace split index изменился");found=true;break;}}
        if(!found)throw new IOException("Workspace source APK больше не принадлежит текущему target");
    }
    private static String safeMessage(Throwable e){String m=e==null?null:e.getMessage();return m==null?(e==null?"unknown":e.getClass().getSimpleName()):m;}
}
