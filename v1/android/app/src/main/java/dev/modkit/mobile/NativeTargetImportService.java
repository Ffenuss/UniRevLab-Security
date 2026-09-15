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

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Imports one exact ELF entry from the canonical target into Native Workspace. */
public class NativeTargetImportService extends Service {
    private static final int NOTE_ID=99;
    private App app;private PowerManager.WakeLock wake;private volatile long lastNote;

    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("native-target-import","Native target import",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,NativeTargetImportService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,NativeWorkspaceActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"native-target-import").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · Native target").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);long now=System.currentTimeMillis();if(now-lastNote>800L){lastNote=now;((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}}
    private void check()throws java.io.InterruptedIOException{if(app.cancelled.get()||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("Native target import cancelled");}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("Native target: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Проверяю canonical target…"));wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:native-target-import");wake.acquire(30L*60L*1000L);getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        final Intent request=intent;
        new Thread(()->{try{runImport(request);}catch(Throwable e){AnalysisJournal.exception(this,e instanceof OutOfMemoryError?"NATIVE_TARGET_IMPORT_OOM":"NATIVE_TARGET_IMPORT_FAILED",e);progress(app.cancelled.get()?"Native target import отменён.":"Native target import заблокирован: "+e.getClass().getSimpleName()+" · "+safeMessage(e));}finally{if(wake!=null&&wake.isHeld())wake.release();getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();}},"modkit-native-target-import").start();return START_NOT_STICKY;
    }

    private void runImport(Intent intent)throws Exception{
        if(intent==null)throw new IOException("Native target request отсутствует");int splitIndex=intent.getIntExtra("splitIndex",-1);String entryName=intent.getStringExtra("entry");if(splitIndex<0||entryName==null||entryName.isEmpty())throw new IOException("Не задан exact split/ELF entry");
        TargetResolver.Target target=TargetResolver.resolve(app);JSONObject verification=TargetResolver.requireVerified(target,app.cancelled);check();NativeTargetLocator.Entry entry=NativeTargetLocator.resolve(target,splitIndex,entryName,app.cancelled);check();
        progress("Native target: извлекаю "+entry.member.name+"!"+entry.zipEntry+"…");File source=app.file("native-source.so"),working=app.file("native-working.so"),state=app.file("native-state.json"),info=app.file("native-info.json");String entrySha=NativeTargetLocator.extract(entry,source,app.cancelled,this::progress);check();
        Files.deleteIfExists(app.file("native-search.json").toPath());Files.deleteIfExists(app.file("native-disasm.json").toPath());Files.deleteIfExists(app.file("native-xrefs.json").toPath());Files.deleteIfExists(working.toPath());Files.deleteIfExists(state.toPath());Files.deleteIfExists(info.toPath());
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject result=Python.getInstance().getModule("modkit.mobile.engine").callAttr("native_workspace_create",source.getPath(),working.getPath(),state.getPath(),new Progress());check();Files.write(info.toPath(),result.toString().getBytes(StandardCharsets.UTF_8));
        JSONObject binding=new JSONObject().put("schema","modkit-native-target-source-1.0").put("targetId",target.targetId).put("targetDigest",verification.optString("currentTargetDigest")).put("splitIndex",entry.member.index).put("splitName",entry.member.name).put("splitExpectedSha256",entry.member.sha256).put("apkPath",entry.member.file.getCanonicalPath()).put("entry",entry.zipEntry).put("abi",entry.abi).put("entrySize",source.length()).put("entrySha256",entrySha).put("createdAtMs",System.currentTimeMillis());writeAtomic(app.file("native-source.json"),binding.toString(2));getSharedPreferences("state",0).edit().putString("native-source.so",entry.member.name+"!"+entry.zipEntry).apply();AnalysisJournal.append(this,"NATIVE_TARGET_READY","Native Workspace bound to canonical target",binding);progress("Native Workspace готов: "+entry.member.name+"!"+entry.zipEntry+" · "+entry.abi+" · target SHA verified.");
    }

    public final class Progress {public boolean isCancelled(){return app.cancelled.get();}public void progress(String text){NativeTargetImportService.this.progress(text);}}
    private static void writeAtomic(File destination,String text)throws Exception{File tmp=new File(destination.getParentFile(),destination.getName()+".part");Files.deleteIfExists(tmp.toPath());try{Files.write(tmp.toPath(),text.getBytes(StandardCharsets.UTF_8));Files.move(tmp.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}}
    private static String safeMessage(Throwable e){String m=e==null?null:e.getMessage();return m==null?(e==null?"unknown":e.getClass().getSimpleName()):m;}
}
