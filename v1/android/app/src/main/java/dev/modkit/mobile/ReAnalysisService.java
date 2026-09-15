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
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

/** Manual RE Workspace service backed by the same canonical APK-set target as Full Analysis. */
public class ReAnalysisService extends Service {
    private static final int NOTE_ID=97;
    private App app;private PowerManager.WakeLock wake;private volatile long lastNote;

    public final class Progress {
        public boolean isCancelled(){return app.cancelled.get();}
        public void progress(String text){ReAnalysisService.this.progress(text);}
    }

    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("re-analysis","RE Workspace",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,ReAnalysisService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,ReWorkspaceActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"re-analysis").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · RE Workspace").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);long now=System.currentTimeMillis();if(now-lastNote>800){lastNote=now;((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}}
    private void check()throws java.io.InterruptedIOException{if(app.cancelled.get()||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("RE-анализ отменён");}
    private PyObject engine(){if(!Python.isStarted())Python.start(new AndroidPlatform(this));return Python.getInstance().getModule("modkit.mobile.engine");}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("RE Workspace: отмена запрошена…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Подготовка RE Workspace…"));
        wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:re-analysis");wake.acquire(90L*60L*1000L);
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            try{
                runAnalysis();
            }catch(Throwable e){
                AnalysisJournal.exception(this,e instanceof OutOfMemoryError?"RE_WORKSPACE_OOM":"RE_WORKSPACE_FAILURE",e);
                progress(app.cancelled.get()?"RE-анализ отменён.":"RE-анализ остановлен: "+e.getClass().getSimpleName()+" · "+safeMessage(e));
            }finally{
                if(wake!=null&&wake.isHeld())wake.release();getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();
            }
        },"modkit-re-analysis").start();return START_NOT_STICKY;
    }

    private void runAnalysis()throws Exception{
        TargetResolver.Target target=TargetResolver.resolve(app);check();
        AnalysisJournal.append(this,"RE_START","RE Workspace started",TargetResolver.describe(target));
        File extractedMeta=app.file("re-metadata.bin"),extractedLib=app.file("re-library.so"),rod=app.file("re-rodroid");
        File selectedMeta=target.selectedMetadataCopy(),selectedLib=target.selectedLibraryCopy();
        File mainRod=app.file("rodroid"),mainAnalysis=app.file("analysis.json"),mainSummary=app.file("analysis.summary.json");
        File scanReport=app.file("re-apkset-scan.json"),unityReport=app.file("re-unity.json"),il2cppReport=app.file("re-il2cpp-analysis.json");
        File fullReport=app.file("re-analysis.json"),uiReport=app.file("re-analysis.ui.json"),menuReport=app.file("re-analysis.menu.json");
        for(File f:new File[]{extractedMeta,extractedLib,scanReport,unityReport,il2cppReport,fullReport,uiReport,menuReport,app.file("re-analysis.json.tmp"),app.file("re-analysis.ui.json.tmp"),app.file("re-analysis.menu.json.tmp")})Files.deleteIfExists(f.toPath());
        deleteTree(rod);check();
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));
        JSONArray paths=new JSONArray();for(File f:target.apkFiles())paths.put(f.getCanonicalPath());String pathsJson=paths.toString();

        progress("RE Workspace: инвентаризация всех APK/split и поиск IL2CPP-пары…");
        PyObject apkset=Python.getInstance().getModule("modkit.mobile.apkset");
        JSONObject scan=new JSONObject(apkset.callAttr("inspect_apk_paths",pathsJson,extractedMeta.getPath(),extractedLib.getPath(),scanReport.getPath(),new Progress(),false).toString());
        check();
        progress("RE Workspace: Unity/Addressables во всех APK/split…");
        Python.getInstance().getModule("modkit.mobile.unityscan").callAttr("inspect_apk_paths",pathsJson,unityReport.getPath(),new Progress());
        check();

        boolean apkPair=scan.optBoolean("fullIl2cppPair")&&extractedMeta.isFile()&&extractedLib.isFile();
        boolean selectedPair=selectedMeta!=null&&selectedLib!=null&&selectedMeta.isFile()&&selectedLib.isFile();
        File meta=apkPair?extractedMeta:(selectedPair?selectedMeta:null),lib=apkPair?extractedLib:(selectedPair?selectedLib:null);
        String inputMode=target.apkSet?"canonical-apk-set":"canonical-single-apk";
        inputMode+="+"+(apkPair?"apkset-extracted-pair":selectedPair?"selected-pair":"no-il2cpp-pair");
        if(meta==null||lib==null)progress("RE Workspace: полная IL2CPP-пара не найдена; DEX/native/Unity correlation продолжится без managed method binding.");

        String rodPath=null,il2cppPath=null;
        if(meta!=null&&lib!=null){
            boolean reuseMain=mainAnalysis.isFile()&&mainSummary.isFile()&&mainRod.isDirectory()&&selectedMeta!=null&&selectedLib!=null&&sameFile(meta,selectedMeta)&&sameFile(lib,selectedLib);
            if(reuseMain){progress("RE Workspace: точная IL2CPP-пара совпала с текущим Rodroid-анализом — переиспользую проверенный dump.");rodPath=mainRod.getPath();il2cppPath=mainAnalysis.getPath();inputMode+="+reused-rodroid";}
            else{
                try{
                    progress("RE Workspace: Rodroid dump точной metadata/libil2cpp пары…");File dump=RodroidRunner.run(this,lib,meta,rod,app.cancelled,new Progress()::progress);rodPath=dump.getPath();engine().callAttr("analyze_rodroid",dump.getPath(),meta.getPath(),lib.getPath(),il2cppReport.getPath(),new Progress());il2cppPath=il2cppReport.getPath();
                }catch(Throwable dumpError){if(app.cancelled.get())check();AnalysisJournal.exception(this,dumpError instanceof OutOfMemoryError?"RE_RODROID_OOM":"RE_RODROID_PARTIAL",dumpError);progress("Rodroid частичен: "+dumpError.getClass().getSimpleName()+" · продолжаю статическую корреляцию.");System.gc();}
            }
        }
        check();File reTarget=TargetResolver.prepareAnalysisContainer(target,app.cancelled,new Progress()::progress);
        progress("RE Workspace: корреляция DEX + metadata + dump + всех .so во всём target…");
        PyObject result=engine().callAttr("re_analyze_apk",reTarget.getPath(),fullReport.getPath(),meta==null?null:meta.getPath(),lib==null?null:lib.getPath(),rodPath,unityReport.isFile()?unityReport.getPath():null,il2cppPath,new Progress(),inputMode,true);
        JSONObject obj=new JSONObject(result.toString());JSONObject diag=obj.optJSONObject("pipelineDiagnostics"),proof=diag==null?null:diag.optJSONObject("methodVerification");String proofText=proof==null?"":(", method proof: "+proof.optInt("addressConfirmed",0)+" addr / "+proof.optInt("abiConfirmed",0)+" ABI / "+proof.optInt("xrefCorroborated",0)+" xref");
        AnalysisJournal.append(this,"RE_FINISH","RE Workspace finished",new JSONObject().put("findings",obj.optInt("findingCount",0)).put("il2cppXrefs",obj.optInt("il2cppXrefs",0)).put("contextMethods",obj.optInt("contextMethods",0)).put("inputMode",inputMode));
        progress("RE-анализ готов. Находок: "+obj.optInt("findingCount",0)+", IL2CPP xrefs: "+obj.optInt("il2cppXrefs",0)+", context methods: "+obj.optInt("contextMethods",0)+proofText+".");
    }

    private boolean sameFile(File a,File b)throws Exception{if(a==null||b==null||!a.isFile()||!b.isFile()||a.length()!=b.length())return false;return sha256(a).equals(sha256(b));}
    private String sha256(File file)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(FileInputStream in=new FileInputStream(file)){byte[] buf=new byte[1024*1024];int n;while((n=in.read(buf))!=-1){check();d.update(buf,0,n);}}StringBuilder s=new StringBuilder();for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b));return s.toString();}
    private void deleteTree(File file)throws IOException{if(file==null||!file.exists())return;if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);}if(!file.delete()&&file.exists())throw new IOException("Не удалось очистить "+file.getName());}
    private static String safeMessage(Throwable e){String m=e==null?null:e.getMessage();return m==null?(e==null?"unknown":e.getClass().getSimpleName()):m;}
}