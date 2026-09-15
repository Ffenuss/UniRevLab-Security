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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;

/** Runs reconstruction backends, then hands off to the isolated automatic evidence service. */
public class FullAnalysisService extends Service {
    private App app;
    private PowerManager.WakeLock wake;
    private volatile long startedAt;
    @Override public void onCreate(){super.onCreate();app=(App)getApplication();((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(new NotificationChannel("full-analysis","Полный анализ",NotificationManager.IMPORTANCE_LOW));}
    @Override public IBinder onBind(Intent intent){return null;}
    private Notification note(String text){Intent stop=new Intent(this,FullAnalysisService.class).setAction("cancel");PendingIntent cancel=PendingIntent.getService(this,92,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);PendingIntent open=PendingIntent.getActivity(this,91,new Intent(this,AutoAnalysisActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);return new Notification.Builder(this,"full-analysis").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · полный анализ").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();}
    private void progress(String text){app.progress(text);((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(91,note(text));}
    private void writeAtomicJson(String name,JSONObject value)throws Exception{
        File temp=app.file(name+".part"),dest=app.file(name);Files.deleteIfExists(temp.toPath());
        try{Files.write(temp.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(temp.toPath(),dest.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        catch(Exception e){Files.deleteIfExists(temp.toPath());throw e;}
    }
    private void stage(int index,int total,String name){
        long elapsed=Math.max(0L,System.currentTimeMillis()-startedAt);
        try{
            JSONObject row=new JSONObject().put("schema","modkit-simple-progress-1.1").put("phase","RECONSTRUCTION").put("stage",index).put("totalStages",total).put("name",name).put("remainingStages",Math.max(0,total-index)).put("elapsedMs",elapsed);
            writeAtomicJson("simple-progress.json",row);
        }catch(Exception ignored){}
        progress("Реконструкция ["+index+"/"+total+"]: "+name);
    }
    private void writePipelineState(String status,String phase,boolean complete,boolean cancelled,String error)throws Exception{
        JSONObject state=new JSONObject().put("schema","modkit-automatic-evidence-1.1").put("status",status).put("phase",phase).put("complete",complete).put("cancelled",cancelled).put("startedAtMs",startedAt).put("updatedAtMs",System.currentTimeMillis());
        if(error!=null&&!error.isEmpty())state.put("error",error);
        writeAtomicJson("automatic-evidence.json",state);
    }
    private boolean bestEffortPipelineState(String status,String phase,boolean complete,boolean cancelled,String error){
        try{writePipelineState(status,phase,complete,cancelled,error);return true;}catch(Exception ignored){return false;}
    }
    private void invalidatePreparedAutoModState()throws Exception{
        for(String name:new String[]{"automod-plan.json","automod-plan.json.part","menu-spec.json","menu-preflight.json","menu-validation.json","menu-auto-confirm.json","menu-autopilot.json","menu-native-recovery.json","menu-native-recovery.json.tmp"}){
            if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
            Files.deleteIfExists(app.file(name).toPath());
        }
    }
    private void invalidatePerRunEvidenceState()throws Exception{
        for(String name:new String[]{
                "simple-catalog.json","simple-catalog.json.part","simple-progress.json","simple-progress.json.part",
                "il2cpp-no-rva-native.json","il2cpp-no-rva-native.json.part","il2cpp-no-rva-native.methods.jsonl","il2cpp-no-rva-native.methods.jsonl.part","il2cpp-no-rva-native.failures.jsonl","il2cpp-no-rva-native.failures.jsonl.part",
                "menu-result.json","menu-auto-prepare.json","menu-auto-prepare-deep.json","menu-probe-prepare.json","menu-spec.simple-source.json","menu-payload-report.json","menu-apk-report.json",
                "connected-report.json","connected-report.json.part","connected-report.md","connected-report.md.part"}){
            if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
            Files.deleteIfExists(app.file(name).toPath());
        }
    }
    private void deleteRunTree(File file)throws Exception{
        if(file==null||!file.exists())return;
        if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
        if(file.isDirectory()){
            File[] children=file.listFiles();
            if(children!=null)for(File child:children)deleteRunTree(child);
        }
        if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
        if(!file.delete()&&file.exists())throw new java.io.IOException("Не удалось очистить старый embedded artifact: "+file.getName());
    }
    private void invalidateEmbeddedRunOutputs()throws Exception{
        for(String name:new String[]{"artifact-families.json","embedded-analysis.json","lua-deep.json","hermes-deep","hermes-deep.json","native-deep.json","cocos-deep.json","flutter-deep.json","deep-gameplay.json"}){
            deleteRunTree(app.file(name));
        }
    }

    /** Chaquopy callback shared with inventory and embedded backends. */
    public final class Progress {
        public boolean isCancelled(){return app.cancelled.get();}
        public void progress(String text){FullAnalysisService.this.progress(text);}
    }

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("Отмена запрошена — завершаю текущий безопасный шаг…");return START_NOT_STICKY;}
        startForeground(91,note("Подготовка полного анализа…"));
        if(wake==null||!wake.isHeld()){wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:full-analysis");wake.acquire(2L*60L*60L*1000L);}
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            boolean chain=true;
            boolean pipelineStarted=false;
            boolean runStateInvalidated=false;
            String handoffFailure=null;
            String reconstructionFailure=null;
            startedAt=System.currentTimeMillis();
            try{
                writePipelineState("RUNNING","RECONSTRUCTION",false,false,null);pipelineStarted=true;
                invalidatePreparedAutoModState();
                invalidatePerRunEvidenceState();
                runStateInvalidated=true;
                List<File> inputs=DecompilerEngine.resolveTargetInputs(app);
                if(inputs.isEmpty())throw new java.io.FileNotFoundException("Сначала выберите APK или установленный пакет.");
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));

                stage(1,4,"Inventory: APK/split, DEX, native, Unity/IL2CPP и runtime-маркеры");
                String scanJson=runInventory(inputs);
                normalizeInstalledTarget(scanJson);
                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}

                progress("Проверяю fingerprint выбранного APK/APK-set…");
                String digest=targetDigest(inputs);
                File manifest=app.file("full-reconstruction.json");
                File decompiled=app.file("modkit-decompiled.zip");
                boolean cached=false;
                if(manifest.isFile()&&decompiled.isFile()){
                    try{
                        JSONObject old=new JSONObject(Io.readUtf8(manifest));
                        String expectedSha=old.optString("outputSha256","");
                        long expectedSize=old.optLong("outputSize",-1L);
                        boolean metadataMatches=digest.equals(old.optString("targetDigest"))&&old.optBoolean("complete")&&decompiled.getName().equals(old.optString("output"));
                        if(metadataMatches&&expectedSize>=0L&&expectedSize==decompiled.length()&&!expectedSha.isEmpty()){
                            cached=expectedSha.equals(fileSha256(decompiled));
                        }
                    }catch(java.io.InterruptedIOException cancelled){throw cancelled;}catch(Exception ignored){}
                }
                if(cached)stage(2,4,"JADX: cache hit · target и export fingerprint совпали");
                else{
                    stage(2,4,"JADX: все classes*.dex и resources во всех split APK");
                    JSONObject state=new JSONObject().put("schema","modkit-full-reconstruction-1.1").put("targetDigest",digest).put("complete",false).put("startedAtMs",System.currentTimeMillis());
                    writeAtomicJson("full-reconstruction.json",state);
                    try(DecompilerEngine dec=new DecompilerEngine(this)){
                        dec.open();if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        File zip=dec.exportAllZip(app.cancelled);if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");
                        long outputSize=zip.length();String outputSha=fileSha256(zip);
                        state.put("backend",DecompilerEngine.BACKEND).put("classCount",dec.classCount()).put("resourceCount",dec.resourceCount()).put("errors",dec.errorCount()).put("warnings",dec.warnCount()).put("output",zip.getName()).put("outputSize",outputSize).put("outputSha256",outputSha);
                        JSONArray names=new JSONArray();for(File f:dec.inputFiles())names.put(f.getName());state.put("inputs",names);
                        state.put("complete",true).put("finishedAtMs",System.currentTimeMillis());
                    }catch(Exception e){
                        state.put("complete",false).put("cancelled",app.cancelled.get()).put("error",String.valueOf(e.getMessage())).put("finishedAtMs",System.currentTimeMillis());
                        if(!app.cancelled.get())progress("JADX частичен: "+e.getMessage()+" · продолжаю остальные backend'ы.");
                    }
                    writeAtomicJson("full-reconstruction.json",state);
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                stage(3,4,"Apktool "+ApktoolEngine.APKTOOL_VERSION+": resources + manifest + полный smali workspace");
                try{
                    JSONObject apktool=ApktoolEngine.analyze(this,inputs,app.cancelled);
                    writeAtomicJson("apktool-analysis.json",apktool);
                    int failed=apktool.optInt("failed");progress("Apktool: decoded="+apktool.optInt("decoded")+" · cache="+apktool.optInt("cached")+(failed>0?" · errors="+failed:"")+".");
                }catch(Throwable e){
                    JSONObject error=new JSONObject().put("schema","modkit-apktool-analysis-1.0").put("engineId",ApktoolEngine.ENGINE_ID).put("bundled",true).put("status","FAILED").put("error",String.valueOf(e.getMessage()));
                    writeAtomicJson("apktool-analysis.json",error);
                    if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                    progress("Apktool частичен: "+e.getMessage()+" · остальные backend'ы продолжаются.");
                }

                if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}
                stage(4,4,"Lua/JS/Hermes deep + ARM64 deep + Flutter AOT + Cocos correlation");
                invalidateEmbeddedRunOutputs();
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
                chain=false;
                if(!pipelineStarted)reconstructionFailure="PIPELINE_MANIFEST_WRITE_FAILED: "+String.valueOf(e.getMessage());
                else if(!runStateInvalidated)reconstructionFailure="RUN_EPOCH_INVALIDATION_FAILED: "+String.valueOf(e.getMessage());
                else if(!app.cancelled.get())reconstructionFailure="RECONSTRUCTION_FAILED: "+String.valueOf(e.getMessage());
                progress(app.cancelled.get()?"Полный анализ отменён.":"Полный анализ остановлен: "+e.getMessage()+" · Evidence Graph не будет запущен на неполной реконструкции.");
            }finally{
                boolean handedOff=false;
                if(chain&&!app.cancelled.get()){
                    progress("Реконструкция готова · передаю в изолированный Evidence Graph pipeline…");
                    try{
                        startForegroundService(new Intent(this,AutomaticEvidenceService.class));
                        handedOff=true;
                    }catch(Exception handoffError){
                        handoffFailure=String.valueOf(handoffError.getMessage());
                        progress("Не удалось запустить Evidence Graph: "+handoffFailure);
                    }
                }
                if(!handedOff){
                    if(pipelineStarted){
                        if(app.cancelled.get())bestEffortPipelineState("CANCELLED","RECONSTRUCTION",false,true,"USER_CANCELLED");
                        else if(reconstructionFailure!=null)bestEffortPipelineState("FAILED","RECONSTRUCTION",false,false,reconstructionFailure);
                        else bestEffortPipelineState("FAILED","HANDOFF",false,false,handoffFailure==null?"EVIDENCE_HANDOFF_NOT_STARTED":handoffFailure);
                    }else{
                        try{Files.deleteIfExists(app.file("automatic-evidence.json").toPath());Files.deleteIfExists(app.file("automatic-evidence.json.part").toPath());}catch(Exception ignored){}
                    }
                    getSharedPreferences("state",0).edit().putBoolean("running",false).apply();
                    app.busy.set(false);app.revision++;
                }
                if(wake!=null&&wake.isHeld())wake.release();
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
        writeAtomicJson("installed-target.json",normalized);
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

    private String fileSha256(File file)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[1024*1024];
        try(FileInputStream in=new FileInputStream(file)){
            int n;while((n=in.read(buf))!=-1){if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled");d.update(buf,0,n);}
        }
        StringBuilder out=new StringBuilder();for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }
}
