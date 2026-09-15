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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Final automatic evidence pass for the release UI. */
public class AutomaticEvidenceService extends Service {
    private static final int NOTE_ID=95;
    private App app;
    private PowerManager.WakeLock wake;
    private volatile long lastNotification;
    private long startedAt;

    public final class Progress {
        public boolean isCancelled(){return app.cancelled.get();}
        public void progress(String text){
            app.progress(text);
            long now=System.currentTimeMillis();
            if(now-lastNotification>1200){lastNotification=now;notifyProgress(text);}
        }
    }

    @Override public void onCreate(){
        super.onCreate();app=(App)getApplication();
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(
                new NotificationChannel("automatic-evidence","Автоматический Evidence Graph",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public IBinder onBind(Intent intent){return null;}

    private Notification note(String text){
        Intent stop=new Intent(this,AutomaticEvidenceService.class).setAction("cancel");
        PendingIntent cancel=PendingIntent.getService(this,NOTE_ID+1,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open=PendingIntent.getActivity(this,NOTE_ID,new Intent(this,AutoAnalysisActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"automatic-evidence").setSmallIcon(R.drawable.ic_modkit).setContentTitle("ModKit · Evidence Graph").setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
    }
    private void notifyProgress(String text){((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTE_ID,note(text));}
    private void progress(String text){app.progress(text);notifyProgress(text);}

    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"cancel".equals(intent.getAction())){app.cancelled.set(true);progress("Отмена запрошена — завершаю текущий безопасный шаг…");return START_NOT_STICKY;}
        startForeground(NOTE_ID,note("Подготовка Evidence Graph…"));
        wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:auto-evidence");wake.acquire(60L*60L*1000L);
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(()->{
            JSONObject manifest=new JSONObject();
            try{
                startedAt=System.currentTimeMillis();manifest.put("schema","modkit-automatic-evidence-1.1").put("startedAtMs",startedAt).put("legacyWorkerUsed",false).put("executesTargetCode",false).put("status","RUNNING").put("phase","EVIDENCE").put("complete",false).put("cancelled",false);writeJson("automatic-evidence.json",manifest);
                runPipeline(manifest);String status=manifest.optString("status","SUCCESS");if("RUNNING".equals(status))status="SUCCESS";manifest.put("status",status).put("phase","FINISHED").put("complete",!app.cancelled.get()).put("cancelled",app.cancelled.get()).put("finishedAtMs",System.currentTimeMillis());writeJson("automatic-evidence.json",manifest);
            }catch(Exception e){
                try{manifest.put("status",app.cancelled.get()?"CANCELLED":"FAILED").put("phase","FINISHED").put("complete",false).put("cancelled",app.cancelled.get()).put("error",String.valueOf(e.getMessage())).put("finishedAtMs",System.currentTimeMillis());writeJson("automatic-evidence.json",manifest);}catch(Exception ignored){}
                progress(app.cancelled.get()?"Автоанализ отменён.":"Evidence Graph: "+e.getMessage());
            }finally{
                if(wake!=null&&wake.isHeld())wake.release();getSharedPreferences("state",0).edit().putBoolean("running",false).apply();app.busy.set(false);app.revision++;stopForeground(true);stopSelf();
            }
        },"modkit-automatic-evidence").start();return START_NOT_STICKY;
    }

    private void runPipeline(JSONObject manifest)throws Exception{
        if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile())throw new IOException("Target отсутствует");
        check();if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject cache=Python.getInstance().getModule("modkit.mobile.simple_cache");

        stage(1,6,"target digest + APK/split cache plan");
        JSONObject plan=new JSONObject(cache.callAttr("plan_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),new Progress()).toString());
        boolean unchanged=plan.optBoolean("unchanged",false);boolean haveAnalysis=app.file("analysis.json").isFile()||app.file("re-analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile();manifest.put("cachePlan",plan).put("cacheHit",unchanged&&haveAnalysis);

        File reTarget=targetForReAnalysis();stage(2,6,unchanged&&haveAnalysis?"cache hit: IL2CPP/DEX/native correlation":"IL2CPP + DEX/native correlation");JSONObject engines=new JSONObject();manifest.put("engines",engines);
        if(!unchanged||!haveAnalysis){
            try{engines.put("il2cpp",runIl2cpp(reTarget));}catch(Exception e){if(app.cancelled.get())check();engines.put("il2cpp",new JSONObject().put("status","PARTIAL").put("error",String.valueOf(e.getMessage())));progress("IL2CPP частичен: "+e.getMessage()+" · продолжаю DEX/native correlation.");}
            check();try{engines.put("re",runReAnalysis(reTarget));}catch(Exception e){if(app.cancelled.get())check();engines.put("re",new JSONObject().put("status","PARTIAL").put("error",String.valueOf(e.getMessage())));progress("DEX/native correlation частична: "+e.getMessage()+" · продолжаю остальные evidence backend'ы.");}
        }else{engines.put("il2cpp",new JSONObject().put("status","CACHE_HIT"));engines.put("re",new JSONObject().put("status","CACHE_HIT"));}

        check();stage(3,6,"embedded evidence + gameplay ownership correlation");JSONObject artifactSummary=readJson("artifact-families.json");JSONObject embeddedSummary=readJson("embedded-analysis.json");manifest.put("artifactFamilies",artifactSummary==null?JSONObject.NULL:new JSONObject().put("total",artifactSummary.optInt("total")).put("familyCounts",artifactSummary.optJSONObject("familyCounts")));manifest.put("embeddedAnalysis",embeddedSummary==null?JSONObject.NULL:embeddedSummary);

        check();stage(4,6,unchanged&&app.file("security-surfaces.json").isFile()?"cache hit: passive Network/API + TLS + Crypto":"passive Network/API + TLS + Crypto scan");JSONObject security;
        if(unchanged&&app.file("security-surfaces.json").isFile())security=new JSONObject(Io.readUtf8(app.file("security-surfaces.json")));else{PyObject sec=Python.getInstance().getModule("modkit.mobile.security_scan");security=new JSONObject(sec.callAttr("scan_workspace",getFilesDir().getPath(),app.file("security-surfaces.json").getPath(),new Progress()).toString());}
        manifest.put("security",new JSONObject().put("total",security.optInt("total")).put("uniqueEndpoints",security.optInt("uniqueEndpoints")));

        check();stage(5,6,"Evidence Graph: ownership + confirmation ladder + exact locators + ranking");PyObject simple=Python.getInstance().getModule("modkit.mobile.simple_mode_cancellable");JSONObject catalog=new JSONObject(simple.callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath(),new Progress()).toString());manifest.put("catalog",new JSONObject().put("total",catalog.optInt("total")).put("important",catalog.optInt("important")).put("buildable",catalog.optInt("buildable")).put("actionable",catalog.optInt("actionable")).put("serverAudit",catalog.optInt("serverAudit")));

        check();stage(6,6,"no-RVA native recovery + AutoMod + connected report + cache");
        File meta=app.file("metadata.bin"),lib=app.file("library.so"),methods=app.file("analysis.methods.jsonl");
        if(meta.isFile()&&lib.isFile()&&methods.isFile()){
            try{
                PyObject recovery=Python.getInstance().getModule("modkit.mobile.il2cpp_no_rva_native_release");
                JSONObject recovered=new JSONObject(recovery.callAttr("recover_workspace",getFilesDir().getPath(),app.file("il2cpp-no-rva-native.json").getPath(),new Progress()).toString());
                JSONObject rc=recovered.optJSONObject("counts");String recoveryError=recovered.optString("error","");
                manifest.put("noRvaNative",new JSONObject().put("status",recoveryError.isEmpty()?"SUCCESS":"PARTIAL").put("schema",recovered.optString("schema")).put("resolvedModules",recovered.optInt("resolvedModuleCount")).put("recoveredExact",rc==null?0:rc.optInt("recoveredExact")).put("sharedPointers",rc==null?0:rc.optInt("sharedExecutablePointer")).put("identityMismatch",rc==null?0:rc.optInt("identityMismatch")).put("error",recoveryError));
            }catch(Exception e){if(app.cancelled.get())check();manifest.put("noRvaNative",new JSONObject().put("status","PARTIAL").put("error",String.valueOf(e.getMessage())));progress("No-RVA native recovery частичен: "+e.getMessage()+" · продолжаю AutoMod/report.");}
        }else manifest.put("noRvaNative",new JSONObject().put("status","NOT_APPLICABLE").put("reason","complete IL2CPP pair/catalog not available"));

        check();
        try{
            PyObject autoMod=Python.getInstance().getModule("modkit.mobile.automod_cancellable");JSONObject autoPlan=new JSONObject(autoMod.callAttr("build_workspace_plan",getFilesDir().getPath(),app.file("automod-plan.json").getPath(),new Progress()).toString());
            boolean autoPartial=hasError(autoPlan.optJSONObject("il2cppCrosscheck"))||hasError(autoPlan.optJSONObject("il2cppMetadataIdentity"))||hasError(autoPlan.optJSONObject("il2cppNativeRecovery"));
            manifest.put("autoMod",new JSONObject().put("status",autoPartial?"PARTIAL":"SUCCESS").put("readyToBuild",autoPlan.optInt("readyToBuildCount")).put("readyForPreflight",autoPlan.optInt("readyForPreflightCount")).put("runtimeNeeded",autoPlan.optInt("runtimeNeededCount")).put("review",autoPlan.optInt("reviewCount")).put("auditOnly",autoPlan.optInt("auditOnlyCount")).put("excluded",autoPlan.optInt("excludedCount")).put("metadataIdentityNoRva",autoPlan.optInt("metadataIdentityObservedCount")).put("metadataQualifiedNoRva",autoPlan.optInt("metadataQualifiedNoRvaCount")));
        }catch(Exception e){if(app.cancelled.get())check();manifest.put("autoMod",new JSONObject().put("status","PARTIAL").put("error",String.valueOf(e.getMessage())));progress("AutoMod-план частичен: "+e.getMessage()+" · основной Evidence Graph сохранён.");}

        check();
        try{
            PyObject reportModule=Python.getInstance().getModule("modkit.mobile.connected_report_streaming");JSONObject connected=new JSONObject(reportModule.callAttr("build_connected_report",getFilesDir().getPath(),app.file("connected-report.json").getPath(),app.file("connected-report.md").getPath(),new Progress()).toString());
            manifest.put("connectedReport",new JSONObject().put("status","SUCCESS").put("schema",connected.optString("schema")).put("findingCount",connected.optInt("findingCount")).put("exactLinked",connected.optInt("exactLinked")).put("runtimeObserved",connected.optInt("runtimeObservedFindings")).put("il2cppStructural",connected.optInt("il2cppStructuralFindings")).put("metadataIdentityNoRva",connected.optInt("metadataIdentityConfirmedFindings")).put("metadataQualifiedNoRva",connected.optInt("metadataQualifiedIdentityFindings")).put("metadataTokenNoRva",connected.optInt("metadataTokenIdentityFindings")).put("metadataTokenConflicts",connected.optInt("metadataTokenConflictFindings")).put("nativeRvaRecovered",connected.optInt("nativeRvaRecoveredFindings")));
        }catch(Exception e){if(app.cancelled.get())check();manifest.put("connectedReport",new JSONObject().put("status","PARTIAL").put("error",String.valueOf(e.getMessage())));progress("Connected report частичен: "+e.getMessage()+" · AutoMod/Evidence Graph сохранены.");}

        JSONObject il2cppEngine=engines.optJSONObject("il2cpp"),reEngine=engines.optJSONObject("re");
        String il2cppStatus=il2cppEngine==null?"":il2cppEngine.optString("status"),reStatus=reEngine==null?"":reEngine.optString("status");
        boolean il2cppCacheable="SUCCESS".equals(il2cppStatus)||"CACHE_HIT".equals(il2cppStatus)||"NOT_APPLICABLE".equals(il2cppStatus);
        boolean reCacheable="SUCCESS".equals(reStatus)||"CACHE_HIT".equals(reStatus);
        boolean cacheEligible=il2cppCacheable&&reCacheable;manifest.put("cacheEligible",cacheEligible);
        if(cacheEligible){
            cache.callAttr("record_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),plan.toString(),new Progress());manifest.put("cacheRecorded",true);
        }else{
            Files.deleteIfExists(app.file("simple-cache.json").toPath());manifest.put("cacheRecorded",false).put("cacheBlockedReason","core analyzer partial or incomplete");
        }

        JSONArray degradedReasons=new JSONArray();JSONObject reconstruction=readJson("full-reconstruction.json"),apktoolSummary=readJson("apktool-analysis.json");
        if(reconstruction==null)degradedReasons.put("JADX_RECONSTRUCTION_MISSING");else if(!reconstruction.optBoolean("complete",false))degradedReasons.put("JADX_RECONSTRUCTION_PARTIAL");else if(reconstruction.optInt("errors")>0)degradedReasons.put("JADX_DECODE_ERRORS");
        if(apktoolSummary==null)degradedReasons.put("APKTOOL_SUMMARY_MISSING");else if("FAILED".equals(apktoolSummary.optString("status"))||hasError(apktoolSummary)||apktoolSummary.optInt("failed")>0)degradedReasons.put("APKTOOL_PARTIAL");
        if(embeddedSummary==null)degradedReasons.put("EMBEDDED_SUMMARY_MISSING");else if(embeddedSummary.optInt("failed")>0)degradedReasons.put("EMBEDDED_PARTIAL");
        if("PARTIAL".equals(il2cppStatus))degradedReasons.put("IL2CPP_PARTIAL");if("PARTIAL".equals(reStatus))degradedReasons.put("RE_ANALYSIS_PARTIAL");
        JSONObject noRvaStatus=manifest.optJSONObject("noRvaNative"),autoStatus=manifest.optJSONObject("autoMod"),reportStatus=manifest.optJSONObject("connectedReport");
        if(noRvaStatus!=null&&"PARTIAL".equals(noRvaStatus.optString("status")))degradedReasons.put("NO_RVA_NATIVE_PARTIAL");
        if(autoStatus!=null&&"PARTIAL".equals(autoStatus.optString("status")))degradedReasons.put("AUTOMOD_PARTIAL");
        if(reportStatus!=null&&"PARTIAL".equals(reportStatus.optString("status")))degradedReasons.put("CONNECTED_REPORT_PARTIAL");
        boolean degraded=degradedReasons.length()>0;manifest.put("degraded",degraded).put("degradedReasons",degradedReasons).put("status",degraded?"PARTIAL":"SUCCESS");

        check();app.result=readJson("analysis.summary.json");JSONObject autoPlan=readJson("automod-plan.json");JSONObject connected=readJson("connected-report.json");JSONObject nativeRecovery=readJson("il2cpp-no-rva-native.json");JSONObject recoveryCounts=nativeRecovery==null?null:nativeRecovery.optJSONObject("counts");
        String autoText=autoPlan==null?"":" · AutoMod build "+autoPlan.optInt("readyToBuildCount")+" / preflight "+autoPlan.optInt("readyForPreflightCount");String reportText=connected==null?"":" · report links "+connected.optInt("exactLinked")+" / recovered RVA "+connected.optInt("nativeRvaRecoveredFindings")+" / token-no-RVA "+connected.optInt("metadataTokenIdentityFindings")+" / conflicts "+connected.optInt("metadataTokenConflictFindings");String recoveryText=recoveryCounts==null?"":" · native recovery "+recoveryCounts.optInt("recoveredExact");
        progress((degraded?"Готово частично":"Готово")+". Найдено "+catalog.optInt("total")+", важных "+catalog.optInt("important")+", точных locator "+catalog.optInt("actionable")+", PATCH_READY "+catalog.optInt("buildable")+", server/trust audit "+catalog.optInt("serverAudit")+autoText+recoveryText+reportText+(unchanged?" · cache hit":" · fresh target")+".");
    }

    private JSONObject runIl2cpp(File reTarget)throws Exception{
        File meta=app.file("metadata.bin"),lib=app.file("library.so");if(!meta.isFile()||!lib.isFile())return new JSONObject().put("status","NOT_APPLICABLE").put("reason","complete IL2CPP pair not found");check();deleteTree(app.file("rodroid"));progress("Rodroid IL2CPP: metadata + libil2cpp → methods, fields, RVA и offsets…");File dump=RodroidRunner.run(this,lib,meta,app.file("rodroid"),app.cancelled,new Progress()::progress);check();PyObject result=engine().callAttr("analyze_rodroid",dump.getPath(),meta.getPath(),lib.getPath(),app.file("analysis.json").getPath(),new Progress(),true,app.file("analysis.ui.jsonl").getPath(),app.file("analysis.methods.jsonl").getPath());JSONObject analysis=new JSONObject(result.toString());app.result=analysis;
        if(app.file("analysis.methods.jsonl").isFile()){PyObject gameplay=engine().callAttr("build_gameplay_discovery",meta.getPath(),lib.getPath(),app.file("analysis.methods.jsonl").getPath(),app.file("analysis.evidence-graph.jsonl").getPath(),app.file("analysis.gameplay-coverage.json").getPath(),reTarget.getPath(),app.file("analysis.json").getPath(),new Progress());analysis.put("gameplayDiscovery",new JSONObject(gameplay.toString()));}
        JSONObject installed=readJson("installed-scan.json");if(installed!=null)analysis.put("installedScan",installed);Files.write(app.file("analysis.summary.json").toPath(),analysis.toString().getBytes(StandardCharsets.UTF_8));JSONObject methodCatalog=analysis.optJSONObject("metadata_method_catalog");return new JSONObject().put("status","SUCCESS").put("methodRows",methodCatalog==null?0:methodCatalog.optInt("rows")).put("addressConfirmed",methodCatalog==null?0:methodCatalog.optInt("addressConfirmed")).put("candidateCount",analysis.optInt("candidate_count"));
    }

    private JSONObject runReAnalysis(File reTarget)throws Exception{check();File meta=app.file("metadata.bin"),lib=app.file("library.so"),rod=app.file("rodroid"),analysis=app.file("analysis.json"),output=app.file("re-analysis.json");String inputMode=reTarget.getName().equals("installed-apk-set.zip")?"automatic-installed-apk-set":"automatic-single-apk";PyObject result=engine().callAttr("re_analyze_apk",reTarget.getPath(),output.getPath(),meta.isFile()?meta.getPath():null,lib.isFile()?lib.getPath():null,rod.isDirectory()?rod.getPath():null,null,analysis.isFile()?analysis.getPath():null,new Progress(),inputMode,true);JSONObject obj=new JSONObject(result.toString());return new JSONObject().put("status","SUCCESS").put("findingCount",obj.optInt("findingCount")).put("il2cppXrefs",obj.optInt("il2cppXrefs")).put("contextMethods",obj.optInt("contextMethods"));}

    private File targetForReAnalysis()throws Exception{
        File manifest=app.file("installed-target.json");if(!manifest.isFile()){File single=app.file("game.apk");if(!single.isFile())throw new IOException("APK target отсутствует");return single;}JSONObject target=new JSONObject(Io.readUtf8(manifest));JSONArray splits=target.optJSONArray("splits");if(splits==null||splits.length()<=1){File single=app.file("game.apk");if(!single.isFile())throw new IOException("base APK отсутствует");return single;}List<File> files=new ArrayList<>();List<String> names=new ArrayList<>();for(int i=0;i<splits.length();i++){JSONObject row=splits.optJSONObject(i);if(row==null)continue;File f=new File(row.optString("path",""));if(!f.isFile())throw new IOException("Split отсутствует: "+row.optString("name",f.getName()));files.add(f);names.add(row.optString("name",f.getName()));}if(files.isEmpty())throw new IOException("APK-set manifest не содержит читаемых splits");File zip=app.file("installed-apk-set.zip");writeApkSet(zip,files,names);return zip;
    }
    private void writeApkSet(File output,List<File> files,List<String> names)throws Exception{File temp=new File(output.getParentFile(),output.getName()+".tmp");temp.delete();try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(temp)))){z.setLevel(0);byte[] buf=new byte[1024*1024];for(int i=0;i<files.size();i++){check();ZipEntry entry=new ZipEntry(names.get(i));z.putNextEntry(entry);try(InputStream in=new FileInputStream(files.get(i))){int n;while((n=in.read(buf))!=-1){check();z.write(buf,0,n);}}z.closeEntry();}}Files.move(temp.toPath(),output.toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);}
    private PyObject engine(){if(!Python.isStarted())Python.start(new AndroidPlatform(this));return Python.getInstance().getModule("modkit.mobile.engine");}
    private void check()throws IOException{if(app.cancelled.get())throw new IOException("Автоанализ отменён пользователем");}
    private static boolean hasError(JSONObject value){return value!=null&&!value.optString("error","").isEmpty();}
    private void stage(int stage,int total,String name)throws Exception{check();JSONObject p=new JSONObject().put("schema","modkit-simple-progress-1.1").put("phase","EVIDENCE").put("stage",stage).put("totalStages",total).put("name",name).put("remainingStages",Math.max(0,total-stage)).put("elapsedMs",Math.max(0,System.currentTimeMillis()-startedAt));JSONObject old=readJson("simple-catalog.json");if(old!=null)p.put("candidates",old.optInt("total")).put("confirmed",old.optInt("actionable")).put("patchReady",old.optInt("buildable"));writeJson("simple-progress.json",p);progress("Автоанализ ["+stage+"/"+total+"]: "+name);}
    private JSONObject readJson(String name){try{File f=app.file(name);return f.isFile()?new JSONObject(Io.readUtf8(f)):null;}catch(Exception ignored){return null;}}
    private void writeJson(String name,JSONObject value)throws Exception{File destination=app.file(name),part=app.file(name+".part");Files.deleteIfExists(part.toPath());try{Files.write(part.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(Exception error){Files.deleteIfExists(part.toPath());throw error;}}
    private void deleteTree(File file)throws IOException{if(file==null||!file.exists())return;check();if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);}check();if(!file.delete()&&file.exists())throw new IOException("Не удалось очистить "+file.getName());}
}
