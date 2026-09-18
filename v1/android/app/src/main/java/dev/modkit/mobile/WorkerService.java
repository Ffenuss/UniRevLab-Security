package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.*;
import android.provider.DocumentsContract;
import com.chaquo.python.*;
import com.chaquo.python.android.AndroidPlatform;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

public class WorkerService extends Service {
    private App app;
    private PowerManager.WakeLock wake;
    private volatile long lastNotification;
    public class Progress {
        public boolean isCancelled() { return app.cancelled.get(); }
        public void progress(String text) {
            app.progress(text);
            if (System.currentTimeMillis()-lastNotification > 1500) {
                lastNotification = System.currentTimeMillis();
                ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(1, notification(text));
            }
        }
    }
    private Notification notification(String text) {
        Intent stop = new Intent(this, WorkerService.class).setAction("cancel");
        PendingIntent cancel = PendingIntent.getService(this,2,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open = PendingIntent.getActivity(this,1,new Intent(this,MainActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = new Notification.Builder(this,"work");
        return b.setSmallIcon(dev.modkit.mobile.R.drawable.ic_modkit).setContentTitle("ModKit — обработка файлов")
            .setContentText(text).setContentIntent(open).setOngoing(true).addAction(0,"Отмена",cancel).build();
    }
    @Override public void onCreate() {
        super.onCreate(); app = (App)getApplication();
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE))
            .createNotificationChannel(new NotificationChannel("work","Обработка файлов",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent,int flags,int id) {
        if (intent == null) { stopSelf(); return START_NOT_STICKY; }
        if ("cancel".equals(intent.getAction())) {
            app.cancelled.set(true); app.progress("Отмена…");
            if (!app.busy.get()) stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(1,notification(app.status));
        wake = ((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:work");
        wake.acquire(60*60*1000L);
        getSharedPreferences("state",0).edit().putBoolean("running",true).apply();
        new Thread(() -> {
            try {
                String op=intent.getStringExtra("op");
                if ("scan_installed".equals(op)) scanInstalled(intent.getStringExtra("package"),intent.getStringExtra("label"));
                else if ("import".equals(op)) importFile(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("name"),intent.getStringExtra("display"));
                else if ("analyze".equals(op)) analyze();
                else if ("deep_method".equals(op)) deepMethod(intent.getIntExtra("method_id",-1));
                else if ("report".equals(op)) reportFile(Uri.parse(intent.getStringExtra("uri")));
                else if ("export".equals(op)) exportFile(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("selections"));
                else if ("build_apk".equals(op)) buildApk(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("selections"));
                else if ("dump".equals(op)) dumpFile(Uri.parse(intent.getStringExtra("uri")));
                else if ("re_analyze".equals(op)) reAnalyze();
                else if ("native_import".equals(op)) nativeImport(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("display"));
                else if ("native_search".equals(op)) nativeSearch(intent.getStringExtra("query"));
                else if ("native_disasm".equals(op)) nativeDisasm(intent.getStringExtra("rva"));
                else if ("native_xrefs".equals(op)) nativeXrefs(intent.getStringExtra("rva"));
                else if ("native_patch".equals(op)) nativePatch(intent.getStringExtra("rva"),intent.getStringExtra("mode"),intent.getStringExtra("payload"));
                else if ("native_undo".equals(op)) nativeUndo();
                else if ("native_save_uri".equals(op)) nativeSaveUri(Uri.parse(intent.getStringExtra("uri")));
                else if ("patchpack_import".equals(op)) patchPackImport(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("display"));
                else if ("patchpack_inspect".equals(op)) patchPackInspect();
                else if ("patchpack_build".equals(op)) patchPackBuild(Uri.parse(intent.getStringExtra("uri")));
                else if ("workspace_inspect".equals(op)) workspaceInspect(intent.getStringExtra("source"));
                else if ("workspace_build".equals(op)) workspaceBuild(intent,Uri.parse(intent.getStringExtra("uri")));
                else if ("simple_prepare".equals(op)) simplePrepare();
                else if ("simple_build".equals(op)) simpleBuild(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("controls"));
                else if ("menu_seed".equals(op)) menuSeed();
                else if ("menu_seed_deep".equals(op)) menuSeedDeep();
                else if ("menu_probe_prepare".equals(op)) menuProbePrepare();
                else if ("menu_auto_prepare".equals(op)) menuAutoPrepare();
                else if ("menu_auto_prepare_deep".equals(op)) menuAutoPrepareDeep();
                else if ("menu_autopilot_prepare".equals(op)) menuAutopilotPrepare();
                else if ("menu_smart_prepare".equals(op)) menuSmartPrepare();
                else if ("menu_project".equals(op)) menuProject();
                else if ("menu_validate".equals(op)) menuValidate();
                else if ("menu_auto_confirm".equals(op)) menuAutoConfirm();
                else if ("menu_preflight".equals(op)) menuPreflight();
                else if ("menu_export".equals(op)) menuExport(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_runtime_import".equals(op)) menuRuntimeImport(Uri.parse(intent.getStringExtra("uri")),intent.getStringExtra("display"));
                else if ("menu_payload_export".equals(op)) menuPayloadExport(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_build_apk".equals(op)) menuBuildApk(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_auto_build_apk".equals(op)) menuAutoBuildApk(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_auto_build_apk_deep".equals(op)) menuAutoBuildApkDeep(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_autopilot_build_apk".equals(op)) menuAutopilotBuildApk(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_smart_build_apk".equals(op)) menuSmartBuildApk(Uri.parse(intent.getStringExtra("uri")));
                else if ("menu_probe_build_apk".equals(op)) menuProbeBuildApk(Uri.parse(intent.getStringExtra("uri")));
            } catch (Exception e) {
                app.progress(app.cancelled.get() ? "Операция отменена. Исходные файлы сохранены." : "Ошибка: " + e.getMessage());
            } finally {
                if (wake != null && wake.isHeld()) wake.release();
                getSharedPreferences("state",0).edit().putBoolean("running",false).apply();
                app.busy.set(false); app.revision++;
                stopForeground(true); stopSelf();
            }
        },"modkit-work").start();
        return START_NOT_STICKY;
    }
    private void check() throws IOException { if (app.cancelled.get()) throw new IOException("Операция отменена"); }
    private void deleteTree(File f) throws IOException {
        if(f==null||!f.exists())return;
        if(f.isDirectory()){File[] children=f.listFiles();if(children!=null)for(File c:children)deleteTree(c);}
        if(!f.delete()&&f.exists())throw new IOException("Не удалось очистить старый RE-артефакт: "+f.getName());
    }
    private void clearInstalledAnalysisState() throws Exception {
        app.result=null;
        for(String name:new String[]{"metadata.bin","library.so","game.apk","game-native-split.apk","analysis.json","analysis.summary.json","analysis.ui.jsonl","analysis.methods.jsonl","analysis.methods.jsonl.idx","analysis.methods.jsonl.pages.idx","analysis.methods.jsonl.rva.idx","analysis.methods.meta.json","analysis.candidates.jsonl","analysis.discoveries.jsonl","analysis.evidence-graph.jsonl","analysis.evidence-graph.jsonl.idx","analysis.evidence-graph.meta.json","analysis.fields.jsonl","analysis.resolver-index.json","analysis.autopilot-index.jsonl","analysis.gameplay-coverage.json","re-analysis.json","re-analysis.ui.json","re-analysis.menu.json","menu-spec.json","menu-result.json","menu-preflight.json","menu-validation.json","security-surfaces.json","simple-catalog.json","simple-cache.json","simple-progress.json"})
            Files.deleteIfExists(app.file(name).toPath());
        deleteTree(app.file("analysis-deep"));deleteTree(app.file("rodroid"));deleteTree(app.file("menu-project"));deleteTree(app.file("installed-apks"));
        Files.deleteIfExists(app.file("installed-apk-set.zip").toPath());Files.deleteIfExists(app.file("installed-scan.json").toPath());Files.deleteIfExists(app.file("installed-target.json").toPath());
        getSharedPreferences("state",0).edit().remove("selections").remove("metadata.bin").remove("library.so").remove("game.apk").remove("active.project").apply();
    }
    private void copyInstalledFile(File source,File dest,String label) throws Exception {
        try(InputStream in=new FileInputStream(source);OutputStream out=new FileOutputStream(dest)){
            byte[] buf=new byte[1024*1024];int n;long total=0,size=Math.max(1,source.length());
            while((n=in.read(buf))!=-1){check();out.write(buf,0,n);total+=n;if(total%(8L*1024*1024)<buf.length)new Progress().progress("Installed scan: "+label+" · "+(total*100/size)+"%");}
        }
    }
    private void buildInstalledApkSet(List<File> apks,File output) throws Exception {
        File temp=new File(output.getParentFile(),output.getName()+".tmp");
        try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(temp)))){
            z.setLevel(0);byte[] buf=new byte[1024*1024];
            for(File apk:apks){check();ZipEntry e=new ZipEntry(apk.getName());z.putNextEntry(e);try(InputStream in=new FileInputStream(apk)){int n;while((n=in.read(buf))!=-1){check();z.write(buf,0,n);}}z.closeEntry();}
        }
        Files.move(temp.toPath(),output.toPath(),StandardCopyOption.REPLACE_EXISTING);
    }
    private String safeApkName(String sourceName,int index,boolean base){
        String name=base?"base.apk":(sourceName==null?"":new File(sourceName).getName());
        name=name.replaceAll("[^A-Za-z0-9._-]","_");if(name.isEmpty()||!name.toLowerCase(Locale.ROOT).endsWith(".apk"))name=base?"base.apk":"split.apk";
        // Prefix every copied APK with its PackageManager order. This prevents
        // two different split names from collapsing to the same sanitized file.
        return String.format(Locale.ROOT,"%03d-%s",index,name);
    }
    private JSONObject installedTarget() {
        File f=app.file("installed-target.json");if(!f.isFile())return null;
        try{return new JSONObject(new String(Files.readAllBytes(f.toPath()),java.nio.charset.StandardCharsets.UTF_8));}catch(Exception ignored){return null;}
    }
    private boolean targetIsApkSet(){JSONObject t=installedTarget();return t!=null&&"apk-set".equals(t.optString("buildMode"))&&t.optJSONArray("splits")!=null&&t.optJSONArray("splits").length()>1;}
    private File targetPatchApk() throws IOException {
        JSONObject t=installedTarget();if(t!=null){JSONObject owner=t.optJSONObject("patchOwner");if(owner!=null){File f=new File(owner.optString("path",""));if(f.isFile())return f;}}
        File fallback=app.file("game.apk");if(!fallback.isFile())throw new IOException("APK для изменения не найден");return fallback;
    }
    private void verifyInstalledTarget() throws Exception {
        JSONObject t=installedTarget();if(t==null)return;
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));
        PyObject mod=Python.getInstance().getModule("modkit.mobile.package_target");
        JSONObject verify=new JSONObject(mod.callAttr("verify_target_manifest",t.toString()).toString());
        if(!verify.optBoolean("ok"))throw new IOException("APK-set изменился после анализа или неполон. Повторите Installed Scanner перед сборкой.");
        JSONObject plan=new JSONObject(mod.callAttr("build_output_plan",t.toString()).toString());
        if(!plan.optBoolean("ready"))throw new IOException("Target не готов к сборке: "+plan.optJSONArray("blockers"));
    }
    private File activeProjectDir(){String id=getSharedPreferences("state",0).getString("active.project","");return id.isEmpty()?null:new File(app.file("projects"),id);}
    private void snapshotProjectAnalysis(){
        File project=activeProjectDir();if(project==null||!project.isDirectory())return;File out=new File(project,"analysis");if(!out.exists())out.mkdirs();
        for(String name:new String[]{"installed-target.json","installed-scan.json","analysis.json","analysis.summary.json","analysis.gameplay-coverage.json","re-analysis.json","re-analysis.ui.json","re-analysis.menu.json","menu-spec.json","menu-preflight.json"}){
            File source=app.file(name);if(!source.isFile())continue;try{Files.copy(source.toPath(),new File(out,name).toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(Exception ignored){}
        }
        try{Files.write(new File(project,"session.json").toPath(),new JSONObject().put("schema","modkit-project-session-1.0").put("targetId",project.getName()).put("updatedAtMs",System.currentTimeMillis()).put("modkitVersion",BuildConfig.VERSION_NAME).toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));}catch(Exception ignored){}
    }
    private void persistProjectTarget(JSONObject target) throws Exception {
        String id=target.optString("targetId","").replaceAll("[^A-Za-z0-9._-]","");if(id.isEmpty())return;
        File project=new File(app.file("projects"),id);if(!project.exists()&&!project.mkdirs())throw new IOException("Не удалось создать каталог проекта");
        for(String dir:new String[]{"analysis","reports","build"}){File d=new File(project,dir);if(!d.exists())d.mkdirs();}
        Files.write(new File(project,"target.json").toPath(),target.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        getSharedPreferences("state",0).edit().putString("active.project",id).apply();
    }
    private void copyFileToUri(File source,Uri uri,String label) throws Exception {
        try(InputStream in=new FileInputStream(source);OutputStream out=getContentResolver().openOutputStream(uri,"wt")){
            if(out==null)throw new IOException("Не удалось открыть файл для записи");byte[] bytes=new byte[1024*1024];int n;long total=0,size=Math.max(1,source.length());
            while((n=in.read(bytes))!=-1){check();out.write(bytes,0,n);total+=n;if(total%(8L*1024*1024)<bytes.length)new Progress().progress(label+": "+(total*100/size)+"%");}out.flush();
        }
    }
    private void exportSignedTarget(Uri uri,File patchedUnsigned,String singleDone,String setDone) throws Exception {
        boolean saved=false;File singleSigned=app.file("target-signed.apk"),bundle=app.file("target-signed.apks"),signedDir=app.file("target-signed-set");
        SigningKeyManager.Identity identity=SigningKeyManager.getOrCreate();
        try{
            JSONObject target=installedTarget();
            if(target!=null&&targetIsApkSet()){
                if(!"COMPLETE".equals(target.optString("scanCompleteness")))throw new IOException("APK-set неполный: сборка заблокирована, повторите Installed Scanner и убедитесь, что все splits читаются.");
                verifyInstalledTarget();deleteTree(signedDir);if(!signedDir.mkdirs()&&!signedDir.isDirectory())throw new IOException("Не удалось создать каталог подписанного APK-set");
                JSONObject owner=target.optJSONObject("patchOwner");if(owner==null)throw new IOException("Не определён owning split для изменяемой libil2cpp.so");int ownerIndex=owner.optInt("splitIndex",-1);
                JSONArray rows=target.optJSONArray("splits");if(rows==null||rows.length()<2)throw new IOException("Некорректный APK-set target manifest");
                ArrayList<File> signedFiles=new ArrayList<>();ArrayList<String> entryNames=new ArrayList<>();
                for(int i=0;i<rows.length();i++){check();JSONObject row=rows.optJSONObject(i);if(row==null)continue;int index=row.optInt("index",i);File input=index==ownerIndex?patchedUnsigned:new File(row.optString("path",""));if(!input.isFile())throw new IOException("Split отсутствует: "+row.optString("name"));String entry=row.optString("name",String.format(Locale.ROOT,"%03d.apk",index));File signed=new File(signedDir,entry);app.progress("APK-set: подпись "+(i+1)+"/"+rows.length()+" · "+entry);ApkSignerUtil.sign(input,signed,identity);signedFiles.add(signed);entryNames.add(entry);}
                File temp=new File(bundle.getParentFile(),bundle.getName()+".tmp");try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(temp)))){byte[] buf=new byte[1024*1024];for(int i=0;i<signedFiles.size();i++){check();ZipEntry e=new ZipEntry(entryNames.get(i));z.putNextEntry(e);try(InputStream in=new FileInputStream(signedFiles.get(i))){int n;while((n=in.read(buf))!=-1){check();z.write(buf,0,n);}}z.closeEntry();}JSONObject exportedTarget=new JSONObject(target.toString()).put("signing",new JSONObject().put("provider","AndroidKeyStore").put("certificateSha256",identity.fingerprintSha256));ZipEntry manifest=new ZipEntry("modkit-target.json");z.putNextEntry(manifest);z.write(exportedTarget.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));z.closeEntry();ZipEntry readme=new ZipEntry("INSTALL.txt");z.putNextEntry(readme);z.write(("ModKit APK-set. Install all APK files from this archive together with an install-multiple capable installer. All APKs are signed with the same device-local ModKit certificate. SHA-256: "+identity.fingerprintSha256+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));z.closeEntry();}
                Files.move(temp.toPath(),bundle.toPath(),StandardCopyOption.REPLACE_EXISTING);copyFileToUri(bundle,uri,"Сохранение APK-set");saved=true;app.progress(setDone);
            }else{
                app.progress("Подпись и проверка APK локальным ключом…");ApkSignerUtil.sign(patchedUnsigned,singleSigned,identity);copyFileToUri(singleSigned,uri,"Сохранение APK");saved=true;app.progress(singleDone);
            }
        }finally{singleSigned.delete();bundle.delete();deleteTree(signedDir);if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    }

    private void exportSignedTargetForSource(Uri uri,File patchedUnsigned,File sourceApk,Intent guardRequest,String singleDone,String setDone) throws Exception {
        TargetResolver.Member guardedSource=verifyWorkspaceHandoff(guardRequest,sourceApk,app.file("workspace-patch.zip"));
        TargetResolver.Target canonical=TargetResolver.resolve(app);JSONObject canonicalVerification=TargetResolver.requireVerified(canonical,app.cancelled);
        if(!canonical.apkSet){
            boolean saved=false;File signed=app.file("workspace-target-signed.apk");SigningKeyManager.Identity identity=SigningKeyManager.getOrCreate();
            try{ApkSignerUtil.sign(patchedUnsigned,signed,identity);copyFileToUri(signed,uri,"Сохранение APK");verifyWorkspaceHandoff(guardRequest,sourceApk,app.file("workspace-patch.zip"));saved=true;app.progress(singleDone);}
            finally{signed.delete();if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
            return;
        }
        if(canonical.members.size()<2)throw new IOException("Canonical APK-set не содержит полный набор splits");
        TargetResolver.Member currentSource=null;String sourceCanonical=sourceApk.getCanonicalPath();
        for(TargetResolver.Member member:canonical.members)if(member.file.getCanonicalPath().equals(sourceCanonical)){currentSource=member;break;}
        if(currentSource==null||currentSource.index!=guardedSource.index||!currentSource.name.equals(guardedSource.name))throw new IOException("Workspace owning split identity изменилась после build guard");

        boolean saved=false;File bundle=app.file("workspace-target-signed.apks"),signedDir=app.file("workspace-target-signed-set");SigningKeyManager.Identity identity=SigningKeyManager.getOrCreate();
        try{
            deleteTree(signedDir);if(!signedDir.mkdirs()&&!signedDir.isDirectory())throw new IOException("Не удалось создать каталог подписанного APK-set");
            ArrayList<File> signedFiles=new ArrayList<>();ArrayList<TargetResolver.Member> signedMembers=new ArrayList<>();int patchedCount=0;
            for(int i=0;i<canonical.members.size();i++){
                check();TargetResolver.Member member=canonical.members.get(i);boolean patched=member.index==guardedSource.index;if(patched)patchedCount++;
                File input=patched?patchedUnsigned:member.file;if(!input.isFile())throw new IOException("Split отсутствует: "+member.name);
                File signed=new File(signedDir,member.name);app.progress("APK-set: подпись "+(i+1)+"/"+canonical.members.size()+" · "+member.name);ApkSignerUtil.sign(input,signed,identity);signedFiles.add(signed);signedMembers.add(member);
            }
            if(patchedCount!=1||signedFiles.size()!=canonical.members.size())throw new IOException("Workspace APK-set build должен изменить ровно один split и сохранить полный set");

            File tmp=new File(bundle.getParentFile(),bundle.getName()+".tmp");Files.deleteIfExists(tmp.toPath());
            try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
                byte[] buf=new byte[1024*1024];JSONArray exportedMembers=new JSONArray();
                for(int i=0;i<signedFiles.size();i++){
                    check();File signedFile=signedFiles.get(i);TargetResolver.Member member=signedMembers.get(i);boolean patched=member.index==guardedSource.index;MessageDigest digest=MessageDigest.getInstance("SHA-256");
                    ZipEntry e=new ZipEntry(member.name);e.setTime(0L);z.putNextEntry(e);try(InputStream in=new FileInputStream(signedFile)){int n;while((n=in.read(buf))!=-1){check();digest.update(buf,0,n);z.write(buf,0,n);}}z.closeEntry();
                    StringBuilder sha=new StringBuilder(64);for(byte b:digest.digest())sha.append(String.format(Locale.ROOT,"%02x",b));
                    exportedMembers.put(new JSONObject().put("index",member.index).put("name",member.name).put("sourceSha256",member.sha256).put("signedSha256",sha.toString()).put("modified",patched));
                }
                JSONObject exportedTarget=new JSONObject().put("schema","modkit-workspace-export-target-1.0").put("sourceTargetId",canonical.targetId).put("sourceFingerprintSha256",canonical.fingerprint).put("sourceTargetDigest",canonicalVerification.getString("currentTargetDigest")).put("memberCount",canonical.members.size()).put("patchedSplitIndex",guardedSource.index).put("patchedSplitName",guardedSource.name).put("signing",new JSONObject().put("provider","AndroidKeyStore").put("certificateSha256",identity.fingerprintSha256)).put("members",exportedMembers);
                ZipEntry manifest=new ZipEntry("modkit-target.json");manifest.setTime(0L);z.putNextEntry(manifest);z.write(exportedTarget.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));z.closeEntry();
                ZipEntry readme=new ZipEntry("INSTALL.txt");readme.setTime(0L);z.putNextEntry(readme);z.write(("ModKit edited APK-set. Install all APKs together. Certificate SHA-256: "+identity.fingerprintSha256+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));z.closeEntry();
            }catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}
            catch(Error e){try{Files.deleteIfExists(tmp.toPath());}catch(Exception ignored){}throw e;}
            verifyWorkspaceHandoff(guardRequest,sourceApk,app.file("workspace-patch.zip"));Files.move(tmp.toPath(),bundle.toPath(),StandardCopyOption.REPLACE_EXISTING);copyFileToUri(bundle,uri,"Сохранение APK-set");verifyWorkspaceHandoff(guardRequest,sourceApk,app.file("workspace-patch.zip"));saved=true;app.progress(setDone);
        }finally{bundle.delete();deleteTree(signedDir);if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    }

    private void splitDiscovery(JSONObject scan) throws Exception {
        File set=app.file("installed-apk-set.zip"),full=app.file("re-analysis.json");
        app.progress("Installed scan: полной ARM64 IL2CPP-пары нет — multi-split DEX/.so/Unity Discovery…");
        File meta=app.file("metadata.bin"),lib=app.file("library.so");
        PyObject result=engine().callAttr("re_analyze_apk",set.getPath(),full.getPath(),meta.isFile()?meta.getPath():null,lib.isFile()?lib.getPath():null,null,null,null,new Progress(),"installed-apk-set-auto-discovery",true);
        JSONObject re=new JSONObject(result.toString());JSONObject menuSeed=null;File menuSide=app.file("re-analysis.menu.json");
        if(menuSide.isFile())try{menuSeed=new JSONObject(new String(Files.readAllBytes(menuSide.toPath()),java.nio.charset.StandardCharsets.UTF_8));}catch(Exception ignored){}
        JSONArray candidates=menuSeed==null?new JSONArray():menuSeed.optJSONArray("controlCandidates");if(candidates==null)candidates=new JSONArray();
        JSONObject summary=new JSONObject().put("schema","modkit-installed-discovery-1.0").put("installedScanOnly",true).put("installedScan",scan).put("reDiscovery",re).put("candidate_count",candidates.length()).put("candidates",candidates);
        app.result=summary;byte[] bytes=summary.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);Files.write(app.file("analysis.json").toPath(),bytes);Files.write(app.file("analysis.summary.json").toPath(),bytes);
        try{engine().callAttr("menu_seed_from_re",full.getPath(),app.file("menu-spec.json").getPath(),app.file("menu-project").getPath(),"ModKit Installed Discovery",new Progress());}catch(Exception seedError){new Progress().progress("Installed scan: Menu seed REVIEW — "+seedError.getMessage());}
        snapshotProjectAnalysis();app.progress("Installed scan готов: splits "+scan.optJSONObject("summary").optInt("splitCount")+", findings "+re.optInt("findingCount")+", review candidates "+candidates.length()+".");
    }
    private void scanInstalled(String packageName,String requestedLabel) throws Exception {
        if(packageName==null||packageName.trim().isEmpty())throw new IOException("Не выбран package");
        PackageManager pm=getPackageManager();ApplicationInfo info=pm.getApplicationInfo(packageName,0);CharSequence loaded=pm.getApplicationLabel(info);String label=requestedLabel==null||requestedLabel.isEmpty()?String.valueOf(loaded):requestedLabel;
        clearInstalledAnalysisState();File dir=app.file("installed-apks");if(!dir.mkdirs()&&!dir.isDirectory())throw new IOException("Не удалось создать каталог APK-set");
        ArrayList<String> sources=new ArrayList<>();sources.add(info.sourceDir);if(info.splitSourceDirs!=null)Collections.addAll(sources,info.splitSourceDirs);
        ArrayList<File> local=new ArrayList<>();JSONArray localPaths=new JSONArray();ArrayList<String> copyErrors=new ArrayList<>();
        for(int i=0;i<sources.size();i++){String source=sources.get(i);if(source==null)continue;File src=new File(source),dst=new File(dir,safeApkName(source,i,i==0));
            try{copyInstalledFile(src,dst,(i==0?"base":"split "+i));local.add(dst);localPaths.put(dst.getPath());}
            catch(Exception e){if(i==0)throw new IOException("Не удалось прочитать base APK установленного пакета: "+e.getMessage());copyErrors.add(src.getName()+": "+e.getMessage());new Progress().progress("Installed scan: split пропущен — "+src.getName());}
        }
        if(local.isEmpty())throw new IOException("Не удалось прочитать APK установленного пакета");
        copyInstalledFile(local.get(0),app.file("game.apk"),"base APK → рабочая копия");buildInstalledApkSet(local,app.file("installed-apk-set.zip"));
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject apkset=Python.getInstance().getModule("modkit.mobile.apkset");
        PyObject result=apkset.callAttr("inspect_apk_paths",localPaths.toString(),app.file("metadata.bin").getPath(),app.file("library.so").getPath(),app.file("installed-scan.json").getPath(),new Progress(),true);
        JSONObject scan=new JSONObject(result.toString()).put("packageName",packageName).put("label",label).put("copyErrors",new JSONArray(copyErrors));
        String versionName=null;long versionCode=0;
        try{PackageInfo pi=pm.getPackageInfo(packageName,0);versionName=pi.versionName;versionCode=Build.VERSION.SDK_INT>=28?pi.getLongVersionCode():pi.versionCode;scan.put("versionName",versionName);scan.put("versionCode",versionCode);}catch(Exception ignored){}
        scan.put("scanCompleteness",copyErrors.isEmpty()&&local.size()==sources.size()?"COMPLETE":"PARTIAL").put("expectedApkCount",sources.size()).put("copiedApkCount",local.size());
        boolean androidCategoryGame=Build.VERSION.SDK_INT>=26&&info.category==ApplicationInfo.CATEGORY_GAME;
        PyObject profileMod=Python.getInstance().getModule("modkit.mobile.target_profile");
        JSONObject targetProfile=new JSONObject(profileMod.callAttr("classify_apkset_scan_json",scan.toString(),androidCategoryGame).toString());
        scan.put("androidCategoryGame",androidCategoryGame).put("targetProfile",targetProfile);
        JSONObject selected=scan.optJSONObject("selected"),libSel=selected==null?null:selected.optJSONObject("library");if(libSel!=null){int idx=libSel.optInt("splitIndex",-1);if(idx>=0&&idx<local.size()&&idx!=0)copyInstalledFile(local.get(idx),app.file("game-native-split.apk"),"native split → рабочая копия");}
        Files.write(app.file("installed-scan.json").toPath(),scan.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        PyObject targetMod=Python.getInstance().getModule("modkit.mobile.package_target");
        JSONObject target=new JSONObject(targetMod.callAttr("build_target_manifest",scan.toString(),packageName,label,versionName,versionCode,sources.size(),new JSONArray(copyErrors).toString()).toString());
        Files.write(app.file("installed-target.json").toPath(),target.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));persistProjectTarget(target);
        android.content.SharedPreferences.Editor prefs=getSharedPreferences("state",0).edit().putString("installed.package",label+" · "+packageName).putString("game.apk",label+" · base.apk");
        if(app.file("metadata.bin").isFile())prefs.putString("metadata.bin","auto · "+selected.optJSONObject("metadata").optString("split")+"!global-metadata.dat");
        if(app.file("library.so").isFile())prefs.putString("library.so","auto · "+libSel.optString("split")+"!libil2cpp.so");prefs.apply();
        if(scan.optBoolean("fullIl2cppPair")){
            app.progress("Installed scan: IL2CPP pair найдена автоматически — запускаю полный анализ…");analyze();
            try{
                if(app.result!=null){app.result.put("targetProfile",scan.optJSONObject("targetProfile"));app.result.put("applicationDiscovery",scan.optJSONObject("applicationDiscovery"));}
                menuProbePrepare();
                File probe=app.file("menu-probe-prepare.json");if(probe.isFile()&&app.result!=null)app.result.put("installedProbe",new JSONObject(new String(Files.readAllBytes(probe.toPath()),java.nio.charset.StandardCharsets.UTF_8)));
                if(app.result!=null)Files.write(app.file("analysis.summary.json").toPath(),app.result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                JSONObject pre=probe.isFile()?new JSONObject(new String(Files.readAllBytes(probe.toPath()),java.nio.charset.StandardCharsets.UTF_8)).optJSONObject("preflight"):null;
                snapshotProjectAnalysis();app.progress("Installed scan готов: IL2CPP + Gameplay + Runtime Probe; payload "+(pre!=null&&pre.optBoolean("readyForPayload")?"READY":"REVIEW / native split может требоваться")+".");
            }catch(Exception probeError){app.progress("Installed scan: анализ готов, Runtime Probe seed REVIEW — "+probeError.getMessage());}
        }else splitDiscovery(scan);
    }

    private void importFile(Uri uri,String name,String display) throws Exception {
        if("metadata.bin".equals(name)||"library.so".equals(name)||"game.apk".equals(name)){
            deleteTree(app.file("installed-apks"));Files.deleteIfExists(app.file("installed-apk-set.zip").toPath());Files.deleteIfExists(app.file("installed-scan.json").toPath());Files.deleteIfExists(app.file("installed-target.json").toPath());Files.deleteIfExists(app.file("game-native-split.apk").toPath());
            getSharedPreferences("state",0).edit().remove("installed.package").remove("active.project").apply();
        }
        File temp=app.file(name+".tmp");
        try {
            try (InputStream in=getContentResolver().openInputStream(uri); OutputStream out=new FileOutputStream(temp)) {
                if (in==null) throw new IOException("Не удалось открыть выбранный файл");
                byte[] bytes=new byte[1024*1024]; int n; long total=0;
                while ((n=in.read(bytes))!=-1) {
                    check(); out.write(bytes,0,n); total+=n;
                    new Progress().progress("Импорт: "+(total/1024/1024)+" МБ — "+display);
                }
                if (total==0) throw new IOException("Выбран пустой файл");
            }
            check();
            Files.move(temp.toPath(),app.file(name).toPath(),StandardCopyOption.REPLACE_EXISTING);
            synchronized(app) {
                app.result=null;
                Files.deleteIfExists(app.file("analysis.json").toPath());
                Files.deleteIfExists(app.file("analysis.summary.json").toPath());
                Files.deleteIfExists(app.file("security-surfaces.json").toPath());
                Files.deleteIfExists(app.file("simple-catalog.json").toPath());
                Files.deleteIfExists(app.file("simple-cache.json").toPath());
                Files.deleteIfExists(app.file("simple-progress.json").toPath());
                Files.deleteIfExists(app.file("analysis.ui.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.methods.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.methods.jsonl.idx").toPath());
                Files.deleteIfExists(app.file("analysis.methods.jsonl.pages.idx").toPath());
                Files.deleteIfExists(app.file("analysis.methods.jsonl.rva.idx").toPath());
                Files.deleteIfExists(app.file("analysis.methods.meta.json").toPath());
                Files.deleteIfExists(app.file("analysis.candidates.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.discoveries.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.evidence-graph.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.evidence-graph.jsonl.idx").toPath());
                Files.deleteIfExists(app.file("analysis.evidence-graph.meta.json").toPath());
                Files.deleteIfExists(app.file("analysis.fields.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.resolver-index.json").toPath());
                Files.deleteIfExists(app.file("analysis.autopilot-index.jsonl").toPath());
                Files.deleteIfExists(app.file("analysis.gameplay-coverage.json").toPath());
                deleteTree(app.file("analysis-deep"));
                getSharedPreferences("state",0).edit().putString(name,display).remove("selections").apply();
            }
            app.progress("Файл выбран: "+display);
        } finally { temp.delete(); }
    }
    private PyObject engine() {
        if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
        return Python.getInstance().getModule("modkit.mobile.engine");
    }
    private void analyze() throws Exception {
        deleteTree(app.file("analysis-deep"));
        app.progress("Запуск Rodroid Il2CppDumper V7…");
        File dump=RodroidRunner.run(this,app.file("library.so"),app.file("metadata.bin"),app.file("rodroid"),app.cancelled,new Progress()::progress);
        app.progress("Построение списка изменений из script.json…");
        PyObject result=engine().callAttr("analyze_rodroid",dump.getPath(),app.file("metadata.bin").getPath(),app.file("library.so").getPath(),app.file("analysis.json").getPath(),new Progress(),true,app.file("analysis.ui.jsonl").getPath(),app.file("analysis.methods.jsonl").getPath());
        String compact=result.toString();
        app.result=new JSONObject(compact);
        if(app.file("analysis.methods.jsonl").isFile()){
            app.progress("Gameplay Discovery: общий Evidence Graph и игровые сущности…");
            File evidenceApk=app.file("installed-apk-set.zip").isFile()?app.file("installed-apk-set.zip"):app.file("game.apk");
            String apk=evidenceApk.isFile()?evidenceApk.getPath():"";
            PyObject gp=engine().callAttr("build_gameplay_discovery",app.file("metadata.bin").getPath(),app.file("library.so").getPath(),app.file("analysis.methods.jsonl").getPath(),app.file("analysis.evidence-graph.jsonl").getPath(),app.file("analysis.gameplay-coverage.json").getPath(),apk,app.file("analysis.json").getPath(),new Progress());
            app.result.put("gameplayDiscovery",new JSONObject(gp.toString()));
        }
        if(app.file("installed-scan.json").isFile()){try{app.result.put("installedScan",new JSONObject(new String(Files.readAllBytes(app.file("installed-scan.json").toPath()),java.nio.charset.StandardCharsets.UTF_8)));}catch(Exception ignored){}}
        compact=app.result.toString();
        Files.write(app.file("analysis.summary.json").toPath(),compact.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        getSharedPreferences("state",0).edit().remove("selections").apply();
        snapshotProjectAnalysis();JSONObject catalog=app.result.optJSONObject("metadata_method_catalog");int full=catalog==null?0:catalog.optInt("rows",0);int confirmed=catalog==null?0:catalog.optInt("addressConfirmed",0);app.progress("Готово. Полный metadata-каталог: "+full+" методов, RVA подтверждено: "+confirmed+". Gameplay Discovery построен. Доступно для изменения: "+app.result.optInt("candidate_count",0)+".");
    }
    private void deepMethod(int methodId) throws Exception {
        if(methodId<0)throw new IOException("Некорректный metadata method id");
        File meta=app.file("metadata.bin"),lib=app.file("library.so"),catalog=app.file("analysis.methods.jsonl"),rod=app.file("rodroid");
        if(!meta.isFile()||!lib.isFile()||!catalog.isFile())throw new IOException("Сначала выполните полный IL2CPP-анализ");
        File deep=app.file("analysis-deep");if(!deep.exists()&&!deep.mkdirs())throw new IOException("Не удалось создать каталог Deep Resolver");
        File output=new File(deep,"method-"+methodId+".json");
        app.progress("Deep Resolver: method id "+methodId+" — точная проверка metadata/RVA/ABI…");
        PyObject result=engine().callAttr("deep_resolve_method",meta.getPath(),lib.getPath(),catalog.getPath(),methodId,output.getPath(),new Progress(),rod.getPath());
        JSONObject obj=new JSONObject(result.toString()),sem=obj.optJSONObject("semantic"),ctx=obj.optJSONObject("contextVerification"),menu=obj.optJSONObject("menuEligibility");
        deep.setLastModified(System.currentTimeMillis());
        app.progress("Deep Resolver: "+obj.optString("decision","review")+" · semantic "+(sem!=null&&sem.optBoolean("verified")?"OK":"REVIEW")+" · context "+(ctx!=null&&ctx.optBoolean("verified")?"OK":"REVIEW")+" · Menu "+(menu!=null&&menu.optBoolean("eligible")?"CANDIDATE":"BLOCKED"));
    }
    private void reportFile(Uri uri) throws Exception {
        boolean saved=false;
        try (InputStream in=new FileInputStream(app.file("analysis.json")); OutputStream out=getContentResolver().openOutputStream(uri,"wt")) {
            if(out==null)throw new IOException("Не удалось открыть файл для записи");
            byte[] bytes=new byte[1024*1024];int n;while((n=in.read(bytes))!=-1){check();out.write(bytes,0,n);}
            out.flush();saved=true;app.progress("Отчёт анализа сохранён.");
        } finally {if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    }
    private void exportFile(Uri uri,String selections) throws Exception {
        File zip=app.file("modkit-result.zip");
        boolean saved=false;
        try {
            engine().callAttr("export",app.file("analysis.json").getPath(),app.file("library.so").getPath(),selections,zip.getPath(),new Progress());
            try (InputStream in=new FileInputStream(zip); OutputStream out=getContentResolver().openOutputStream(uri,"wt")) {
                if(out==null) throw new IOException("Не удалось открыть файл для записи");
                byte[] bytes=new byte[1024*1024]; int n; long total=0;
                while ((n=in.read(bytes))!=-1) {
                    check(); out.write(bytes,0,n); total+=n;
                    new Progress().progress("Сохранение ZIP: "+total*100/Math.max(1,zip.length())+"%");
                }
                out.flush();
            }
            saved=true;
            app.progress("ZIP сохранён: изменённая libil2cpp.so, список изменений и отчёт. Оригиналы не изменены.");
        } finally {
            zip.delete();
            if (!saved) try { DocumentsContract.deleteDocument(getContentResolver(),uri); } catch(Exception ignored) { }
        }
    }
    private void buildApk(Uri uri,String selections) throws Exception {
        File unsigned=app.file("game-unsigned.apk");
        try {
            verifyInstalledTarget();File patchApk=targetPatchApk();
            app.progress(targetIsApkSet()?"Замена ARM64 libil2cpp.so в owning split…":"Замена ARM64 libil2cpp.so и выравнивание APK…");
            engine().callAttr("export_apk_unsigned",app.file("analysis.json").getPath(),app.file("library.so").getPath(),selections,patchApk.getPath(),unsigned.getPath(),new Progress());
            exportSignedTarget(uri,unsigned,"Готово: APK собран, подписан и проверен.","Готово: owning split изменён, весь APK-set переподписан одним ключом и сохранён.");
        } finally {
            unsigned.delete();
        }
    }
    private void dumpFile(Uri uri) throws Exception {
        File zip=app.file("rodroid-full-dump.zip");boolean saved=false;
        try {
            engine().callAttr("export_dump",app.file("rodroid").getPath(),app.file("analysis.json").getPath(),zip.getPath(),new Progress(),app.file("analysis.methods.jsonl").getPath(),app.file("analysis.methods.meta.json").getPath(),app.file("analysis-deep").getPath());
            try(InputStream in=new FileInputStream(zip);OutputStream out=getContentResolver().openOutputStream(uri,"wt")){
                if(out==null)throw new IOException("Не удалось открыть ZIP для записи");
                byte[] bytes=new byte[1024*1024];int n;long total=0;
                while((n=in.read(bytes))!=-1){check();out.write(bytes,0,n);total+=n;new Progress().progress("Сохранение полного дампа: "+total*100/Math.max(1,zip.length())+"%");}
                out.flush();
            }
            saved=true;app.progress("Полный дамп Rodroid сохранён.");
        } finally {
            zip.delete();
            if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}
        }
    }

    private void copyUri(Uri uri,File dest,String label) throws Exception {
        File temp=new File(dest.getParentFile(),dest.getName()+".tmp");
        try(InputStream in=getContentResolver().openInputStream(uri);OutputStream out=new FileOutputStream(temp)){
            if(in==null)throw new IOException("Не удалось открыть выбранный файл");
            byte[] bytes=new byte[1024*1024];int n;long total=0;
            while((n=in.read(bytes))!=-1){check();out.write(bytes,0,n);total+=n;new Progress().progress(label+": "+(total/1024/1024)+" МБ");}
            if(total==0)throw new IOException("Выбран пустой файл");
        }
        Files.move(temp.toPath(),dest.toPath(),StandardCopyOption.REPLACE_EXISTING);
    }
    private void writeResult(File dest,PyObject result) throws Exception {
        Files.write(dest.toPath(),result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    private void reAnalyze() throws Exception {
        if(!app.file("game.apk").isFile())throw new IOException("Сначала выберите исходный APK");
        File extractedMeta=app.file("re-metadata.bin"),extractedLib=app.file("re-library.so"),rod=app.file("re-rodroid");
        File selectedMeta=app.file("metadata.bin"),selectedLib=app.file("library.so");
        File mainRod=app.file("rodroid"),mainAnalysis=app.file("analysis.json"),mainSummary=app.file("analysis.summary.json");
        File unityReport=app.file("re-unity.json"),il2cppReport=app.file("re-il2cpp-analysis.json");
        File fullReport=app.file("re-analysis.json"),uiReport=app.file("re-analysis.ui.json"),menuReport=app.file("re-analysis.menu.json");
        Files.deleteIfExists(extractedMeta.toPath());Files.deleteIfExists(extractedLib.toPath());Files.deleteIfExists(unityReport.toPath());Files.deleteIfExists(il2cppReport.toPath());
        // Never expose a stale/partially written RE result as current. The Python
        // writer creates these atomically; leftover .tmp files can only come from
        // a process kill or device reboot.
        Files.deleteIfExists(fullReport.toPath());Files.deleteIfExists(uiReport.toPath());Files.deleteIfExists(menuReport.toPath());
        Files.deleteIfExists(app.file("re-analysis.json.tmp").toPath());Files.deleteIfExists(app.file("re-analysis.ui.json.tmp").toPath());Files.deleteIfExists(app.file("re-analysis.menu.json.tmp").toPath());
        deleteTree(rod);
        app.progress("RE Workspace: Unity/Addressables и автоматическое извлечение IL2CPP…");
        if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
        PyObject unity=Python.getInstance().getModule("modkit.mobile.unityscan");
        unity.callAttr("inspect_apk",app.file("game.apk").getPath(),extractedMeta.getPath(),extractedLib.getPath(),unityReport.getPath(),new Progress());

        // A Play/AppGallery split base often contains global-metadata.dat but keeps
        // libil2cpp.so in split_config.arm64_v8a.apk.  Dev17 accidentally required
        // both files to be re-extracted from base.apk, discarding the already selected
        // and already Rodroid-verified pair from the main screen.  Prefer an exact APK
        // pair when both were extracted; otherwise use the complete selected pair.
        boolean apkPair=extractedMeta.isFile()&&extractedLib.isFile();
        boolean selectedPair=selectedMeta.isFile()&&selectedLib.isFile();
        File meta=apkPair?extractedMeta:(selectedPair?selectedMeta:null);
        File lib=apkPair?extractedLib:(selectedPair?selectedLib:null);
        String inputMode=apkPair?"apk-extracted-pair":(selectedPair?"selected-external-pair":"apk-only-no-il2cpp-pair");
        if(meta==null||lib==null){
            app.progress("RE Workspace: в APK нет полной IL2CPP-пары и на главном экране не выбраны metadata + libil2cpp.so; продолжу DEX/Unity анализ без managed xref.");
        }else if(!apkPair){
            app.progress("RE Workspace: split APK — использую выбранные global-metadata.dat + libil2cpp.so для IL2CPP xref/context.");
        }

        String rodPath=null, il2cppPath=null;
        if(meta!=null&&lib!=null){
            // Importing any main-screen source invalidates analysis.json/summary/index,
            // so their presence is a cheap but reliable proof that this Rodroid report
            // belongs to the currently selected metadata/library pair. Reuse it instead
            // of dumping the same 100+ MiB IL2CPP target twice.
            boolean reuseMain=!apkPair&&mainAnalysis.isFile()&&mainSummary.isFile()&&mainRod.isDirectory();
            if(reuseMain){
                app.progress("RE Workspace: переиспользую уже завершённый Rodroid-анализ выбранной IL2CPP-пары…");
                rodPath=mainRod.getPath();
                il2cppPath=mainAnalysis.getPath();
                inputMode="selected-external-pair+reused-rodroid";
            }else{
                try{
                    app.progress(apkPair?"RE Workspace: Rodroid dump из IL2CPP-пары, извлечённой из APK…":"RE Workspace: Rodroid dump из выбранной внешней IL2CPP-пары…");
                    File dump=RodroidRunner.run(this,lib,meta,rod,app.cancelled,new Progress()::progress);
                    rodPath=dump.getPath();
                    engine().callAttr("analyze_rodroid",dump.getPath(),meta.getPath(),lib.getPath(),il2cppReport.getPath(),new Progress());
                    il2cppPath=il2cppReport.getPath();
                }catch(Exception dumpError){app.progress("Rodroid не завершён, продолжаю статическую корреляцию: "+dumpError.getMessage());}
            }
        }
        app.progress("RE Workspace: корреляция DEX + metadata + dump + всех .so…");
        File reTarget=app.file("installed-apk-set.zip").isFile()?app.file("installed-apk-set.zip"):app.file("game.apk");
        if(reTarget.getName().equals("installed-apk-set.zip"))inputMode="installed-apk-set+"+inputMode;
        PyObject result=engine().callAttr("re_analyze_apk",reTarget.getPath(),fullReport.getPath(),meta==null?null:meta.getPath(),lib==null?null:lib.getPath(),rodPath,unityReport.isFile()?unityReport.getPath():null,il2cppPath,new Progress(),inputMode,true);
        JSONObject obj=new JSONObject(result.toString());
        JSONObject diag=obj.optJSONObject("pipelineDiagnostics"),proof=diag==null?null:diag.optJSONObject("methodVerification");String proofText=proof==null?"":(", method proof: "+proof.optInt("addressConfirmed",0)+" addr / "+proof.optInt("abiConfirmed",0)+" ABI / "+proof.optInt("xrefCorroborated",0)+" xref");
        snapshotProjectAnalysis();app.progress("RE-анализ готов. Находок: "+obj.optInt("findingCount",0)+", IL2CPP xrefs: "+obj.optInt("il2cppXrefs",0)+", context methods: "+obj.optInt("contextMethods",0)+proofText+".");
    }
    private void nativeImport(Uri uri,String display) throws Exception {
        copyUri(uri,app.file("native-source.so"),"Импорт .so");
        Files.deleteIfExists(app.file("native-search.json").toPath());Files.deleteIfExists(app.file("native-disasm.json").toPath());
        PyObject result=engine().callAttr("native_workspace_create",app.file("native-source.so").getPath(),app.file("native-working.so").getPath(),app.file("native-state.json").getPath(),new Progress());
        writeResult(app.file("native-info.json"),result);getSharedPreferences("state",0).edit().putString("native-source.so",display).apply();
        app.progress("Native Workspace открыт: "+display);
    }
    private void refreshNativeInfo() throws Exception {writeResult(app.file("native-info.json"),engine().callAttr("native_workspace_info",app.file("native-working.so").getPath(),app.file("native-state.json").getPath()));}
    private void nativeSearch(String query) throws Exception {app.progress("Поиск в native symbols/strings…");writeResult(app.file("native-search.json"),engine().callAttr("native_workspace_search",app.file("native-working.so").getPath(),query==null?"":query,200));app.progress("Поиск завершён.");}
    private void nativeDisasm(String rva) throws Exception {if(rva==null||rva.trim().isEmpty())throw new IOException("Укажите RVA");app.progress("ARM64 disassembly…");writeResult(app.file("native-disasm.json"),engine().callAttr("native_workspace_disasm",app.file("native-working.so").getPath(),rva,512));app.progress("Дизассемблирование готово.");}
    private void nativeXrefs(String rva) throws Exception {if(rva==null||rva.trim().isEmpty())throw new IOException("Укажите RVA");app.progress("Поиск прямых ARM64 BL-ссылок…");writeResult(app.file("native-xrefs.json"),engine().callAttr("native_workspace_xrefs",app.file("native-working.so").getPath(),rva,400));app.progress("Static xrefs готовы; это не runtime trace.");}
    private void nativePatch(String rva,String mode,String payload) throws Exception {if(rva==null||rva.trim().isEmpty())throw new IOException("Укажите RVA");if(payload==null||payload.trim().isEmpty())throw new IOException("Укажите HEX/ASM");engine().callAttr("native_workspace_patch",app.file("native-working.so").getPath(),app.file("native-state.json").getPath(),rva,mode,payload,"Android editor",new Progress());refreshNativeInfo();app.progress("Изменение применено к рабочей копии .so.");}
    private void nativeUndo() throws Exception {engine().callAttr("native_workspace_undo",app.file("native-working.so").getPath(),app.file("native-state.json").getPath());refreshNativeInfo();app.progress("Последнее изменение отменено.");}
    private void nativeSaveUri(Uri uri) throws Exception {boolean saved=false;try(InputStream in=new FileInputStream(app.file("native-working.so"));OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Не удалось открыть файл для записи");byte[] b=new byte[1024*1024];int n;while((n=in.read(b))!=-1){check();out.write(b,0,n);}out.flush();saved=true;app.progress("Изменённая .so сохранена.");}finally{if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}}
    private void patchPackImport(Uri uri,String display) throws Exception {copyUri(uri,app.file("patchpack.zip"),"Импорт Patch Pack");getSharedPreferences("state",0).edit().putString("patchpack.zip",display).apply();patchPackInspect();}
    private void patchPackInspect() throws Exception {if(!app.file("patchpack.zip").isFile())throw new IOException("Нужен Patch Pack ZIP");File patchApk=targetPatchApk();PyObject result=engine().callAttr("patchpack_inspect",patchApk.getPath(),app.file("patchpack.zip").getPath(),app.file("patchpack-report.json").getPath(),new Progress());JSONObject obj=new JSONObject(result.toString());app.progress(obj.optBoolean("blocked")?"Patch Pack заблокирован проверками совместимости.":"Patch Pack совместим с owning APK target.");}
    private void patchPackBuild(Uri uri) throws Exception {
        File unsigned=app.file("patchpack-unsigned.apk");
        try{verifyInstalledTarget();File patchApk=targetPatchApk();engine().callAttr("patchpack_apply_unsigned",patchApk.getPath(),app.file("patchpack.zip").getPath(),unsigned.getPath(),app.file("patchpack-report.json").getPath(),new Progress());exportSignedTarget(uri,unsigned,"Patch Pack APK собран и подписан.","Patch Pack применён к owning split; весь APK-set переподписан одним ключом.");}finally{unsigned.delete();}
    }
    private void workspaceInspect(String source) throws Exception {
        if(source==null||source.isEmpty())throw new IOException("Не выбран source APK для File Workspace");File src=new File(source);if(!src.isFile())throw new IOException("Source APK больше не существует");File pack=app.file("workspace-patch.zip");if(!pack.isFile())throw new IOException("Workspace Patch Pack отсутствует");
        PyObject result=engine().callAttr("patchpack_inspect",src.getPath(),pack.getPath(),app.file("workspace-report.json").getPath(),new Progress());JSONObject obj=new JSONObject(result.toString());app.progress(obj.optBoolean("blocked")?"File Workspace: Patch Pack BLOCKED":"File Workspace: Patch Pack совместим; можно собирать APK/APK-set.");
    }
    private static final long WORKSPACE_PATCH_MAX_BYTES=21L*1024L*1024L;
    private String workspaceGuardString(Intent request,String key)throws IOException{String value=request==null?null:request.getStringExtra(key);if(value==null)throw new IOException("Workspace build handoff не содержит "+key);return value;}
    private String workspaceGuardSha(Intent request,String key)throws IOException{String value=workspaceGuardString(request,key);if(!value.matches("(?i)[0-9a-f]{64}"))throw new IOException("Workspace build handoff содержит некорректный SHA-256: "+key);return value;}
    private String sha256WorkspaceArtifact(File file,long maxBytes)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[256*1024];long total=0;
        try(InputStream in=new FileInputStream(file)){int n;while((n=in.read(buffer))!=-1){check();total+=n;if(total>maxBytes)throw new IOException("Workspace Patch Pack превышает допустимый размер");digest.update(buffer,0,n);}}
        StringBuilder out=new StringBuilder(64);for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }
    private TargetResolver.Member verifyWorkspaceHandoff(Intent request,File source,File pack)throws Exception{
        if(request==null)throw new IOException("Workspace build handoff отсутствует");
        String expectedTargetId=workspaceGuardString(request,"workspaceGuardTargetId"),expectedFingerprint=workspaceGuardString(request,"workspaceGuardTargetFingerprint"),expectedDigest=workspaceGuardSha(request,"workspaceGuardTargetDigest"),expectedPatch=workspaceGuardSha(request,"workspaceGuardPatchSha256"),expectedName=workspaceGuardString(request,"workspaceGuardSplitName");
        int expectedIndex=request.getIntExtra("workspaceGuardSplitIndex",Integer.MIN_VALUE);if(expectedIndex<0)throw new IOException("Workspace build handoff содержит некорректный split index");
        TargetResolver.Target target=TargetResolver.resolve(app);JSONObject verification=TargetResolver.requireVerified(target,app.cancelled);
        if(!expectedTargetId.equals(target.targetId))throw new IOException("Workspace targetId изменился после build guard");
        if(!expectedFingerprint.equals(target.fingerprint))throw new IOException("Workspace target fingerprint изменился после build guard");
        if(!expectedDigest.equalsIgnoreCase(verification.optString("currentTargetDigest","")))throw new IOException("Workspace target digest изменился после build guard");
        String canonical=source.getCanonicalPath();TargetResolver.Member found=null;for(TargetResolver.Member member:target.members)if(member.file.getCanonicalPath().equals(canonical)){found=member;break;}
        if(found==null||found.index!=expectedIndex||!found.name.equals(expectedName))throw new IOException("Workspace source split изменился после build guard");
        if(!pack.isFile())throw new IOException("Workspace Patch Pack отсутствует после build guard");
        String actualPatch=sha256WorkspaceArtifact(pack,WORKSPACE_PATCH_MAX_BYTES);if(!expectedPatch.equalsIgnoreCase(actualPatch))throw new IOException("Workspace Patch Pack изменился после build guard");
        return found;
    }
    private void workspaceBuild(Intent request,Uri uri) throws Exception {
        String source=workspaceGuardString(request,"source");if(source.isEmpty())throw new IOException("Не выбран source APK для File Workspace");File src=new File(source),pack=app.file("workspace-patch.zip"),unsigned=app.file("workspace-unsigned.apk");if(!src.isFile()||!pack.isFile())throw new IOException("Workspace source/patch отсутствует");
        verifyWorkspaceHandoff(request,src,pack);
        try{engine().callAttr("patchpack_apply_unsigned",src.getPath(),pack.getPath(),unsigned.getPath(),app.file("workspace-report.json").getPath(),new Progress());verifyWorkspaceHandoff(request,src,pack);exportSignedTargetForSource(uri,unsigned,src,request,"Изменённый APK собран и подписан.","Изменён owning split; APK-set переподписан одним ключом.");}finally{unsigned.delete();}
    }
    private long simpleStartedAt=0L;
    private void simpleCheckCancelled() throws IOException {
        if(app.cancelled.get())throw new IOException("Simple Mode: отменено пользователем");
    }
    private void simpleStage(int stage,int total,String name) throws Exception {
        simpleCheckCancelled();
        JSONObject p=new JSONObject();p.put("schema","modkit-simple-progress-1.0");p.put("stage",stage);p.put("totalStages",total);p.put("name",name);p.put("remainingStages",Math.max(0,total-stage));p.put("elapsedMs",Math.max(0L,System.currentTimeMillis()-simpleStartedAt));
        try{if(app.file("simple-catalog.json").isFile()){JSONObject c=new JSONObject(Io.readUtf8(app.file("simple-catalog.json")));p.put("candidates",c.optInt("total"));p.put("confirmed",c.optInt("actionable"));p.put("patchReady",c.optInt("buildable"));}}catch(Exception ignored){}
        try(java.io.FileOutputStream out=new java.io.FileOutputStream(app.file("simple-progress.json"))){out.write(p.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        app.progress("Simple Mode ["+stage+"/"+total+"]: "+name);
    }
    private void simplePrepare() throws Exception {
        if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile())throw new IOException("Сначала выберите установленное приложение/игру или APK");
        simpleStartedAt=System.currentTimeMillis();if(!Python.isStarted())Python.start(new AndroidPlatform(this));
        PyObject cache=Python.getInstance().getModule("modkit.mobile.simple_cache");
        simpleStage(1,6,"инвентаризация APK/split + SHA-256 кэш");
        JSONObject plan=new JSONObject(cache.callAttr("plan_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath()).toString());
        boolean unchanged=plan.optBoolean("unchanged",false);boolean haveAnalysis=app.file("analysis.json").isFile()||app.file("re-analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile();
        simpleStage(2,6,unchanged&&haveAnalysis?"кэш hit: DEX/native/IL2CPP результаты не изменились":"engine + DEX/native/IL2CPP discovery/analysis");
        if(!unchanged||!haveAnalysis){
            if(app.file("installed-scan.json").isFile()){
                JSONObject scan=new JSONObject(Io.readUtf8(app.file("installed-scan.json")));simpleCheckCancelled();
                if(scan.optBoolean("fullIl2cppPair")&&app.file("metadata.bin").isFile()&&app.file("library.so").isFile())analyze();
                else if(app.file("installed-apk-set.zip").isFile())splitDiscovery(scan);
            }else if(!haveAnalysis){
                app.progress("Simple Mode: APK выбран; полного analysis report ещё нет — продолжаю engine/security/content discovery и не повышаю неподтверждённые точки до READY.");
            }
        }
        simpleStage(3,6,"gameplay semantics + существующие Deep Resolver/Menu evidence");
        if(app.file("analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile()||app.file("re-analysis.json").isFile()){try{menuSmartPrepare();}catch(Exception e){new Progress().progress("Simple Mode: Menu prepare остаётся REVIEW — "+e.getMessage());}}
        simpleCheckCancelled();
        simpleStage(4,6,unchanged&&app.file("security-surfaces.json").isFile()?"кэш hit: passive Network/API + Crypto/Keys":"passive Network/API + TLS + Crypto/Keys scan");
        JSONObject secObj;
        if(unchanged&&app.file("security-surfaces.json").isFile())secObj=new JSONObject(Io.readUtf8(app.file("security-surfaces.json")));
        else{PyObject sec=Python.getInstance().getModule("modkit.mobile.security_scan");PyObject secOut=sec.callAttr("scan_workspace",getFilesDir().getPath(),app.file("security-surfaces.json").getPath());secObj=new JSONObject(secOut.toString());}
        simpleCheckCancelled();
        simpleStage(5,6,"ownership + confirmation ladder + exact locators + ranking");
        PyObject mod=Python.getInstance().getModule("modkit.mobile.simple_mode");PyObject out=mod.callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath());JSONObject obj=new JSONObject(out.toString());
        simpleCheckCancelled();simpleStage(6,6,"сохранение кэша и каталога");
        cache.callAttr("record_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),plan.toString());
        app.progress("Simple Mode: найдено "+obj.optInt("total")+", важных "+obj.optInt("important")+", PATCH_READY "+obj.optInt("buildable")+", locator "+obj.optInt("actionable")+", server/trust "+obj.optInt("serverAudit")+", framework "+obj.optInt("frameworkNoise")+(unchanged?" · cache hit":" · fresh target")+".");
    }
    private void simpleBuild(Uri uri,String controlsJson) throws Exception {
        if(controlsJson==null)controlsJson="[]";if(!app.file("menu-spec.json").isFile())menuSmartPrepare();
        File backup=app.file("menu-spec.simple-source.json");Files.copy(app.file("menu-spec.json").toPath(),backup.toPath(),StandardCopyOption.REPLACE_EXISTING);
        if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject mod=Python.getInstance().getModule("modkit.mobile.simple_mode");JSONObject filtered=new JSONObject(mod.callAttr("filter_menu_spec",app.file("menu-spec.json").getPath(),controlsJson).toString());if(filtered.optInt("buildable",0)<=0){Files.copy(backup.toPath(),app.file("menu-spec.json").toPath(),StandardCopyOption.REPLACE_EXISTING);throw new IOException("Выбранные пункты не имеют подтверждённых локальных executable bindings");}
        invalidateMenuChecks();menuProject();app.progress("Simple Mode: выбранных подтверждённых controls "+filtered.optInt("buildable")+"; выполняю preflight и сборку…");menuBuildApk(uri);
    }

    private void invalidateMenuChecks() throws IOException {Files.deleteIfExists(app.file("menu-validation.json").toPath());Files.deleteIfExists(app.file("menu-preflight.json").toPath());}
    private void menuSeedDeep() throws Exception {
        if(!app.file("analysis-deep").isDirectory())throw new IOException("Сначала выполните Deep Resolver хотя бы для одного метода");
        PyObject result=engine().callAttr("menu_seed_from_deep",app.file("analysis-deep").getPath(),app.file("menu-spec.json").getPath(),app.file("menu-project").getPath(),"ModKit Deep Menu",new Progress());
        Files.write(app.file("menu-result.json").toPath(),result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        JSONObject obj=new JSONObject(result.toString());invalidateMenuChecks();
        app.progress("Deep Resolver → Menu Builder: прошло все static gates "+obj.optInt("eligibleControls",0)+" из "+obj.optInt("deepResults",0)+" проверенных методов. Binding остаётся review до APK preflight.");
    }
    private void menuProbePrepare() throws Exception {
        File coverage=app.file("analysis.gameplay-coverage.json"),apk=targetPatchApk(),graph=app.file("analysis.evidence-graph.meta.json");
        if(!coverage.isFile())throw new IOException("Сначала выполните полный IL2CPP-анализ: gameplay coverage отсутствует");
        if(!apk.isFile())throw new IOException("Сначала выберите исходный APK");
        PyObject result=engine().callAttr("menu_probe_prepare_from_gameplay",coverage.getPath(),app.file("menu-spec.json").getPath(),apk.getPath(),app.file("menu-project").getPath(),graph.isFile()?graph.getPath():null,app.file("menu-probe-prepare.json").getPath(),"ModKit Runtime Probe",48,new Progress());
        JSONObject obj=new JSONObject(result.toString());invalidateMenuChecks();
        app.progress("Runtime Probe: read-only WATCH controls "+obj.optInt("readOnlyProbes",0)+". Нажатие SCAN только ищет live object и читает exact field offset.");
    }
    private void menuProbeBuildApk(Uri uri) throws Exception {
        app.progress("Runtime Probe: gameplay coverage → WATCH MenuSpec…");menuProbePrepare();
        JSONObject preflight=menuPreflightReport();
        if(!preflight.optBoolean("readyForPayload"))throw new IOException("Runtime Probe preflight не готов: проверьте SHA/target APK");
        app.progress("Runtime Probe: preflight READY, сборка подписанного тестового APK…");menuBuildApk(uri);
    }
    private void menuSeed() throws Exception {if(!app.file("re-analysis.json").isFile())throw new IOException("Сначала выполните RE-анализ");PyObject result=engine().callAttr("menu_seed_from_re",app.file("re-analysis.json").getPath(),app.file("menu-spec.json").getPath(),app.file("menu-project").getPath(),"ModKit Menu",new Progress());Files.write(app.file("menu-result.json").toPath(),result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));invalidateMenuChecks();app.progress("Menu Builder создан из RE-находок; evidence RVA сохранены отдельно до подтверждения.");}
    private void menuAutoPrepare() throws Exception {if(!app.file("re-analysis.json").isFile())throw new IOException("Сначала выполните RE-анализ");File patchApk=targetPatchApk();Files.deleteIfExists(app.file("menu-validation.json").toPath());PyObject result=engine().callAttr("menu_auto_prepare_from_re",app.file("re-analysis.json").getPath(),app.file("menu-spec.json").getPath(),patchApk.getPath(),app.file("menu-project").getPath(),app.file("menu-auto-prepare.json").getPath(),app.file("menu-preflight.json").getPath(),"ModKit Menu",new Progress());JSONObject obj=new JSONObject(result.toString()),confirm=obj.optJSONObject("confirm"),pre=obj.optJSONObject("preflight");JSONArray promoted=confirm==null?null:confirm.optJSONArray("promoted"),rejected=confirm==null?null:confirm.optJSONArray("rejected");app.progress("RE → Menu: confirmed "+(promoted==null?0:promoted.length())+", rejected "+(rejected==null?0:rejected.length())+", payload "+(pre!=null&&pre.optBoolean("readyForPayload")?"READY":"REVIEW")+".");}
    private void menuAutoPrepareDeep() throws Exception {if(!app.file("analysis-deep").isDirectory())throw new IOException("Сначала выполните Deep Resolver хотя бы для одного метода");File patchApk=targetPatchApk();Files.deleteIfExists(app.file("menu-validation.json").toPath());PyObject result=engine().callAttr("menu_auto_prepare_from_deep",app.file("analysis-deep").getPath(),app.file("menu-spec.json").getPath(),patchApk.getPath(),app.file("menu-project").getPath(),app.file("menu-auto-prepare-deep.json").getPath(),app.file("menu-preflight.json").getPath(),"ModKit Deep Menu",new Progress());JSONObject obj=new JSONObject(result.toString()),confirm=obj.optJSONObject("confirm"),pre=obj.optJSONObject("preflight");JSONArray promoted=confirm==null?null:confirm.optJSONArray("promoted"),rejected=confirm==null?null:confirm.optJSONArray("rejected");app.progress("Deep Resolver → Menu: candidates "+obj.optInt("eligibleControls",0)+", confirmed "+(promoted==null?0:promoted.length())+", rejected "+(rejected==null?0:rejected.length())+", payload "+(pre!=null&&pre.optBoolean("readyForPayload")?"READY":"REVIEW")+".");}
    private void menuAutopilotPrepare() throws Exception {
        File meta=app.file("metadata.bin"),lib=app.file("library.so"),catalog=app.file("analysis.methods.jsonl"),apk=targetPatchApk(),rod=app.file("rodroid");
        if(!meta.isFile()||!lib.isFile()||!catalog.isFile()||!apk.isFile())throw new IOException("Для Menu Autopilot нужен завершённый IL2CPP-анализ и исходный APK");
        File deep=app.file("analysis-deep");if(!deep.exists()&&!deep.mkdirs())throw new IOException("Не удалось создать каталог Deep Resolver");
        Files.deleteIfExists(app.file("menu-validation.json").toPath());
        PyObject result=engine().callAttr("menu_autopilot_prepare",meta.getPath(),lib.getPath(),catalog.getPath(),deep.getPath(),apk.getPath(),app.file("menu-spec.json").getPath(),app.file("menu-project").getPath(),app.file("menu-autopilot.json").getPath(),app.file("menu-preflight.json").getPath(),rod.isDirectory()?rod.getPath():null,"ModKit Autopilot Menu",24,12,new Progress());
        JSONObject obj=new JSONObject(result.toString()),batch=obj.optJSONObject("batch"),pre=obj.optJSONObject("preflight"),confirm=obj.optJSONObject("confirm");
        int processed=batch==null?0:batch.optInt("processedCount",0),eligible=batch==null?0:batch.optInt("eligibleCount",0);JSONArray promoted=confirm==null?null:confirm.optJSONArray("promoted");
        app.progress("Menu Autopilot: Deep проверено "+processed+", controls доказано "+eligible+", ELF bindings "+(promoted==null?0:promoted.length())+", payload "+(pre!=null&&pre.optBoolean("readyForPayload")?"READY":"REVIEW")+".");
    }

    private boolean hasIl2cppMenuAnalysis(){return app.file("metadata.bin").isFile()&&app.file("library.so").isFile()&&(app.file("analysis.methods.jsonl").isFile()||app.file("analysis.json").isFile());}
    private void menuSmartPrepare() throws Exception {
        if(!hasIl2cppMenuAnalysis()){
            if(app.file("re-analysis.json").isFile()){menuSeed();app.progress("Application RE: сохранены только review/evidence controls. DEX-строки без доказанной patch-привязки не превращаются в исполнимое меню.");return;}
            throw new IOException("Сначала выполните RE-анализ приложения");
        }
        if(app.file("analysis.methods.jsonl").isFile()&&app.file("game.apk").isFile()){menuAutopilotPrepare();return;}
        if(app.file("analysis-deep").isDirectory()&&app.file("game.apk").isFile()){menuAutoPrepareDeep();return;}
        if(app.file("re-analysis.json").isFile()&&app.file("game.apk").isFile()){menuAutoPrepare();return;}
        menuSeed();
    }
    private void menuSmartBuildApk(Uri uri) throws Exception {
        if(!hasIl2cppMenuAnalysis())throw new IOException("Для этого target нет подтверждённого IL2CPP/native menu path. DEX developer/debug surface остаётся evidence-only до подтверждения owning method и безопасной DEX patch-семантики.");
        menuSmartPrepare();JSONObject preflight=menuPreflightReport();
        if(!preflight.optBoolean("readyForAutoBuild"))throw new IOException("Автосборка остановлена fail-closed: есть REVIEW/BLOCK или нет подтверждённых исполнимых bindings.");
        menuBuildApk(uri);
    }
    private void menuAutopilotBuildApk(Uri uri) throws Exception {
        app.progress("Menu Autopilot: каталог → Deep Resolver → Menu…");menuAutopilotPrepare();JSONObject preflight=menuPreflightReport();
        if(!preflight.optBoolean("readyForAutoBuild"))throw new IOException("Menu Autopilot остановлен fail-closed: часть сильных controls требует review или безопасные bindings не подтверждены; откройте Menu Builder.");
        app.progress("Menu Autopilot: preflight READY, сборка подписанного тестового APK…");menuBuildApk(uri);
    }

    private void menuProject() throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");engine().callAttr("menu_project_from_spec",app.file("menu-spec.json").getPath(),app.file("menu-project").getPath(),new Progress());invalidateMenuChecks();app.progress("Проект меню обновлён.");}
    private void menuValidate() throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");File patchApk=targetPatchApk();PyObject result=engine().callAttr("menu_validate_spec",app.file("menu-spec.json").getPath(),patchApk.getPath(),app.file("menu-validation.json").getPath(),new Progress());JSONObject obj=new JSONObject(result.toString());app.progress(obj.optBoolean("blocked")?"Привязки меню: есть BLOCK-ошибки, генерация требует исправления RVA/.so.":"Привязки меню проверены по owning APK target.");}
    private void menuAutoConfirm() throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");File patchApk=targetPatchApk();PyObject result=engine().callAttr("menu_auto_confirm",app.file("menu-spec.json").getPath(),patchApk.getPath(),app.file("menu-project").getPath(),app.file("menu-auto-confirm.json").getPath(),new Progress());JSONObject obj=new JSONObject(result.toString());invalidateMenuChecks();JSONArray promoted=obj.optJSONArray("promoted"),rejected=obj.optJSONArray("rejected");app.progress("Автоподтверждение: promoted "+(promoted==null?0:promoted.length())+", rejected "+(rejected==null?0:rejected.length())+". Проверьте карточки перед payload.");}
    private JSONObject menuPreflightReport() throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");File patchApk=targetPatchApk();PyObject result=engine().callAttr("menu_review_preflight",app.file("menu-spec.json").getPath(),patchApk.getPath(),app.file("menu-preflight.json").getPath(),new Progress());return new JSONObject(result.toString());}
    private void menuPreflight() throws Exception {JSONObject obj=menuPreflightReport();JSONObject c=obj.optJSONObject("counts");int bound=c==null?0:c.optInt("bound"),review=c==null?0:c.optInt("evidenceOnly"),unresolved=c==null?0:c.optInt("unresolved");app.progress(obj.optBoolean("readyForPayload")?"Menu Builder готов к payload: bindings "+bound+", review "+review+", unresolved "+unresolved+".":"Menu Builder ещё не готов к payload: bindings "+bound+", review "+review+", unresolved "+unresolved+".");}
    private void menuExport(Uri uri) throws Exception {File zip=app.file("menu-project.zip");boolean saved=false;try{engine().callAttr("menu_export_project",app.file("menu-project").getPath(),app.file("menu-spec.json").getPath(),zip.getPath(),new Progress());try(InputStream in=new FileInputStream(zip);OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Не удалось открыть ZIP для записи");byte[] b=new byte[1024*1024];int n;while((n=in.read(b))!=-1){check();out.write(b,0,n);}out.flush();}saved=true;app.progress("Проект Menu Builder сохранён.");}finally{zip.delete();if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}}
    private void menuRuntimeImport(Uri uri,String display) throws Exception {copyUri(uri,app.file("menu-runtime.so"),"Импорт compiled menu runtime");getSharedPreferences("state",0).edit().putString("menu-runtime.so",display).apply();app.progress("Runtime Menu Builder импортирован: "+display);}
    private void menuPayloadExport(Uri uri) throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");File patchApk=targetPatchApk();JSONObject preflight=menuPreflightReport();if(!preflight.optBoolean("readyForPayload"))throw new IOException("Menu Builder не готов: подтвердите хотя бы одну привязку и исправьте BLOCK-ошибки");File runtime=app.file("menu-runtime.so");if(!runtime.isFile())runtime=new File(getApplicationInfo().nativeLibraryDir,"libmk.so");if(!runtime.isFile())throw new IOException("В этой сборке ModKit нет встроенного libmk.so; пересоберите приложение с NDK или выберите runtime вручную");File zip=app.file("menu-payload.zip");boolean saved=false;try{engine().callAttr("menu_payload_from_runtime",app.file("menu-spec.json").getPath(),patchApk.getPath(),runtime.getPath(),zip.getPath(),app.file("menu-payload-report.json").getPath(),new Progress());copyFileToUri(zip,uri,"Сохранение Menu Patch Pack");saved=true;app.progress("DEX-free Menu Patch Pack готов. Можно открыть его в Patch Pack.");}finally{zip.delete();if(!saved)try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}}
    private File menuRuntimeFile() throws IOException {File runtime=app.file("menu-runtime.so");if(!runtime.isFile())runtime=new File(getApplicationInfo().nativeLibraryDir,"libmk.so");if(!runtime.isFile())throw new IOException("В этой сборке ModKit нет встроенного libmk.so; пересоберите приложение с NDK или выберите runtime вручную");return runtime;}
    private void menuBuildApk(Uri uri) throws Exception {if(!app.file("menu-spec.json").isFile())throw new IOException("Menu spec отсутствует");verifyInstalledTarget();File patchApk=targetPatchApk();JSONObject preflight=menuPreflightReport();if(!preflight.optBoolean("readyForPayload"))throw new IOException("Menu Builder не готов: подтвердите bindings/RVA и устраните BLOCK-ошибки");File payload=app.file("menu-payload-build.zip"),unsigned=app.file("menu-unsigned.apk");try{File runtime=menuRuntimeFile();app.progress("Menu Builder: создание DEX-free payload для owning APK…");engine().callAttr("menu_payload_from_runtime",app.file("menu-spec.json").getPath(),patchApk.getPath(),runtime.getPath(),payload.getPath(),app.file("menu-payload-report.json").getPath(),new Progress());app.progress("Menu Builder: применение payload к owning APK…");engine().callAttr("patchpack_apply_unsigned",patchApk.getPath(),payload.getPath(),unsigned.getPath(),app.file("menu-apk-report.json").getPath(),new Progress());exportSignedTarget(uri,unsigned,"APK с Menu Builder собран и подписан.","Menu Builder применён к owning split; весь APK-set переподписан одним ключом.");}finally{payload.delete();unsigned.delete();}}
    private void menuAutoBuildApk(Uri uri) throws Exception {if(!app.file("re-analysis.json").isFile())throw new IOException("Сначала выполните RE-анализ");if(!app.file("game.apk").isFile())throw new IOException("Сначала выберите исходный APK");app.progress("Авто APK: RE → подтверждение bindings…");menuAutoPrepare();JSONObject preflight=menuPreflightReport();if(!preflight.optBoolean("readyForAutoBuild"))throw new IOException("Автосборка остановлена: остались сильные controls для review, нет безопасно подтверждённых bindings или есть BLOCK; откройте Menu Builder. Ручная сборка подтверждённых bindings остаётся доступна отдельно.");app.progress("Авто APK: все сильные candidates разобраны, bindings подтверждены, сборка payload/APK…");menuBuildApk(uri);}
    private void menuAutoBuildApkDeep(Uri uri) throws Exception {if(!app.file("analysis-deep").isDirectory())throw new IOException("Сначала выполните Deep Resolver для нужных методов");if(!app.file("game.apk").isFile())throw new IOException("Сначала выберите исходный APK");app.progress("Авто APK: Deep Resolver → подтверждение bindings…");menuAutoPrepareDeep();JSONObject preflight=menuPreflightReport();if(!preflight.optBoolean("readyForAutoBuild"))throw new IOException("Автосборка остановлена fail-closed: остались Deep controls для review, нет безопасно подтверждённых bindings или есть BLOCK; откройте Menu Builder.");app.progress("Авто APK: Deep static gates + APK ELF preflight пройдены, сборка payload/APK…");menuBuildApk(uri);}

    @Override public IBinder onBind(Intent intent) { return null; }
}
