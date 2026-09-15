package dev.modkit.mobile;

import android.app.Application;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class App extends Application {
    public final AtomicBoolean busy = new AtomicBoolean(false), cancelled = new AtomicBoolean(false);
    public volatile String status = "Выберите установленное приложение/игру или локальный APK.";
    public volatile String stage = "IDLE";
    public volatile int stageProgress = -1;
    public volatile JSONObject result;
    public volatile long revision = 0;
    private static final Pattern PERCENT=Pattern.compile("(?:^|\\D)(100|[0-9]{1,2})%");
    public File file(String name) { return new File(getFilesDir(), name); }
    private String visibleStatus(String message){return (message==null?"":message).replace("Simple Mode","Автоанализ");}
    private String stageFor(String message) {
        String s=message==null?"":message.toLowerCase(Locale.ROOT);
        if(s.contains("ошибка")||s.contains("отмен"))return "STOPPED";
        if(s.contains("сохран")||s.contains("сбор")||s.contains("подпис")||s.contains("apk-set: подпись"))return "OUTPUT";
        if(s.contains("menu")||s.contains("payload"))return "MENU";
        if(s.contains("probe"))return "PROBE";
        if(s.contains("re:")||s.contains("discovery")||s.contains("relationship graph")||s.contains("trust"))return "DISCOVERY";
        if(s.contains("rodroid")||s.contains("il2cpp")||s.contains("metadata")||s.contains("gameplay"))return "ANALYSIS";
        if(s.contains("installed scan")||s.contains("инвентар")||s.contains("поиск"))return "INVENTORY";
        if(s.contains("копирован")||s.contains("импорт")||s.contains("подготов"))return "INPUT";
        if(s.startsWith("готово")||s.contains(" готов"))return "DONE";
        return stage==null?"IDLE":stage;
    }
    public void progress(String message) {
        String visible=visibleStatus(message);
        status = visible;
        stage = stageFor(visible);
        stageProgress = -1;
        Matcher m=PERCENT.matcher(visible);
        if(m.find())try{stageProgress=Integer.parseInt(m.group(1));}catch(Exception ignored){}
        revision++;
    }
    private void markInterruptedPipeline(){
        File part=file("automatic-evidence.json.part");
        if(part.exists())part.delete();
        File manifest=file("automatic-evidence.json");
        if(!manifest.isFile())return;
        try{
            JSONObject value;
            try{value=new JSONObject(new String(Files.readAllBytes(manifest.toPath()),StandardCharsets.UTF_8));}
            catch(Exception malformed){value=new JSONObject().put("schema","modkit-automatic-evidence-1.1").put("status","RUNNING");}
            if(!"RUNNING".equals(value.optString("status")))return;
            value.put("status","FAILED").put("phase","FINISHED").put("complete",false).put("cancelled",false).put("interruptedBySystem",true).put("error","SYSTEM_INTERRUPTED").put("finishedAtMs",System.currentTimeMillis());
            try{Files.write(part.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(part.toPath(),manifest.toPath(),StandardCopyOption.REPLACE_EXISTING);}
            catch(Exception writeError){Files.deleteIfExists(part.toPath());throw writeError;}
        }catch(Exception ignored){}
    }
    private void deleteInterruptedTargetTree(File value){
        if(value==null||!value.exists())return;
        if(value.isDirectory()){
            File[] children=value.listFiles();
            if(children!=null)for(File child:children)deleteInterruptedTargetTree(child);
        }
        try{Files.deleteIfExists(value.toPath());}catch(Exception ignored){}
    }
    private void cleanupInterruptedTargetPreparation(){
        result=null;
        String[] names={
                "full-reconstruction.json","full-reconstruction.json.part","modkit-decompiled.zip","apktool-analysis.json","apktool-analysis.json.part","apktool-workspace",
                "artifact-families.json","embedded-analysis.json","automatic-evidence.json","automatic-evidence.json.part","automod-plan.json","automod-plan.json.part",
                "runtime-session.json","runtime-session.json.part","runtime-correlation.json","runtime-correlation.json.part","runtime-correlation.json.build",
                "il2cpp-crosscheck.json","il2cpp-crosscheck.json.part","il2cpp-crosscheck.methods.jsonl","il2cpp-crosscheck.methods.jsonl.part",
                "il2cpp-metadata-identity.json","il2cpp-metadata-identity.json.part","il2cpp-metadata-identity.methods.jsonl","il2cpp-metadata-identity.methods.jsonl.part",
                "il2cpp-no-rva-native.json","il2cpp-no-rva-native.json.part","il2cpp-no-rva-native.methods.jsonl","il2cpp-no-rva-native.methods.jsonl.part","il2cpp-no-rva-native.failures.jsonl","il2cpp-no-rva-native.failures.jsonl.part",
                "lua-deep.json","hermes-deep","hermes-deep.json","native-deep.json","native-deep-cache","cocos-deep.json","flutter-deep.json","deep-gameplay.json",
                "installed-target.json","installed-target.json.part","installed-apk-set.zip","installed-apk-set.zip.tmp","installed-scan.json","installed-apks",
                "metadata.bin","library.so","game.apk","game-native-split.apk","game.apk.part",
                "analysis.json","analysis.summary.json","analysis.summary.json.part","analysis.ui.jsonl",
                "analysis.methods.jsonl","analysis.methods.jsonl.idx","analysis.methods.jsonl.rva.idx","analysis.methods.jsonl.pages.idx","analysis.methods.meta.json",
                "analysis.candidates.jsonl","analysis.discoveries.jsonl","analysis.fields.jsonl",
                "analysis.evidence-graph.jsonl","analysis.evidence-graph.jsonl.idx","analysis.evidence-graph.meta.json",
                "analysis.resolver-index.json","analysis.autopilot-index.jsonl","analysis.gameplay-coverage.json",
                "analysis-deep","re-analysis.json","re-analysis.ui.json","re-analysis.menu.json","security-surfaces.json",
                "simple-catalog.json","simple-catalog.json.part","simple-cache.json","simple-progress.json","simple-progress.json.part","rodroid",
                "menu-spec.json","menu-result.json","menu-preflight.json","menu-validation.json","menu-auto-prepare.json","menu-auto-prepare-deep.json","menu-auto-confirm.json","menu-autopilot.json","menu-probe-prepare.json","menu-spec.simple-source.json","menu-native-recovery.json","menu-native-recovery.json.tmp","menu-project",
                "menu-payload-report.json","menu-apk-report.json","menu-payload-build.zip","menu-unsigned.apk",
                "patchpack-report.json","patchpack-unsigned.apk",
                "workspace-patch.zip","workspace-patch.zip.tmp","workspace-source.json","workspace-report.json","workspace-edit.bin","workspace-unsigned.apk",
                "target-signed.apk","target-signed.apks","target-signed-set",
                "connected-report.json","connected-report.json.part","connected-report.md","connected-report.md.part","evidence-bundle.zip"
        };
        for(String name:names)deleteInterruptedTargetTree(file(name));
        getSharedPreferences("state",0).edit().remove("selections").remove("active.project").remove("metadata.bin").remove("library.so").remove("installed.package").remove("game.apk").apply();
    }
    @Override public void onCreate() {
        super.onCreate();
        boolean wasRunning=getSharedPreferences("state",0).getBoolean("running",false);
        boolean targetPreparing=getSharedPreferences("state",0).getBoolean("target.preparing",false);
        if(targetPreparing){
            cleanupInterruptedTargetPreparation();
            status="Подготовка target была прервана системой. Частичный APK/APK-set очищен; выберите target заново.";
            stage="STOPPED";
        }else if(wasRunning){
            status = "Предыдущая операция прервана системой. Можно запустить её заново.";
            stage = "STOPPED";
        }
        if(wasRunning){markInterruptedPipeline();}
        if(wasRunning||targetPreparing){getSharedPreferences("state",0).edit().putBoolean("running",false).putBoolean("target.preparing",false).apply();}
        new Thread(() -> {
            synchronized (this) {
                if (busy.get()) return;
                try {
                    File f = file("analysis.summary.json");
                    if (f.exists()) result = new JSONObject(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
                } catch (Exception ignored) { }
                revision++;
            }
        }, "restore").start();
    }
}
