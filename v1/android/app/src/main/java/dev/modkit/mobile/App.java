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
    @Override public void onCreate() {
        super.onCreate();
        if (getSharedPreferences("state",0).getBoolean("running",false)) {
            status = "Предыдущая операция прервана системой. Можно запустить её заново.";
            stage = "STOPPED";
            markInterruptedPipeline();
            getSharedPreferences("state",0).edit().putBoolean("running",false).apply();
        }
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
