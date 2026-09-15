package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.graphics.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import org.json.*;

public class ReWorkspaceActivity extends Activity {
    private App app;
    private LinearLayout root, findings;
    private TextView status, summary;
    private Button run, menu;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private long revision = -1;
    private final Runnable poll = new Runnable(){ public void run(){ refresh(); handler.postDelayed(this,400); }};
    private int dp(int n){ return (int)(n*getResources().getDisplayMetrics().density); }
    private TextView text(String s,int size){ TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(getColor(R.color.mk_on_surface));t.setPadding(0,dp(6),0,dp(6));t.setTextIsSelectable(true);return t; }
    private Button button(String s,View.OnClickListener l){ Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setOnClickListener(l);root.addView(b);return b; }
    @Override public void onCreate(Bundle state){
        super.onCreate(state); app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(20),dp(18),dp(24));root.setBackgroundColor(getColor(R.color.mk_background));scroll.addView(root);setContentView(scroll);
        TextView title=text("RE Workspace",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text("DEX + global-metadata + Rodroid dump + все ELF/.so + Unity/Addressables. Полный отчёт хранится отдельно; экран читает компактный UI-индекс, чтобы большие IL2CPP-проекты не переполняли Java heap.",14));
        run=button("Полный RE-анализ выбранного APK",v->startWork(new Intent().putExtra("op","re_analyze")));
        menu=button("Создать Menu Builder из подтверждённых находок",v->{
            if(!app.file("re-analysis.json").isFile()){toast("Сначала выполните RE-анализ");return;}
            startWork(new Intent().putExtra("op","menu_seed"));
        });
        button("Открыть Menu Builder",v->startActivity(new Intent(this,MenuBuilderActivity.class)));
        status=text("",14);root.addView(status);summary=text("",14);root.addView(summary);
        findings=new LinearLayout(this);findings.setOrientation(LinearLayout.VERTICAL);root.addView(findings);
    }
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    private void startWork(Intent i){
        if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}
        if(!app.file("game.apk").isFile() && "re_analyze".equals(i.getStringExtra("op"))){toast("Сначала выберите исходный APK на главном экране");return;}
        app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);
        try{startForegroundService(i);}catch(Exception e){app.busy.set(false);app.revision++;app.progress("RE Workspace: не удалось запустить операцию: "+e.getMessage());toast("Не удалось запустить RE-операцию");}
    }
    private JSONObject readUi(){try{return new JSONObject(Io.readUtf8(app.file("re-analysis.ui.json")));}catch(Exception e){return null;}}
    private String confidence(JSONObject finding){if(finding==null||!finding.has("confidence")||finding.isNull("confidence"))return "—";return String.format(java.util.Locale.ROOT,"%.2f",finding.optDouble("confidence"));}
    private void addLinesCard(String title,JSONArray lines){
        if(lines==null||lines.length()==0)return;
        StringBuilder b=new StringBuilder();
        for(int i=0;i<lines.length();i++){String line=lines.optString(i,"");if(!line.isEmpty())b.append(line).append("\n");}
        if(b.length()==0)return;
        LinearLayout card=new LinearLayout(this);card.setOrientation(LinearLayout.VERTICAL);card.setPadding(dp(10),dp(8),dp(10),dp(12));
        TextView h=text(title,17);h.setTypeface(null,Typeface.BOLD);card.addView(h);card.addView(text(b.toString().trim(),12));findings.addView(card);
    }
    private void refresh(){
        if(revision==app.revision)return;revision=app.revision;status.setText(app.status);
        run.setEnabled(!app.busy.get()&&app.file("game.apk").isFile());
        JSONObject report=readUi();
        boolean complete=report!=null&&"complete".equals(report.optString("reportState"));
        menu.setEnabled(!app.busy.get()&&complete&&app.file("re-analysis.json").isFile());
        findings.removeAllViews();
        if(report==null){
            if(app.file("re-analysis.json").isFile()){
                summary.setText("Обнаружен полный RE-отчёт без компактного UI-индекса. Это может быть результат прерванного или устаревшего сохранения. Чтобы не загружать большой JSON целиком в Java heap, экран его не открывает. Повторите полный RE-анализ в текущей версии ModKit.");
            }else{
                summary.setText("Отчёта пока нет. RE-анализ использует выбранный APK и, если доступны, текущие metadata/libil2cpp/Rodroid dump.");
            }
            return;
        }
        String state=report.optString("reportState","unknown");
        String summaryText=report.optString("summaryText","");
        long bytes=report.optLong("reportSizeBytes",0);
        if("saving".equals(state))summaryText="RE-результат уже рассчитан; полный отчёт ещё сохраняется потоково. Не закрывайте приложение до статуса «готово».\n"+summaryText;
        else if("complete".equals(state)&&bytes>0)summaryText+="\nFull report: "+(bytes/1024/1024)+" МБ · UI index: bounded";
        summary.setText(summaryText);
        addLinesCard("IL2CPP control shortlist",report.optJSONArray("controlCandidateLines"));
        addLinesCard("Static relationship graph",report.optJSONArray("graphLines"));
        addLinesCard("Native / JNI / IL2CPP relationships",report.optJSONArray("relationshipLines"));
        JSONArray arr=report.optJSONArray("findings");
        if(arr==null)return;
        for(int i=0;i<arr.length();i++){
            JSONObject f=arr.optJSONObject(i);if(f==null)continue;
            LinearLayout card=new LinearLayout(this);card.setOrientation(LinearLayout.VERTICAL);card.setPadding(dp(10),dp(8),dp(10),dp(12));
            TextView h=text(f.optString("title"),17);h.setTypeface(null,Typeface.BOLD);card.addView(h);
            card.addView(text(f.optString("status").toUpperCase()+" · confidence "+confidence(f)+"\n"+f.optString("rationale"),12));
            JSONArray ev=f.optJSONArray("evidenceLines");if(ev!=null&&ev.length()>0){StringBuilder b=new StringBuilder();for(int j=0;j<ev.length();j++){String line=ev.optString(j,"");if(!line.isEmpty())b.append(line).append("\n");}if(b.length()>0)card.addView(text(b.toString().trim(),12));}
            findings.addView(card);
        }
        int total=report.optInt("findingCount",arr.length()),visible=report.optInt("visibleFindingCount",arr.length());
        if(total>visible)findings.addView(text("Показано "+visible+" из "+total+" находок. Полный набор сохранён в re-analysis.json и не загружается целиком в UI.",12));
    }
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}
}
