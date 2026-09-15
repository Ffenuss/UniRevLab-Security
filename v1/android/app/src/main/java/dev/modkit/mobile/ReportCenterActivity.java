package dev.modkit.mobile;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** One report surface: build connected report, then export the complete evidence bundle. */
public class ReportCenterActivity extends AppCompatActivity {
    private static final int SAVE_BUNDLE=801;private final ExecutorService worker=Executors.newSingleThreadExecutor();private final Handler main=new Handler(Looper.getMainLooper());private TextView status;private ProgressBar progress;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(fg());t.setPadding(0,dp(6),0,dp(6));return t;}
    @Override public void onCreate(Bundle state){super.onCreate(state);ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);TextView title=text("Отчёт полного анализа",28);title.setTypeface(null,android.graphics.Typeface.BOLD);root.addView(title);TextView note=text("Перед экспортом ModKit строит connected-report 1.2: связывает findings с method id / class / method / RVA, добавляет deep coverage, read-only runtime RVA→VA corroboration, независимый IL2CPP metadata+ELF structural cross-check и metadata identity для методов без RVA. Identity учитывает Class::Method и уникальный method token, но не придумывает native-адрес. Конфликт token↔class/name явно блокируется и никогда не повышает actionable/buildable.",14);note.setTextColor(muted());root.addView(note);com.google.android.material.button.MaterialButton b=new com.google.android.material.button.MaterialButton(this);b.setText("Экспортировать связанный отчёт ZIP");b.setAllCaps(false);b.setOnClickListener(v->pick());root.addView(b);progress=new ProgressBar(this);progress.setVisibility(View.GONE);root.addView(progress);status=text("Готово к экспорту.",14);status.setTextIsSelectable(true);root.addView(status);}
    private void pick(){startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"ModKit-Connected-Report.zip"),SAVE_BUNDLE);}
    private JSONObject buildConnected() throws Exception{if(!Python.isStarted())Python.start(new AndroidPlatform(this));return new JSONObject(Python.getInstance().getModule("modkit.mobile.connected_report_v12").callAttr("build_connected_report",getFilesDir().getPath(),new java.io.File(getFilesDir(),"connected-report.json").getPath(),new java.io.File(getFilesDir(),"connected-report.md").getPath()).toString());}
    private int availableDeep(JSONObject connected){JSONObject summary=connected.optJSONObject("summary");if(summary!=null)return summary.optInt("deepEnginesAvailable",0);int n=0;JSONArray rows=connected.optJSONArray("engineCoverage");if(rows!=null)for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null&&row.optBoolean("available"))n++;}return n;}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request!=SAVE_BUNDLE||result!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();progress.setVisibility(View.VISIBLE);status.setText("Связываем методы, runtime/IL2CPP/no-RVA metadata+token evidence, deep evidence и формируем Evidence Bundle…");worker.execute(()->{try{JSONObject connected=buildConnected();JSONObject manifest=EvidenceBundleExporter.export(this,uri);main.post(()->{progress.setVisibility(View.GONE);status.setText("Готово · findings: "+connected.optInt("findingCount")+" · exact links: "+connected.optInt("exactLinked")+" · runtime VA: "+connected.optInt("runtimeObservedFindings")+" · IL2CPP structural: "+connected.optInt("il2cppStructuralFindings")+" · metadata identity/no-RVA: "+connected.optInt("metadataIdentityConfirmedFindings")+" · exact Class::Method/no-RVA: "+connected.optInt("metadataQualifiedIdentityFindings")+" · token/no-RVA: "+connected.optInt("metadataTokenIdentityFindings")+" · token conflicts: "+connected.optInt("metadataTokenConflictFindings")+" · deep backend'ов: "+availableDeep(connected)+" · файлов: "+manifest.optInt("evidenceFileCount")+" · данных: "+manifest.optLong("evidenceBytes")+" байт.");});}catch(Exception e){main.post(()->{progress.setVisibility(View.GONE);status.setText("Ошибка экспорта: "+e.getMessage());});}});}
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
