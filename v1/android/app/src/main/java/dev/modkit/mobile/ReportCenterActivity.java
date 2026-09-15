package dev.modkit.mobile;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import com.google.android.material.button.MaterialButton;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InterruptedIOException;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** One report surface: build connected report, then export the complete evidence bundle. */
public class ReportCenterActivity extends AppCompatActivity {
    private static final int SAVE_BUNDLE=801;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private final AtomicBoolean exportCancelled=new AtomicBoolean(false);
    private volatile Future<?> activeExport;
    private TextView status;private ProgressBar progress;private MaterialButton exportButton,cancelExport;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(fg());t.setPadding(0,dp(6),0,dp(6));return t;}
    @Override public void onCreate(Bundle state){super.onCreate(state);ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);TextView title=text("Отчёт полного анализа",28);title.setTypeface(null,android.graphics.Typeface.BOLD);root.addView(title);TextView note=text("Перед экспортом ModKit строит connected-report 1.2: связывает findings с method id / class / method / RVA, добавляет deep coverage, read-only runtime RVA→VA corroboration, независимый IL2CPP metadata+ELF structural cross-check и metadata identity для методов без RVA. Identity учитывает Class::Method и уникальный method token, но не придумывает native-адрес. Конфликт token↔class/name явно блокируется и никогда не повышает actionable/buildable. Большие per-method JSONL читаются потоково и не материализуются целиком в RAM.",14);note.setTextColor(muted());root.addView(note);exportButton=new MaterialButton(this);exportButton.setText("Экспортировать связанный отчёт ZIP");exportButton.setAllCaps(false);exportButton.setOnClickListener(v->pick());root.addView(exportButton);cancelExport=new MaterialButton(this);cancelExport.setText("Отменить экспорт");cancelExport.setAllCaps(false);cancelExport.setEnabled(false);cancelExport.setOnClickListener(v->cancelExport());root.addView(cancelExport);progress=new ProgressBar(this);progress.setVisibility(View.GONE);root.addView(progress);status=text("Готово к экспорту.",14);status.setTextIsSelectable(true);root.addView(status);}
    private boolean exportRunning(){Future<?> job=activeExport;return job!=null&&!job.isDone();}
    private void pick(){if(exportRunning())return;startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"ModKit-Connected-Report.zip"),SAVE_BUNDLE);}
    private void cancelExport(){exportCancelled.set(true);Future<?> job=activeExport;if(job!=null)job.cancel(true);cancelExport.setEnabled(false);status.setText("Отмена экспорта запрошена…");}
    public final class ExportProgress {public boolean isCancelled(){return exportCancelled.get()||Thread.currentThread().isInterrupted();}}
    private void checkExportCancelled()throws InterruptedIOException{if(exportCancelled.get()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("export cancelled");}
    private JSONObject buildConnected() throws Exception{checkExportCancelled();if(!Python.isStarted())Python.start(new AndroidPlatform(this));checkExportCancelled();return new JSONObject(Python.getInstance().getModule("modkit.mobile.connected_report_streaming").callAttr("build_connected_report",getFilesDir().getPath(),new java.io.File(getFilesDir(),"connected-report.json").getPath(),new java.io.File(getFilesDir(),"connected-report.md").getPath(),new ExportProgress()).toString());}
    private int availableDeep(JSONObject connected){JSONObject summary=connected.optJSONObject("summary");if(summary!=null)return summary.optInt("deepEnginesAvailable",0);int n=0;JSONArray rows=connected.optJSONArray("engineCoverage");if(rows!=null)for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null&&row.optBoolean("available"))n++;}return n;}
    private boolean cancellation(Throwable e){if(exportCancelled.get()||Thread.currentThread().isInterrupted())return true;String message=String.valueOf(e==null?"":e.getMessage()).toLowerCase(Locale.ROOT);return message.contains("cancel")||message.contains("отмен");}
    private void finishExportUi(){progress.setVisibility(View.GONE);cancelExport.setEnabled(false);exportButton.setEnabled(true);}
    private void deleteFailedDestination(Uri uri){try{DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request!=SAVE_BUNDLE||result!=RESULT_OK||data==null||data.getData()==null)return;if(exportRunning())return;Uri uri=data.getData();exportCancelled.set(false);progress.setVisibility(View.VISIBLE);cancelExport.setEnabled(true);exportButton.setEnabled(false);status.setText("Связываем методы, runtime/IL2CPP/no-RVA metadata+token evidence, deep evidence и формируем Evidence Bundle…");activeExport=worker.submit(()->{try{String epoch=EvidenceBundleExporter.exportEpoch(this);JSONObject connected=buildConnected();checkExportCancelled();if(!epoch.equals(EvidenceBundleExporter.exportEpoch(this)))throw new java.io.IOException("Pipeline изменился во время построения connected report; экспорт отменён для защиты epoch consistency.");JSONObject manifest=EvidenceBundleExporter.export(this,uri);main.post(()->{finishExportUi();status.setText("Готово · pipeline: "+manifest.optString("pipelineStatus","UNKNOWN")+" · findings: "+connected.optInt("findingCount")+" · exact links: "+connected.optInt("exactLinked")+" · runtime VA: "+connected.optInt("runtimeObservedFindings")+" · IL2CPP structural: "+connected.optInt("il2cppStructuralFindings")+" · metadata identity/no-RVA: "+connected.optInt("metadataIdentityConfirmedFindings")+" · exact Class::Method/no-RVA: "+connected.optInt("metadataQualifiedIdentityFindings")+" · token/no-RVA: "+connected.optInt("metadataTokenIdentityFindings")+" · token conflicts: "+connected.optInt("metadataTokenConflictFindings")+" · deep backend'ов: "+availableDeep(connected)+" · файлов: "+manifest.optInt("evidenceFileCount")+" · данных: "+manifest.optLong("evidenceBytes")+" байт.");});}catch(Exception e){deleteFailedDestination(uri);boolean cancelled=cancellation(e);main.post(()->{finishExportUi();status.setText(cancelled?"Экспорт отменён.":"Ошибка экспорта: "+e.getMessage());});}});}
    @Override protected void onDestroy(){exportCancelled.set(true);Future<?> job=activeExport;if(job!=null)job.cancel(true);worker.shutdownNow();main.removeCallbacksAndMessages(null);super.onDestroy();}
}