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

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** One clean export surface for the full technical evidence package. */
public class ReportCenterActivity extends AppCompatActivity {
    private static final int SAVE_BUNDLE = 801;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private TextView status;
    private ProgressBar progress;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(Color.rgb(31,41,55));t.setPadding(0,dp(6),0,dp(6));return t;}
    @Override public void onCreate(Bundle state){
        super.onCreate(state);ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));scroll.addView(root);setContentView(scroll);
        TextView title=text("Отчёты и Evidence",28);title.setTypeface(null,android.graphics.Typeface.BOLD);root.addView(title);
        root.addView(text("Полный пакет содержит все доступные JSON/JSONL/индексы/карты/логи/дампы текста, runtime snapshot, engine catalog и SHA-256. Исходные APK/.so/metadata не дублируются.",14));
        com.google.android.material.button.MaterialButton b=new com.google.android.material.button.MaterialButton(this);b.setText("Экспортировать полный Evidence Bundle ZIP");b.setAllCaps(false);b.setOnClickListener(v->pick());root.addView(b);
        progress=new ProgressBar(this);progress.setVisibility(View.GONE);root.addView(progress);
        status=text("Готово к экспорту.",14);status.setTextIsSelectable(true);root.addView(status);
    }
    private void pick(){startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"ModKit-Evidence-Bundle.zip"),SAVE_BUNDLE);}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request!=SAVE_BUNDLE||result!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();progress.setVisibility(View.VISIBLE);status.setText("Формируем пакет доказательств…");worker.execute(()->{try{JSONObject manifest=EvidenceBundleExporter.export(this,uri);main.post(()->{progress.setVisibility(View.GONE);status.setText("Готово · файлов: "+manifest.optInt("evidenceFileCount")+" · данных: "+manifest.optLong("evidenceBytes")+" байт.\nДобавлены engine-catalog, bundle-manifest и hashes.sha256.");});}catch(Exception e){main.post(()->{progress.setVisibility(View.GONE);status.setText("Ошибка экспорта: "+e.getMessage());});}});}
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
