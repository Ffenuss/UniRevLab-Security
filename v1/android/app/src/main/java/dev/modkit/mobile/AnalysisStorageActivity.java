package dev.modkit.mobile;

import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.text.DecimalFormat;

/** Human-readable analysis artifact store with editor/workspace entry points. */
public class AnalysisStorageActivity extends AppCompatActivity {
    private App app;private LinearLayout root,files;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}private MaterialButton button(String label,View.OnClickListener l){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(l);root.addView(b);return b;}
    @Override public void onCreate(Bundle s){super.onCreate(s);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);TextView title=text("Хранилище анализа",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView note=text("Здесь лежат результаты текущего target. Оригинальный APK не изменяется; редакторы работают с рабочими копиями и собирают новый подписанный APK/APK-set. Deep-отчёты Lua/Hermes/native/Cocos/Flutter показываются отдельно, чтобы сразу было понятно, каким backend'ом получено evidence.",13);note.setTextColor(muted());root.addView(note);button("Deep evidence · Lua / Hermes / ARM64 / Cocos / Flutter",v->startActivity(new Intent(this,DeepEvidenceActivity.class)));button("Decompiler · открыть Java / Smali / Resources",v->startActivity(new Intent(this,DecompilerActivity.class)));button("Редактор файлов · изменить entry и собрать",v->startActivity(new Intent(this,FileWorkspaceActivity.class)));button("Методы / Evidence / Deep Resolve",v->startActivity(new Intent(this,ReWorkspaceActivity.class)));button("Native ELF / ARM64",v->startActivity(new Intent(this,NativeWorkspaceActivity.class)));button("Menu Builder / Autopilot",v->startActivity(new Intent(this,MenuBuilderActivity.class)));button("Отчёт и Evidence Bundle",v->startActivity(new Intent(this,ReportCenterActivity.class)));TextView h=text("Файлы текущего анализа",18);h.setTypeface(null,Typeface.BOLD);root.addView(h);files=new LinearLayout(this);files.setOrientation(LinearLayout.VERTICAL);root.addView(files);render();}
    @Override protected void onResume(){super.onResume();if(files!=null)render();}
    private static long size(File f){if(f==null||!f.exists())return 0;if(f.isFile())return f.length();long n=0;File[] c=f.listFiles();if(c!=null)for(File x:c)n+=size(x);return n;}
    private String human(long n){if(n<1024)return n+" B";double v=n;String[] u={"B","KB","MB","GB"};int i=0;while(v>=1024&&i<u.length-1){v/=1024;i++;}return new DecimalFormat("0.##").format(v)+" "+u[i];}
    private String label(String name){
        if("lua-deep.json".equals(name))return "Lua bytecode · "+name;
        if("hermes-deep.json".equals(name))return "Hermes HBC · "+name;
        if("native-deep.json".equals(name))return "ARM64/ELF · "+name;
        if("cocos-deep.json".equals(name))return "Cocos script↔native · "+name;
        if("flutter-deep.json".equals(name))return "Flutter/Dart AOT · "+name;
        if("automatic-evidence.json".equals(name))return "Автоматическая цепочка · "+name;
        if("connected-report.json".equals(name)||"connected-report.md".equals(name))return "Связанный отчёт · "+name;
        return name;
    }
    private void render(){files.removeAllViews();String[] names={
            "full-reconstruction.json","modkit-decompiled.zip","apktool-analysis.json","apktool-workspace",
            "installed-scan.json","artifact-families.json","embedded-analysis.json","automatic-evidence.json",
            "lua-deep.json","hermes-deep.json","native-deep.json","cocos-deep.json","flutter-deep.json",
            "analysis.summary.json","analysis.methods.jsonl","analysis.fields.jsonl","analysis.evidence-graph.jsonl",
            "analysis.gameplay-coverage.json","re-analysis.json","security-surfaces.json","simple-catalog.json",
            "rodroid","analysis-deep","menu-spec.json","menu-preflight.json","connected-report.json","connected-report.md"
        };int found=0;for(String n:names){File f=app.file(n);if(!f.exists())continue;TextView t=text("✓ "+label(n)+" · "+human(size(f)),13);t.setTextColor(fg());files.addView(t);found++;}if(found==0){TextView t=text("Пока пусто. Сначала выполните полный анализ.",14);t.setTextColor(muted());files.addView(t);}}
}
