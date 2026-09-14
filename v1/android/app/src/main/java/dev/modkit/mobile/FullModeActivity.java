package dev.modkit.mobile;

import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

/** Unified professional hub for the v1.1 workflow. */
public class FullModeActivity extends AppCompatActivity {
    private static final int TARGET=930;private App app;private LinearLayout root;private TextView target,status;private ProgressBar progress;private MaterialButton select,analyze,cancel;private final Handler handler=new Handler(Looper.getMainLooper());
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));return t;}private MaterialButton button(String label,LinearLayout box,View.OnClickListener l){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(l);box.addView(b);return b;}
    private LinearLayout section(String title,String note){MaterialCardView c=new MaterialCardView(this);c.setCardBackgroundColor(surface());c.setStrokeColor(outline());c.setStrokeWidth(dp(1));c.setRadius(dp(18));LinearLayout b=new LinearLayout(this);b.setOrientation(LinearLayout.VERTICAL);b.setPadding(dp(15),dp(12),dp(15),dp(14));c.addView(b);TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);b.addView(h);TextView n=text(note,13);n.setTextColor(muted());b.addView(n);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(7),0,dp(7));root.addView(c,lp);return b;}
    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);TextView title=text("Полный режим",30);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView sub=text("Все функции ModKit по одному, без второго главного меню.",13);sub.setTextColor(muted());root.addView(sub);
        LinearLayout t=section("Target и анализ","Один target используется всеми рабочими пространствами.");target=text("",14);t.addView(target);select=button("Выбрать / сменить приложение или APK",t,v->startActivityForResult(new Intent(this,TargetSelectionActivity.class),TARGET));analyze=button("Запустить полный автоматический анализ",t,v->startFull());cancel=button("Отменить текущую операцию",t,v->{app.cancelled.set(true);app.progress("Отмена запрошена…");});progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);progress.setIndeterminate(true);t.addView(progress,new LinearLayout.LayoutParams(-1,dp(8)));status=text("",13);t.addView(status);
        LinearLayout storage=section("Результаты и хранилище","Все созданные после анализа артефакты и быстрые переходы к редакторам.");button("Открыть хранилище анализа",storage,v->startActivity(new Intent(this,AnalysisStorageActivity.class)));
        LinearLayout code=section("Код и ресурсы","Декомпиляция, DEX/Unity/IL2CPP и ручная работа с файлами.");button("Decompiler · Java / Smali / Resources",code,v->startActivity(new Intent(this,DecompilerActivity.class)));button("RE Workspace · DEX / Unity / IL2CPP / методы",code,v->startActivity(new Intent(this,ReWorkspaceActivity.class)));button("Файлы · редактор · Patch Pack · сборка",code,v->startActivity(new Intent(this,FileWorkspaceActivity.class)));
        LinearLayout nativeBox=section("Native","ELF/ARM64, RVA, xrefs и рабочая копия .so.");button("Native Workspace",nativeBox,v->startActivity(new Intent(this,NativeWorkspaceActivity.class)));button("Patch Pack",nativeBox,v->startActivity(new Intent(this,PatchPackActivity.class)));
        LinearLayout build=section("Мод и runtime","Подготовка подтверждённых controls, сборка и локальная runtime-проверка.");button("Menu Builder / Autopilot",build,v->startActivity(new Intent(this,MenuBuilderActivity.class)));button("Process Lab · root / процессы",build,v->startActivity(new Intent(this,ProcessLabActivity.class)));
        LinearLayout reports=section("Отчёт","Связанный отчёт и Evidence Bundle после полного прогона.");button("Экспортировать отчёт",reports,v->startActivity(new Intent(this,ReportCenterActivity.class)));
        handler.post(poll);if(state==null&&getIntent().getBooleanExtra("openTargetPicker",false))handler.postDelayed(()->startActivityForResult(new Intent(this,TargetSelectionActivity.class),TARGET),180);
    }
    private String targetText(){String i=getSharedPreferences("state",0).getString("installed.package","");String a=getSharedPreferences("state",0).getString("game.apk","");return !i.isEmpty()?i:!a.isEmpty()?a:app.file("game.apk").isFile()?"Локальный APK":"не выбран";}
    private void startFull(){if(app.busy.get()){Toast.makeText(this,"Уже выполняется операция",Toast.LENGTH_LONG).show();return;}if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile()){startActivityForResult(new Intent(this,TargetSelectionActivity.class),TARGET);return;}app.cancelled.set(false);app.busy.set(true);app.progress("Полный анализ: подготовка…");startForegroundService(new Intent(this,FullAnalysisService.class));}
    private void refresh(){boolean b=app.busy.get();target.setText("Target: "+targetText());status.setText(app.status==null?"":app.status);progress.setVisibility(b?View.VISIBLE:View.GONE);select.setEnabled(!b);analyze.setEnabled(!b);cancel.setEnabled(b&&!app.cancelled.get());}
    private final Runnable poll=new Runnable(){public void run(){refresh();handler.postDelayed(this,500);}};
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(req==TARGET&&result==RESULT_OK)refresh();}
    @Override protected void onDestroy(){handler.removeCallbacks(poll);super.onDestroy();}
}
