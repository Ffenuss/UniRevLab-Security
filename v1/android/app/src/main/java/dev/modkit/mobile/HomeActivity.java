package dev.modkit.mobile;

import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/** Minimal release dashboard. Deep complexity stays behind dedicated workspaces. */
public class HomeActivity extends AppCompatActivity {
    private LinearLayout root;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}
    private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}
    private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}
    private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}
    private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}
    private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));return t;}
    private LinearLayout section(String title,String note){
        com.google.android.material.card.MaterialCardView card=new com.google.android.material.card.MaterialCardView(this);card.setCardBackgroundColor(surface());card.setRadius(dp(18));card.setStrokeColor(outline());card.setStrokeWidth(dp(1));card.setCardElevation(dp(1));
        LinearLayout body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);body.setPadding(dp(16),dp(13),dp(16),dp(15));card.addView(body);
        TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);body.addView(h);if(note!=null&&!note.trim().isEmpty()){TextView n=text(note,13);n.setTextColor(muted());body.addView(n);}
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(7),0,dp(7));root.addView(card,lp);return body;
    }
    private void button(String label,LinearLayout box,Class<?> target){
        com.google.android.material.button.MaterialButton b=new com.google.android.material.button.MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(v->startActivity(new Intent(this,target)));box.addView(b);
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("ModKit",34);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView sub=text("Android Analysis & Reverse Engineering · 1.0",14);sub.setTextColor(muted());root.addView(sub);
        LinearLayout quick=section("Полный автоматический анализ","Один запуск: inventory → reconstruction → semantics → security → confirmation. На экране только важное; технические доказательства сохраняются полностью.");
        button("Начать полный анализ",quick,SimpleModeActivity.class);
        LinearLayout target=section("Target и полный режим","Выбор установленного приложения/APK, IL2CPP-пары, каталога методов и ручных операций.");
        button("Открыть полный режим",target,MainActivity.class);
        LinearLayout work=section("Инженерные пространства","Открывайте нужный уровень представления только когда он действительно нужен.");
        button("Decompiler · Java / Smali / Resources",work,DecompilerActivity.class);button("RE Workspace · DEX / Unity / IL2CPP",work,ReWorkspaceActivity.class);button("Native · ELF / ARM64",work,NativeWorkspaceActivity.class);button("Файлы / Patch Pack",work,FileWorkspaceActivity.class);
        LinearLayout runtime=section("Runtime","Root проверяется только по вашему нажатию. При uid=0 можно открыть read-only session живого процесса; Frida/ptrace — отдельные расширяемые backends.");
        button("Process Lab · root / процессы",runtime,ProcessLabActivity.class);
        LinearLayout evidence=section("Отчёты","Экспортируйте один технический пакет со всеми результатами, индексами, графами, runtime snapshot и SHA-256.");
        button("Отчёты и Evidence Bundle",evidence,ReportCenterActivity.class);
        LinearLayout engines=section("Движки и расширения","Показывает, что встроено сейчас и какие точки входа подготовлены для следующих анализаторов/декомпиляторов.");
        button("Каталог движков",engines,EngineCatalogActivity.class);
        TextView footer=text("Simple Mode не скрывает данные: он скрывает шум. Полный Evidence остаётся доступен для инженера и экспорта.",12);footer.setTextColor(muted());root.addView(footer);
    }
}
