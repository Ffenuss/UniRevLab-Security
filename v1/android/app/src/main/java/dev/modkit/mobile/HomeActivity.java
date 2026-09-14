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

/** Single release entry point. Only the unified v1.1 routes are exposed here. */
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
        TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);body.addView(h);TextView n=text(note,13);n.setTextColor(muted());body.addView(n);
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(7),0,dp(7));root.addView(card,lp);return body;
    }
    private void button(String label,LinearLayout box,Intent intent){
        com.google.android.material.button.MaterialButton b=new com.google.android.material.button.MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(v->startActivity(intent));box.addView(b);
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("ModKit",34);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView sub=text("Android Analysis & Reverse Engineering · 1.1",14);sub.setTextColor(muted());root.addView(sub);

        LinearLayout auto=section("Полный автоматический анализ","Выберите приложение или APK один раз. ModKit сам прогонит встроенные декодеры, декомпиляторы, DEX/native/IL2CPP, gameplay/security и соберёт единый Evidence Graph.");
        button("Начать полный анализ",auto,new Intent(this,AutoAnalysisActivity.class).putExtra("autoStart",true));

        LinearLayout full=section("Полный режим","Все ручные инструменты в одном месте: target, декомпиляция, методы, native, редактор файлов, Patch Pack, Menu Builder, runtime и сборка.");
        button("Открыть полный режим",full,new Intent(this,FullModeActivity.class));

        LinearLayout reports=section("Отчёт","Экспортирует результаты полного прогона вместе со связанными методами/локаторами, Evidence Graph, дампами текста и SHA-256.");
        button("Экспортировать отчёт",reports,new Intent(this,ReportCenterActivity.class));

        TextView footer=text("На главном экране нет дублирующих инженерных кнопок и внешних импортов. Они не нужны для обычного полного анализа.",12);footer.setTextColor(muted());root.addView(footer);
    }
}
