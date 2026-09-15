package dev.modkit.mobile;

import android.app.AlertDialog;
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

import org.json.JSONArray;
import org.json.JSONObject;

/** One-screen automatic flow: target -> full in-app pipeline -> ranked result. */
public class AutoAnalysisActivity extends AppCompatActivity {
    private static final int TARGET=920;
    private App app;private LinearLayout root,findings;private TextView target,status,summary;private ProgressBar progress;private MaterialButton rerun,change,cancel,storage,mod;
    private final Handler handler=new Handler(Looper.getMainLooper());private long lastRevision=-1;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}
    private MaterialButton button(String label,LinearLayout box,View.OnClickListener click){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(click);box.addView(b);return b;}
    private LinearLayout card(String title){MaterialCardView c=new MaterialCardView(this);c.setCardBackgroundColor(surface());c.setStrokeColor(outline());c.setStrokeWidth(dp(1));c.setRadius(dp(18));LinearLayout b=new LinearLayout(this);b.setOrientation(LinearLayout.VERTICAL);b.setPadding(dp(15),dp(12),dp(15),dp(14));c.addView(b);TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);b.addView(h);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(7),0,dp(7));root.addView(c,lp);return b;}

    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("Полный автоматический анализ",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView note=text("Один target и один прогон. Встроенные движки запускаются автоматически; ручной импорт внешних отчётов не требуется.",13);note.setTextColor(muted());root.addView(note);
        LinearLayout run=card("Target и прогон");target=text("",14);run.addView(target);change=button("Сменить приложение / APK и запустить заново",run,v->openTarget());rerun=button("Повторить полный анализ текущего target",run,v->startFullAnalysis());cancel=button("Отменить текущий анализ",run,v->{app.cancelled.set(true);app.progress("Отмена запрошена — завершаю текущий безопасный шаг…");});progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);progress.setIndeterminate(true);run.addView(progress,new LinearLayout.LayoutParams(-1,dp(8)));status=text("",13);run.addView(status);
        LinearLayout result=card("Результат");summary=text("Анализ ещё не завершён.",14);result.addView(summary);findings=new LinearLayout(this);findings.setOrientation(LinearLayout.VERTICAL);result.addView(findings);storage=button("Открыть результаты и хранилище",result,v->startActivity(new Intent(this,AnalysisStorageActivity.class)));mod=button("AutoMod / Patch Lab · подготовить подтверждённые изменения",result,v->startActivity(new Intent(this,AutoModActivity.class)));
        handler.post(poll);
        if(state==null&&getIntent().getBooleanExtra("autoStart",false))handler.postDelayed(this::openTarget,180);
    }
    private String targetText(){String installed=getSharedPreferences("state",0).getString("installed.package","");String apk=getSharedPreferences("state",0).getString("game.apk","");if(!installed.isEmpty())return installed;if(!apk.isEmpty())return apk;if(app.file("game.apk").isFile())return "Локальный APK";return "Target не выбран";}
    private void openTarget(){if(app.busy.get()){toast("Сначала дождитесь завершения или отмените текущую операцию");return;}startActivityForResult(new Intent(this,TargetSelectionActivity.class),TARGET);}
    private void startFullAnalysis(){if(app.busy.get()){toast("Анализ уже выполняется");return;}if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile()){openTarget();return;}app.cancelled.set(false);app.busy.set(true);app.progress("Полный анализ: подготовка встроенных движков…");try{startForegroundService(new Intent(this,FullAnalysisService.class));}catch(Exception e){app.busy.set(false);app.progress("Не удалось запустить полный анализ: "+e.getMessage());}}
    private JSONObject json(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private String elapsed(long ms){long sec=Math.max(0L,ms/1000L),min=sec/60L;sec%=60L;return min>0?min+" мин "+sec+" с":sec+" с";}
    private String phase(JSONObject p){String value=p.optString("phase","");if("RECONSTRUCTION".equals(value))return "Реконструкция";if("EVIDENCE".equals(value))return "Evidence Graph";return "Анализ";}
    private void renderCatalog(JSONObject cat){findings.removeAllViews();if(cat==null){summary.setText(app.busy.get()?"Анализ выполняется…":"Результаты ещё не сформированы.");mod.setEnabled(false);return;}int total=cat.optInt("total"),important=cat.optInt("important"),ready=cat.optInt("buildable"),actionable=cat.optInt("actionable"),server=cat.optInt("serverAudit");summary.setText("Найдено: "+total+" · важных: "+important+" · точных locator: "+actionable+" · готовых локальных изменений: "+ready+" · server/trust audit: "+server);mod.setEnabled(!app.busy.get()&&(ready>0||actionable>0||important>0));JSONArray cards=cat.optJSONArray("cards");if(cards==null)return;int shown=0;for(int pass=0;pass<2&&shown<35;pass++){for(int i=0;i<cards.length()&&shown<35;i++){JSONObject c=cards.optJSONObject(i);if(c==null)continue;boolean noisy=c.optBoolean("lowSignal")||"FRAMEWORK_NOISE".equals(c.optString("ownership"));boolean audit=c.optBoolean("serverAudit");if(pass==0&&(noisy||audit))continue;if(pass==1&&!audit)continue;TextView row=text((c.optBoolean("buildable")?"READY · ":c.optBoolean("actionable")?"LOCATOR · ":"")+c.optString("title","Находка")+"\n"+c.optString("description",c.optString("status","")),14);row.setPadding(dp(10),dp(9),dp(10),dp(9));row.setBackgroundColor(surface());row.setOnClickListener(v->new AlertDialog.Builder(this).setTitle(c.optString("title","Находка")).setMessage(c.toString()).setPositiveButton("OK",null).show());findings.addView(row,new LinearLayout.LayoutParams(-1,-2));shown++;}}}
    private void refresh(){target.setText("Target: "+targetText());boolean busy=app.busy.get();progress.setVisibility(busy?View.VISIBLE:View.GONE);cancel.setEnabled(busy&&!app.cancelled.get());change.setEnabled(!busy);rerun.setEnabled(!busy&&(app.file("game.apk").isFile()||app.file("installed-target.json").isFile()));storage.setEnabled(!busy);String s=app.status==null?"":app.status;JSONObject p=json("simple-progress.json");if(p!=null&&busy)s+="\n"+phase(p)+" · этап "+p.optInt("stage")+"/"+p.optInt("totalStages")+" · "+p.optString("name")+" · прошло: "+elapsed(p.optLong("elapsedMs"))+" · осталось стадий: "+p.optInt("remainingStages");status.setText(s);renderCatalog(json("simple-catalog.json"));}
    private final Runnable poll=new Runnable(){public void run(){if(lastRevision!=app.revision||app.busy.get()){lastRevision=app.revision;refresh();}handler.postDelayed(this,450);}};
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(req==TARGET&&result==RESULT_OK)startFullAnalysis();}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override protected void onDestroy(){handler.removeCallbacks(poll);super.onDestroy();}
}
