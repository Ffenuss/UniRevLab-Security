package dev.modkit.mobile;

import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Compact coordinator over Evidence Graph -> smart prepare -> preflight -> signed build. */
public class AutoModActivity extends AppCompatActivity {
    private static final int BUILD_DOCUMENT=980;
    private App app;
    private LinearLayout root,candidates;
    private TextView summary,status,preflight;
    private MaterialButton refresh,prepare,check,build;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private long revision=-1;
    private volatile boolean planning;

    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}
    private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}
    private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}
    private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}
    private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}
    private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(4),0,dp(4));t.setTextIsSelectable(true);return t;}
    private MaterialButton button(String label,View.OnClickListener listener){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(listener);root.addView(b);return b;}
    private JSONObject read(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private void toast(String value){Toast.makeText(this,value,Toast.LENGTH_LONG).show();}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(30));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("AutoMod / Patch Lab",29);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        TextView note=text("Evidence Graph сам раскладывает находки по готовности. В автоматическую сборку проходят только локальные app-owned controls с проверенным executable binding. Server/payment/auth/trust findings остаются audit-only; статический keyword сам по себе не становится патчем.",13);note.setTextColor(muted());root.addView(note);
        summary=text("",14);root.addView(summary);preflight=text("",13);preflight.setTextColor(muted());root.addView(preflight);status=text("",13);root.addView(status);
        refresh=button("Обновить AutoMod-план",v->rebuildPlan());
        prepare=button("Подготовить подтверждённые controls",v->startWork("menu_smart_prepare",null));
        check=button("Проверить preflight",v->startWork("menu_preflight",null));
        build=button("Собрать подписанный APK / APK-set",v->chooseBuildDestination());
        button("Menu Builder · детали controls",v->startActivity(new Intent(this,MenuBuilderActivity.class).putExtra("focus","autopilot")));
        button("Ручной Patch Pack",v->startActivity(new Intent(this,PatchPackActivity.class)));
        TextView heading=text("Приоритетные кандидаты",18);heading.setTypeface(null,Typeface.BOLD);root.addView(heading);
        candidates=new LinearLayout(this);candidates.setOrientation(LinearLayout.VERTICAL);root.addView(candidates);
        render();
        if(!app.file("automod-plan.json").isFile()&&app.file("simple-catalog.json").isFile())rebuildPlan();
        handler.post(poll);
    }

    private void rebuildPlan(){
        if(planning){toast("AutoMod-план уже обновляется");return;}
        if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}
        if(!app.file("simple-catalog.json").isFile()&&!app.file("game.apk").isFile()){toast("Сначала выполните полный анализ");return;}
        planning=true;refresh.setEnabled(false);status.setText("AutoMod: строю fail-closed план из Evidence Graph…");
        executor.execute(()->{
            try{
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));
                PyObject result=Python.getInstance().getModule("modkit.mobile.automod").callAttr("build_workspace_plan",getFilesDir().getPath(),app.file("automod-plan.json").getPath());
                new JSONObject(result.toString());
                runOnUiThread(()->{status.setText("AutoMod-план обновлён.");render();});
            }catch(Exception e){runOnUiThread(()->{status.setText("AutoMod: "+e.getMessage());toast("Не удалось обновить план");});}
            finally{planning=false;runOnUiThread(()->refresh.setEnabled(!app.busy.get()));}
        });
    }

    private void startWork(String op,Uri uri){
        if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}
        if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile()){toast("Target не выбран");return;}
        app.cancelled.set(false);app.busy.set(true);app.progress("AutoMod: подготовка…");
        Intent intent=new Intent(this,WorkerService.class).putExtra("op",op);
        if(uri!=null)intent.putExtra("uri",uri.toString());
        startForegroundService(intent);
    }

    private void chooseBuildDestination(){
        JSONObject plan=read("automod-plan.json");
        if(plan==null){toast("Сначала обновите AutoMod-план");return;}
        int ready=plan.optInt("readyToBuildCount")+plan.optInt("readyForPreflightCount");
        if(ready<=0){toast("Нет локальных кандидатов, допущенных до prepare/preflight");return;}
        boolean apkSet=hasApkSet();
        String mime=apkSet?"application/zip":"application/vnd.android.package-archive";
        String name=apkSet?"modkit-automod-signed.apks":"modkit-automod-signed.apk";
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(mime).addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,name);
        startActivityForResult(intent,BUILD_DOCUMENT);
    }

    private boolean hasApkSet(){
        JSONObject target=read("installed-target.json");
        JSONArray splits=target==null?null:target.optJSONArray("splits");
        return splits!=null&&splits.length()>1;
    }

    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==BUILD_DOCUMENT&&result==RESULT_OK&&data!=null&&data.getData()!=null)startWork("menu_smart_build_apk",data.getData());
    }

    private String count(JSONObject plan,String key){return String.valueOf(plan==null?0:plan.optInt(key));}
    private void render(){
        JSONObject plan=read("automod-plan.json");JSONObject pf=read("menu-preflight.json");
        if(plan==null){summary.setText("План ещё не построен. Выполните полный анализ и нажмите «Обновить AutoMod-план».");candidates.removeAllViews();setButtons(null,pf);return;}
        summary.setText("Готово к build: "+count(plan,"readyToBuildCount")+" · preflight: "+count(plan,"readyForPreflightCount")+" · runtime/binding: "+count(plan,"runtimeNeededCount")+" · review: "+count(plan,"reviewCount")+" · audit-only: "+count(plan,"auditOnlyCount")+" · исключено: "+count(plan,"excludedCount")+"\nExact locators: "+count(plan,"exactLocatorCount")+" · всего: "+count(plan,"candidateCount"));
        if(pf==null)preflight.setText("Preflight ещё не выполнен.");
        else preflight.setText("Preflight: "+(pf.optBoolean("readyForAutoBuild")?"READY":"BLOCK")+" · controls "+pf.optInt("controlCount",pf.optInt("controls"))+" · blockers "+pf.optInt("blockerCount",pf.optInt("blockers")));
        candidates.removeAllViews();JSONArray rows=plan.optJSONArray("candidates");int shown=0;if(rows!=null)for(int i=0;i<rows.length()&&shown<24;i++){JSONObject row=rows.optJSONObject(i);if(row==null)continue;String stage=row.optString("stage","REVIEW");if("EXCLUDED".equals(stage)&&shown>=18)continue;candidateCard(row);shown++;}
        setButtons(plan,pf);
    }

    private void candidateCard(JSONObject row){
        MaterialCardView card=new MaterialCardView(this);card.setCardBackgroundColor(surface());card.setStrokeColor(outline());card.setStrokeWidth(dp(1));card.setRadius(dp(14));
        LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(12),dp(9),dp(12),dp(10));card.addView(box);
        TextView h=text(row.optString("title","evidence"),16);h.setTypeface(null,Typeface.BOLD);box.addView(h);
        String domain=row.optString("gameplayDomain","");String locator="";JSONObject loc=row.optJSONObject("locator");if(loc!=null){Object rva=loc.opt("rva");if(rva!=null&&rva!=JSONObject.NULL)locator=" · RVA "+String.valueOf(rva);else if(loc.has("entry"))locator=" · "+loc.optString("entry");}
        TextView meta=text(row.optString("stage")+" · "+row.optString("verificationStage","FOUND_STATIC")+(domain.isEmpty()?"":" · "+domain)+locator,12);meta.setTextColor(muted());box.addView(meta);
        box.addView(text(row.optString("reason",""),13));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(5),0,dp(5));candidates.addView(card,lp);
    }

    private void setButtons(JSONObject plan,JSONObject pf){
        boolean idle=!app.busy.get()&&!planning;int prepareCount=plan==null?0:plan.optInt("readyToBuildCount")+plan.optInt("readyForPreflightCount");
        refresh.setEnabled(idle);prepare.setEnabled(idle&&prepareCount>0);check.setEnabled(idle&&app.file("menu-spec.json").isFile());
        boolean preflightReady=pf!=null&&pf.optBoolean("readyForAutoBuild");
        build.setEnabled(idle&&prepareCount>0&&(preflightReady||plan.optInt("readyToBuildCount")>0||plan.optInt("readyForPreflightCount")>0));
    }

    private final Runnable poll=new Runnable(){public void run(){if(revision!=app.revision){revision=app.revision;render();}status.setText(app.status==null?"":app.status);handler.postDelayed(this,600);}};
    @Override protected void onResume(){super.onResume();render();}
    @Override protected void onDestroy(){handler.removeCallbacks(poll);executor.shutdownNow();super.onDestroy();}
}
