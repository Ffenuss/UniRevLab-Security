package dev.modkit.mobile;

import android.app.AlertDialog;
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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Compact coordinator over Evidence Graph -> exact prepare -> preflight -> signed build. */
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

    public final class PlanningProgress {public boolean isCancelled(){return Thread.currentThread().isInterrupted();}}
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}
    private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}
    private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}
    private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}
    private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}
    private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(3),0,dp(3));t.setTextIsSelectable(true);return t;}
    private LinearLayout actionRow(){LinearLayout row=new LinearLayout(this);row.setOrientation(LinearLayout.HORIZONTAL);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(3),0,dp(3));root.addView(row,lp);return row;}
    private MaterialButton rowButton(String label,LinearLayout row,View.OnClickListener listener){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextSize(12);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(listener);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1f);lp.setMargins(dp(2),0,dp(2),0);row.addView(b,lp);return b;}
    private JSONObject read(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private void toast(String value){Toast.makeText(this,value,Toast.LENGTH_LONG).show();}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(14),dp(14),dp(14),dp(24));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("AutoMod / Patch Lab",27);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        TextView note=text("Fail-closed: в prepare/build проходят только подтверждённые exact locators. Runtime и metadata/no-RVA — corroboration до строгого recovery + binding + preflight.",12);note.setTextColor(muted());root.addView(note);
        summary=text("",13);root.addView(summary);preflight=text("",12);preflight.setTextColor(muted());root.addView(preflight);status=text("",12);root.addView(status);

        LinearLayout planRow=actionRow();refresh=rowButton("Обновить план",planRow,v->rebuildPlan());prepare=rowButton("Exact prepare",planRow,v->startExactPrepare());
        LinearLayout buildRow=actionRow();check=rowButton("Preflight",buildRow,v->startWorker("menu_preflight",null));build=rowButton("Собрать APK",buildRow,v->chooseBuildDestination());
        TextView toolsHeading=text("Инструменты",14);toolsHeading.setTypeface(null,Typeface.BOLD);root.addView(toolsHeading);
        LinearLayout tools=actionRow();rowButton("Runtime",tools,v->startActivity(new Intent(this,ProcessLabActivity.class)));rowButton("Controls",tools,v->startActivity(new Intent(this,MenuBuilderActivity.class).putExtra("focus","autopilot")));rowButton("Patch Pack",tools,v->startActivity(new Intent(this,PatchPackActivity.class)));

        TextView heading=text("Приоритетные кандидаты · нажмите для деталей",16);heading.setTypeface(null,Typeface.BOLD);root.addView(heading);
        candidates=new LinearLayout(this);candidates.setOrientation(LinearLayout.VERTICAL);root.addView(candidates);
        render();if(!app.file("automod-plan.json").isFile()&&app.file("simple-catalog.json").isFile())rebuildPlan();handler.post(poll);
    }

    private boolean canStart(){if(planning){toast("Дождитесь обновления AutoMod-плана");return false;}if(app.busy.get()){toast("Сейчас выполняется другая операция");return false;}if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile()){toast("Target не выбран");return false;}return true;}
    private void invalidatePreparedState(){for(String name:new String[]{"menu-spec.json","menu-preflight.json","menu-validation.json","menu-auto-confirm.json","menu-autopilot.json","menu-native-recovery.json"})app.file(name).delete();}
    private boolean exactPrepareAuditReady(){JSONObject audit=read("menu-native-recovery.json");return audit!=null&&audit.optBoolean("completed")&&audit.optBoolean("normalBindingRequired")&&audit.optBoolean("preflightRequired")&&!audit.optBoolean("promotesBuildability")&&!audit.optBoolean("addressRecoveryPromotesBuildability");}

    private void rebuildPlan(){
        if(planning){toast("AutoMod-план уже обновляется");return;}if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}if(!app.file("simple-catalog.json").isFile()&&!app.file("game.apk").isFile()){toast("Сначала выполните полный анализ");return;}
        invalidatePreparedState();
        planning=true;refresh.setEnabled(false);prepare.setEnabled(false);check.setEnabled(false);build.setEnabled(false);status.setText("AutoMod: проверяю Evidence Graph, exact SHA и native recovery…");
        executor.execute(()->{try{if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject result=Python.getInstance().getModule("modkit.mobile.automod_cancellable").callAttr("build_workspace_plan",getFilesDir().getPath(),app.file("automod-plan.json").getPath(),new PlanningProgress());new JSONObject(result.toString());runOnUiThread(()->status.setText("План обновлён · старый prepare/preflight инвалидирован."));}catch(Exception e){runOnUiThread(()->{status.setText("AutoMod: "+e.getMessage());toast("Не удалось обновить план");});}finally{planning=false;runOnUiThread(this::render);}});
    }

    private void startExactPrepare(){
        if(!canStart())return;
        JSONObject plan=read("automod-plan.json");if(plan==null){toast("Сначала обновите AutoMod-план");return;}
        if(plan.optInt("readyToBuildCount")+plan.optInt("readyForPreflightCount")<=0){toast("Нет кандидатов для prepare/preflight");return;}
        app.cancelled.set(false);app.busy.set(true);app.progress("AutoMod: exact recovery + Deep/binding/preflight…");
        startForegroundService(new Intent(this,AutoModPrepareService.class));
    }

    private void startWorker(String op,Uri uri){
        if(!canStart())return;app.cancelled.set(false);app.busy.set(true);app.progress("AutoMod: "+op+"…");
        Intent intent=new Intent(this,WorkerService.class).putExtra("op",op);if(uri!=null)intent.putExtra("uri",uri.toString());startForegroundService(intent);
    }

    private void chooseBuildDestination(){
        if(!canStart())return;
        JSONObject plan=read("automod-plan.json");if(plan==null){toast("Сначала обновите AutoMod-план");return;}int ready=plan.optInt("readyToBuildCount")+plan.optInt("readyForPreflightCount");if(ready<=0){toast("Нет локальных кандидатов, допущенных до prepare/preflight");return;}
        if(!exactPrepareAuditReady()){toast("Exact prepare audit отсутствует или не завершён. Сборка fail-closed заблокирована.");return;}
        JSONObject pf=read("menu-preflight.json");if(pf==null||!pf.optBoolean("readyForAutoBuild")){toast("Сначала выполните успешный exact prepare/preflight. Сборка fail-closed заблокирована.");return;}
        boolean apkSet=hasApkSet();String mime=apkSet?"application/zip":"application/vnd.android.package-archive";String name=apkSet?"modkit-automod-signed.apks":"modkit-automod-signed.apk";Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(mime).addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,name);startActivityForResult(intent,BUILD_DOCUMENT);
    }

    private boolean hasApkSet(){JSONObject target=read("installed-target.json");JSONArray splits=target==null?null:target.optJSONArray("splits");return splits!=null&&splits.length()>1;}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request==BUILD_DOCUMENT&&result==RESULT_OK&&data!=null&&data.getData()!=null)startWorker("menu_build_apk",data.getData());}
    private String count(JSONObject plan,String key){return String.valueOf(plan==null?0:plan.optInt(key));}

    private void render(){
        JSONObject plan=read("automod-plan.json");JSONObject pf=read("menu-preflight.json");boolean auditReady=exactPrepareAuditReady();if(plan==null){summary.setText("План не построен · выполните полный анализ и обновите план.");candidates.removeAllViews();setButtons(null,pf);return;}
        summary.setText("BUILD "+count(plan,"readyToBuildCount")+" · PREFLIGHT "+count(plan,"readyForPreflightCount")+" · RUNTIME "+count(plan,"runtimeNeededCount")+" · REVIEW "+count(plan,"reviewCount")+" · AUDIT "+count(plan,"auditOnlyCount")+" · EXCLUDED "+count(plan,"excludedCount")+"\nExact "+count(plan,"exactLocatorCount")+" · recovered RVA "+count(plan,"nativeRecoveredLocatorCount")+" · runtime VA "+count(plan,"runtimeObservedCount")+" · metadata/no-RVA "+count(plan,"metadataIdentityObservedCount")+" · total "+count(plan,"candidateCount"));
        if(pf==null)preflight.setText("Exact audit: "+(auditReady?"READY":"BLOCK")+" · Preflight: NOT RUN · build BLOCK");else preflight.setText("Exact audit: "+(auditReady?"READY":"BLOCK")+" · Preflight: "+(pf.optBoolean("readyForAutoBuild")?"READY":"BLOCK")+" · controls "+pf.optInt("controlCount",pf.optInt("controls"))+" · blockers "+pf.optInt("blockerCount",pf.optInt("blockers")));
        candidates.removeAllViews();JSONArray rows=plan.optJSONArray("candidates");int shown=0;if(rows!=null)for(int i=0;i<rows.length()&&shown<16;i++){JSONObject row=rows.optJSONObject(i);if(row==null)continue;String stage=row.optString("stage","REVIEW");if("EXCLUDED".equals(stage)&&shown>=12)continue;candidateCard(row);shown++;}setButtons(plan,pf);
    }

    private void candidateCard(JSONObject row){
        MaterialCardView card=new MaterialCardView(this);card.setCardBackgroundColor(surface());card.setStrokeColor(outline());card.setStrokeWidth(dp(1));card.setRadius(dp(12));LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(10),dp(7),dp(10),dp(8));card.addView(box);TextView h=text(row.optString("title","evidence"),15);h.setTypeface(null,Typeface.BOLD);box.addView(h);
        String domain=row.optString("gameplayDomain","");String locator="";JSONObject loc=row.optJSONObject("locator");if(loc!=null){Object rva=loc.opt("rva");if(rva!=null&&rva!=JSONObject.NULL&&!"0".equals(String.valueOf(rva))&&!"0x0".equalsIgnoreCase(String.valueOf(rva)))locator=" · RVA "+String.valueOf(rva);else if(loc.has("entry"))locator=" · "+loc.optString("entry");}
        JSONObject recovered=row.optJSONObject("nativeRvaRecovery");String recoveredText=recovered!=null&&row.optBoolean("nativeRvaRecovered")?" · RECOVERED":"";JSONObject runtime=row.optJSONObject("runtimeObservation");String runtimeText=runtime!=null&&runtime.optBoolean("mapped")?" · RUNTIME":"";JSONObject il2cpp=row.optJSONObject("il2cppStructural");String il2cppText=il2cpp==null?"":" · IL2CPP";JSONObject identity=row.optJSONObject("metadataIdentity");String identityText=identity==null?"":" · META";
        TextView meta=text(row.optString("stage","REVIEW")+(domain.isEmpty()?"":" · "+domain)+locator+recoveredText+runtimeText+il2cppText+identityText,11);meta.setTextColor(muted());box.addView(meta);String reason=row.optString("reason","");if(!reason.isEmpty())box.addView(text(reason,12));card.setOnClickListener(v->new AlertDialog.Builder(this).setTitle(row.optString("title","Evidence details")).setMessage(row.toString()).setPositiveButton("OK",null).show());LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(3),0,dp(3));candidates.addView(card,lp);
    }

    private void setButtons(JSONObject plan,JSONObject pf){boolean idle=!app.busy.get()&&!planning;int prepareCount=plan==null?0:plan.optInt("readyToBuildCount")+plan.optInt("readyForPreflightCount");refresh.setEnabled(idle);prepare.setEnabled(idle&&prepareCount>0);check.setEnabled(idle&&app.file("menu-spec.json").isFile());boolean preflightReady=pf!=null&&pf.optBoolean("readyForAutoBuild");build.setEnabled(idle&&prepareCount>0&&preflightReady&&exactPrepareAuditReady());}
    private final Runnable poll=new Runnable(){public void run(){if(revision!=app.revision){revision=app.revision;render();if(!planning)status.setText(app.status==null?"":app.status);}else if(app.busy.get()&&!planning)status.setText(app.status==null?"":app.status);handler.postDelayed(this,600);}};
    @Override protected void onResume(){super.onResume();render();}
    @Override protected void onDestroy(){handler.removeCallbacks(poll);executor.shutdownNow();super.onDestroy();}
}
