package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.graphics.*;
import android.net.Uri;
import android.os.*;
import android.text.*;
import android.view.*;
import android.widget.*;
import androidx.recyclerview.widget.*;
import org.json.*;
import java.util.*;

/** Human-oriented Simple Mode: prioritize useful evidence, keep all findings available. */
public class SimpleModeActivity extends Activity {
    private static final int BUILD=401;
    private App app;
    private TextView status,summary,shown;
    private RecyclerView list;
    private CardAdapter adapter;
    private Button prepare,build,cancel;
    private Spinner filter;
    private EditText search;
    private final LinkedHashSet<String> selected=new LinkedHashSet<>();
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long revision=-1;
    private JSONObject currentCatalog=null;
    private final Runnable poll=new Runnable(){public void run(){refresh();handler.postDelayed(this,450);}};

    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(Color.rgb(225,230,235));t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}
    private Button button(String s,LinearLayout p,View.OnClickListener l){Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setOnClickListener(l);p.addView(b);return b;}

    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(14),dp(14),dp(14),dp(14));root.setBackgroundColor(Color.rgb(16,20,24));
        TextView title=text("Для глупых · авто-режим",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text("Показывает сначала важные находки, а framework/SDK-шум оставляет во вкладке «Все». READY означает точный локальный locator; автоматическая сборка всё равно требует проверенный executable binding.",13));
        button("1 · Выбрать установленное приложение / игру",root,v->startActivity(new Intent(this,MainActivity.class).putExtra("autoInstalledPicker",true)));
        prepare=button("2 · Обновить полный анализ",root,v->startWork(new Intent().putExtra("op","simple_prepare")));
        cancel=button("Отменить анализ",root,v->cancelCurrent());cancel.setEnabled(false);
        summary=text("",13);root.addView(summary);status=text("",13);root.addView(status);

        LinearLayout filters=new LinearLayout(this);filters.setOrientation(LinearLayout.HORIZONTAL);filters.setGravity(Gravity.CENTER_VERTICAL);root.addView(filters);
        filter=new Spinner(this);String[] modes={"Все","Patch Ready","Gameplay","HP / Health","Damage","Speed","Cooldown","Currency","Level / XP","Inventory","Camera","Movement","Offline","Network/API","Crypto/Keys","Authentication","Server Audit","Game code","SDK","Framework noise"};ArrayAdapter<String> fa=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,modes);fa.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);filter.setAdapter(fa);filters.addView(filter,new LinearLayout.LayoutParams(0,-2,1f));
        search=new EditText(this);search.setHint("Поиск…");search.setTextColor(Color.WHITE);search.setHintTextColor(Color.GRAY);search.setSingleLine(true);filters.addView(search,new LinearLayout.LayoutParams(0,-2,1.4f));
        shown=text("",12);root.addView(shown);

        list=new RecyclerView(this);list.setLayoutManager(new LinearLayoutManager(this));adapter=new CardAdapter();list.setAdapter(adapter);root.addView(list,new LinearLayout.LayoutParams(-1,0,1f));
        build=button("3 · Сделать мод из выбранного",root,v->requestBuild());setContentView(root);
        filter.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onItemSelected(android.widget.AdapterView<?> p,View v,int pos,long id){adapter.applyFilter();}public void onNothingSelected(android.widget.AdapterView<?> p){}});
        search.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int b,int c){}public void onTextChanged(CharSequence s,int a,int b,int c){adapter.applyFilter();}public void afterTextChanged(Editable e){}});
        refresh();
    }

    private void requestBuild(){if(selected.isEmpty()){toast("Отметьте хотя бы один пункт с авто-сборка READY");return;}startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(isInstalledSet()?"application/zip":"application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,isInstalledSet()?"modkit-simple-test.apks":"modkit-simple-test.apk"),BUILD);}
    private boolean isInstalledSet(){try{JSONObject t=new JSONObject(Io.readUtf8(app.file("installed-target.json")));JSONArray a=t.optJSONArray("splits");return "apk-set".equals(t.optString("buildMode"))&&a!=null&&a.length()>1;}catch(Exception e){return false;}}
    private void startWork(Intent i){if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);startForegroundService(i);}
    private void build(Uri uri){JSONArray ids=new JSONArray();for(String s:selected)ids.put(s);startWork(new Intent().putExtra("op","simple_build").putExtra("uri",uri.toString()).putExtra("controls",ids.toString()));}
    private JSONObject read(){try{return new JSONObject(Io.readUtf8(app.file("simple-catalog.json")));}catch(Exception e){return null;}}

    private void refresh(){revision=app.revision;JSONObject pr=readProgress();String ps=app.status==null?"":app.status;if(pr!=null){long sec=pr.optLong("elapsedMs")/1000L;ps+="\nЭтап "+pr.optInt("stage")+"/"+pr.optInt("totalStages")+" · "+pr.optString("name")+" · осталось этапов: "+pr.optInt("remainingStages")+" · elapsed: "+sec+"s"+(pr.has("candidates")?" · кандидатов: "+pr.optInt("candidates")+" · locator: "+pr.optInt("confirmed"):"");}status.setText(ps);if(cancel!=null)cancel.setEnabled(app.busy.get()&&!app.cancelled.get());JSONObject o=read();currentCatalog=o;
        if(o==null){summary.setText("Список ещё не создан. Выберите приложение и нажмите шаг 2.");adapter.set(new JSONArray());build.setEnabled(false);prepare.setEnabled(!app.busy.get());return;}
        JSONArray cards=o.optJSONArray("cards");JSONObject counts=o.optJSONObject("counts");
        summary.setText("Найдено: "+o.optInt("total")+" · важных: "+o.optInt("important")+" · авто-сборка READY: "+o.optInt("buildable")+" · locator/actionable: "+o.optInt("actionable")+"\nserver/trust: "+o.optInt("serverAudit")+" · framework: "+o.optInt("frameworkNoise")+" · SDK: "+o.optInt("bundledSdk")+(counts==null?"":"\n"+counts.toString()));
        adapter.set(cards==null?new JSONArray():cards);build.setEnabled(!app.busy.get()&&!selected.isEmpty());prepare.setEnabled(!app.busy.get());cancel.setEnabled(app.busy.get()&&!app.cancelled.get());
    }

    private String value(JSONObject o,String... keys){for(String k:keys){Object v=o.opt(k);if(v!=null&&v!=JSONObject.NULL){String s=String.valueOf(v);if(!s.isEmpty())return s;}}return "";}
    private String location(JSONObject c){JSONObject e=c.optJSONObject("evidence");JSONObject l=c.optJSONObject("locator");StringBuilder b=new StringBuilder();if(l!=null){String r=value(l,"rva");if(!r.isEmpty())b.append("RVA: ").append(r).append('\n');String a=value(l,"artifact");if(!a.isEmpty())b.append("Artifact: ").append(a).append('\n');String cl=value(l,"class");if(!cl.isEmpty())b.append("Class: ").append(cl).append('\n');String m=value(l,"method");if(!m.isEmpty())b.append("Method: ").append(m).append('\n');String co=value(l,"codeOffset");if(!co.isEmpty())b.append("Code offset: ").append(co).append('\n');String en=value(l,"entry");if(!en.isEmpty())b.append("Entry: ").append(en).append('\n');String sy=value(l,"symbol");if(!sy.isEmpty())b.append("Symbol: ").append(sy).append('\n');}
        if(e!=null){String art=value(e,"artifact","apk");if(!art.isEmpty()&&b.indexOf(art)<0)b.append("Source: ").append(art).append('\n');String en=value(e,"entry","path","file");if(!en.isEmpty()&&b.indexOf(en)<0)b.append("Entry: ").append(en).append('\n');String cl=value(e,"class","className");if(!cl.isEmpty()&&b.indexOf(cl)<0)b.append("Class: ").append(cl).append('\n');String m=value(e,"method","methodName");if(!m.isEmpty()&&b.indexOf(m)<0)b.append("Method: ").append(m).append('\n');String co=value(e,"codeOffset");if(!co.isEmpty()&&b.indexOf("Code offset")<0)b.append("Code offset: ").append(co).append('\n');}
        return b.toString().trim();}

    private JSONObject readProgress(){try{return new JSONObject(Io.readUtf8(app.file("simple-progress.json")));}catch(Exception e){return null;}}
    private void cancelCurrent(){if(!app.busy.get()){toast("Анализ сейчас не выполняется");return;}app.cancelled.set(true);app.progress("Отмена запрошена — завершаю текущий безопасный шаг…");cancel.setEnabled(false);}
    private Intent locatorIntent(Class<?> cls,JSONObject c){Intent i=new Intent(this,cls);JSONObject l=c.optJSONObject("locator"),e=c.optJSONObject("evidence");i.putExtra("modkitFinding",c.toString());if(l!=null){i.putExtra("rva",value(l,"rva"));i.putExtra("artifact",value(l,"artifact"));i.putExtra("class",value(l,"class"));i.putExtra("method",value(l,"method"));i.putExtra("entry",value(l,"entry"));i.putExtra("codeOffset",value(l,"codeOffset"));}if(e!=null){if(i.getStringExtra("artifact")==null||i.getStringExtra("artifact").isEmpty())i.putExtra("artifact",value(e,"artifact","apk"));if(i.getStringExtra("class")==null||i.getStringExtra("class").isEmpty())i.putExtra("class",value(e,"class","className"));if(i.getStringExtra("method")==null||i.getStringExtra("method").isEmpty())i.putExtra("method",value(e,"method","methodName"));if(i.getStringExtra("entry")==null||i.getStringExtra("entry").isEmpty())i.putExtra("entry",value(e,"entry","path","file"));}return i;}
    private void showNavigation(JSONObject c){ArrayList<String> a=new ArrayList<>();JSONObject l=c.optJSONObject("locator");String blob=c.toString().toLowerCase(Locale.ROOT);if((l!=null&&!value(l,"class","method","artifact").isEmpty())||blob.contains(".dex"))a.add("Открыть в Decompiler");if((l!=null&&!value(l,"rva").isEmpty())||blob.contains("libil2cpp")||blob.contains(".so"))a.add("Открыть в Native");if((l!=null&&!value(l,"entry","artifact").isEmpty())||blob.contains("assets/")||blob.contains("res/"))a.add("Открыть файл / APK entry");a.add("Deep Resolve / RE Workspace");a.add("Копировать locator/evidence");a.add("Технические доказательства JSON");new AlertDialog.Builder(this).setTitle("Куда перейти").setItems(a.toArray(new String[0]),(d,w)->{String x=a.get(w);if(x.startsWith("Открыть в Decompiler"))startActivity(locatorIntent(DecompilerActivity.class,c));else if(x.startsWith("Открыть в Native"))startActivity(locatorIntent(NativeWorkspaceActivity.class,c));else if(x.startsWith("Открыть файл"))startActivity(locatorIntent(FileWorkspaceActivity.class,c));else if(x.startsWith("Deep Resolve")){Intent i=locatorIntent(ReWorkspaceActivity.class,c);i.putExtra("autoDeepResolve",true);startActivity(i);}else if(x.startsWith("Копировать"))copyRaw(c);else showRaw(c);}).show();}

    private void showDetails(JSONObject c){String title=c.optString("title","Находка");StringBuilder m=new StringBuilder();m.append(c.optString("description",""));m.append("\n\nСтатус: ").append(c.optString("status"));m.append("\nИсточник: ").append(c.optString("source"));m.append("\nКатегория: ").append(c.optString("category"));m.append("\nВладелец: ").append(c.optString("ownership","UNKNOWN"));m.append("\nПодтверждение: ").append(c.optString("verificationStage","FOUND_STATIC"));String rr=c.optString("readyReason","");String nr=c.optString("notReadyReason","");if(!rr.isEmpty())m.append("\nПочему подтверждено: ").append(rr);if(!nr.isEmpty())m.append("\nПочему ещё не Patch Ready: ").append(nr);
        String loc=location(c);if(!loc.isEmpty())m.append("\n\nГде найдено:\n").append(loc);JSONObject e=c.optJSONObject("evidence");if(e!=null){String trust=value(e,"trustBoundary");if(!trust.isEmpty())m.append("\nTrust boundary: ").append(trust);String pc=value(e,"presenceConfidence");String bc=value(e,"behaviorConfidence");String ac=value(e,"actionabilityConfidence");if(!pc.isEmpty()||!bc.isEmpty()||!ac.isEmpty())m.append("\nConfidence: presence ").append(pc).append(" · behavior ").append(bc).append(" · actionability ").append(ac);}
        if(c.optBoolean("serverAudit"))m.append("\n\nСерверная/аккаунтная граница: это defensive audit. ModKit не генерирует обход серверной проверки, платежей или экономики.");if(c.optBoolean("lowSignal"))m.append("\n\nНизкий приоритет: framework/SDK или слабая статическая связь.");
        AlertDialog dlg=new AlertDialog.Builder(this).setTitle(title).setMessage(m.toString()).setPositiveButton(android.R.string.ok,null).setNeutralButton("Открыть…",null).setNegativeButton("JSON",null).create();
        dlg.setOnShowListener(x->{dlg.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->showNavigation(c));dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->showRaw(c));});dlg.show();}
    private void showRaw(JSONObject c){TextView t=text(c.toString(),12);t.setTypeface(Typeface.MONOSPACE);t.setPadding(dp(14),dp(10),dp(14),dp(10));ScrollView s=new ScrollView(this);s.addView(t);new AlertDialog.Builder(this).setTitle("Технические доказательства JSON").setView(s).setPositiveButton(android.R.string.ok,null).show();}
    private void copyRaw(JSONObject c){android.content.ClipboardManager cm=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);cm.setPrimaryClip(android.content.ClipData.newPlainText("ModKit evidence",c.toString()));toast("JSON скопирован");}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(req==BUILD&&result==RESULT_OK&&data!=null&&data.getData()!=null)build(data.getData());}
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}

    private boolean modeMatch(JSONObject c,String mode){String stage=c.optString("verificationStage");String domain=c.optString("gameplayDomain");String own=c.optString("ownership");String blob=c.toString().toLowerCase(Locale.ROOT);if("Все".equals(mode))return true;if("Patch Ready".equals(mode))return c.optBoolean("patchReady")||"PATCH_READY".equals(stage);if("Gameplay".equals(mode))return !domain.isEmpty();if("HP / Health".equals(mode))return "health".equals(domain);if("Damage".equals(mode))return "damage".equals(domain);if("Speed".equals(mode))return "speed".equals(domain);if("Cooldown".equals(mode))return "cooldown".equals(domain);if("Currency".equals(mode))return "currency".equals(domain);if("Level / XP".equals(mode))return "level_xp".equals(domain);if("Inventory".equals(mode))return "inventory".equals(domain);if("Camera".equals(mode))return "camera".equals(domain);if("Movement".equals(mode))return "movement".equals(domain);if("Offline".equals(mode))return c.optBoolean("offlineCandidate");if("Network/API".equals(mode))return c.optBoolean("serverAudit")||blob.contains("endpoint")||blob.contains("http")||blob.contains("websocket")||blob.contains("retrofit")||blob.contains("okhttp")||blob.contains("grpc");if("Crypto/Keys".equals(mode))return blob.contains("crypto")||blob.contains("encrypt")||blob.contains("keystore")||blob.contains("secretkey")||blob.contains("certificate")||blob.contains("pinning");if("Authentication".equals(mode))return blob.contains("authentication")||blob.contains("session")||blob.contains("login")||blob.contains("oauth")||blob.contains("access token")||blob.contains("refresh token");if("Server Audit".equals(mode))return "SERVER_AUDIT".equals(stage)||c.optBoolean("serverAudit");if("Game code".equals(mode))return ("APP".equals(own)||"APP_OR_GAME".equals(own))&&!c.optBoolean("serverAudit");if("SDK".equals(mode))return "BUNDLED_SDK".equals(own);if("Framework noise".equals(mode))return "FRAMEWORK".equals(own);return true;}

    private final class CardAdapter extends RecyclerView.Adapter<CardHolder>{private final ArrayList<JSONObject> all=new ArrayList<>(),rows=new ArrayList<>();
        void set(JSONArray a){all.clear();for(int i=0;i<a.length();i++){JSONObject o=a.optJSONObject(i);if(o!=null)all.add(o);}applyFilter();}
        void applyFilter(){rows.clear();String mode=filter==null?"Важное":String.valueOf(filter.getSelectedItem());String q=search==null?"":search.getText().toString().trim().toLowerCase(Locale.ROOT);for(JSONObject c:all){if(!modeMatch(c,mode))continue;String hay=(c.optString("title")+" "+c.optString("description")+" "+c.optString("category")+" "+c.optString("source")+" "+c.optString("ownership")).toLowerCase(Locale.ROOT);if(!q.isEmpty()&&!hay.contains(q))continue;rows.add(c);}notifyDataSetChanged();if(shown!=null)shown.setText("Показано: "+rows.size()+" из "+all.size()+" · фильтр: "+mode);}
        @Override public CardHolder onCreateViewHolder(ViewGroup p,int type){LinearLayout box=new LinearLayout(SimpleModeActivity.this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(10),dp(8),dp(10),dp(8));CheckBox cb=new CheckBox(SimpleModeActivity.this);cb.setTextColor(Color.WHITE);box.addView(cb);TextView d=text("",12);d.setTextColor(Color.LTGRAY);box.addView(d);TextView meta=text("",11);meta.setTextColor(Color.GRAY);box.addView(meta);return new CardHolder(box,cb,d,meta);}
        @Override public void onBindViewHolder(CardHolder h,int pos){JSONObject c=rows.get(pos);String control=c.optString("menuControlId","");boolean ready=c.optBoolean("buildable")&&!control.isEmpty();h.cb.setText("["+c.optString("status")+"] "+c.optString("title")+" · "+c.optString("source"));h.desc.setText(c.optString("description"));String own=c.optString("ownership","UNKNOWN");h.meta.setText(own+(c.optBoolean("actionable")?" · точный locator":"")+(c.optBoolean("serverAudit")?" · server/trust audit":""));h.cb.setOnCheckedChangeListener(null);h.cb.setEnabled(ready);h.cb.setChecked(ready&&selected.contains(control));h.cb.setOnCheckedChangeListener((b,on)->{if(!ready)return;if(on)selected.add(control);else selected.remove(control);build.setEnabled(!app.busy.get()&&!selected.isEmpty());});h.itemView.setOnClickListener(v->showDetails(c));}
        @Override public int getItemCount(){return rows.size();}}
    private static final class CardHolder extends RecyclerView.ViewHolder{final CheckBox cb;final TextView desc,meta;CardHolder(View v,CheckBox c,TextView d,TextView m){super(v);cb=c;desc=d;meta=m;}}
}
