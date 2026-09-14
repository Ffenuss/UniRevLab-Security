package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import android.text.*;
import android.view.*;
import android.widget.*;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import org.json.*;
import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class MainActivity extends androidx.appcompat.app.AppCompatActivity {
    private App app;
    private LinearLayout root,list;
    private TextView status,files,summary,gameplay,applicationDiscovery,profile,steps,pageLabel;
    private Button metadata,library,game,installedGame,analyze,export,dumpExport,buildGame,report,cancel,prev,next,catalogToggle;
    private EditText search;
    private ProgressBar progress;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long revision=-1,deepStamp=-1;
    private JSONObject shown;
    private final Map<Integer,String> selected=new LinkedHashMap<>();
    private final ExecutorService rowExecutor=Executors.newSingleThreadExecutor();
    private final AtomicInteger rowGeneration=new AtomicInteger();
    private final Runnable searchDebounce=()->renderRows();
    private int page=0;
    private boolean fullCatalog=false;
    private final Runnable poll=new Runnable() { public void run() { refresh(); handler.postDelayed(this,350); } };
    private int dp(int n) { return (int)(n*getResources().getDisplayMetrics().density); }
    private boolean dark(){return (getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bgColor(){return dark()?Color.rgb(16,20,24):Color.rgb(244,247,251);}
    private int surfaceColor(){return dark()?Color.rgb(23,28,33):Color.WHITE;}
    private int textColor(){return dark()?Color.rgb(221,227,234):Color.rgb(25,40,62);}
    private int mutedColor(){return dark()?Color.rgb(158,170,181):Color.rgb(92,108,126);}
    private int outlineColor(){return dark()?Color.rgb(58,68,78):Color.rgb(216,224,233);}
    private int buttonColor(){return dark()?Color.rgb(39,54,59):Color.rgb(232,243,247);}
    private TextView text(String s,int size) {
        TextView t=new TextView(this); t.setText(s);t.setTextSize(size);t.setTextColor(textColor());
        t.setPadding(0,dp(6),0,dp(6)); return t;
    }
    private GradientDrawable rounded(int fill,int stroke,int radiusDp){
        GradientDrawable g=new GradientDrawable();g.setColor(fill);g.setCornerRadius(dp(radiusDp));if(stroke!=0)g.setStroke(dp(1),stroke);return g;
    }
    private LinearLayout section(String title){
        com.google.android.material.card.MaterialCardView outer=new com.google.android.material.card.MaterialCardView(this);outer.setCardBackgroundColor(surfaceColor());outer.setStrokeColor(outlineColor());outer.setStrokeWidth(dp(1));outer.setRadius(dp(18));outer.setCardElevation(dp(2));
        LinearLayout card=new LinearLayout(this);card.setOrientation(LinearLayout.VERTICAL);card.setPadding(dp(16),dp(12),dp(16),dp(16));outer.addView(card,new android.widget.FrameLayout.LayoutParams(-1,-2));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(7),0,dp(7));root.addView(outer,lp);
        TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);card.addView(h);return card;
    }
    private Button button(String s,LinearLayout target,View.OnClickListener action) {
        com.google.android.material.button.MaterialButton b=new com.google.android.material.button.MaterialButton(this);b.setText(s);b.setAllCaps(false);b.setTextColor(textColor());b.setBackgroundTintList(ColorStateList.valueOf(buttonColor()));target.addView(b);b.setOnClickListener(action);return b;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(28));
        root.setBackgroundColor(bgColor());scroll.addView(root);setContentView(scroll);
        TextView title=text(getString(R.string.app_name),32);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text(getString(R.string.app_subtitle),14));
        profile=text(getString(R.string.target_unknown),13);profile.setTypeface(null,Typeface.BOLD);profile.setPadding(dp(10),dp(7),dp(10),dp(7));profile.setBackground(rounded(dark()?Color.rgb(29,58,54):Color.rgb(226,243,239),0,12));root.addView(profile,new LinearLayout.LayoutParams(-1,-2));
        button(getString(R.string.how_it_works),root,v->new AlertDialog.Builder(this).setTitle(getString(R.string.pipeline_title))
            .setMessage(getString(R.string.pipeline_message))
            .setPositiveButton(getString(R.string.got_it),null).show());
        LinearLayout simple=section(getString(R.string.simple_section));
        button(getString(R.string.simple_button),simple,v->startActivity(new Intent(this,SimpleModeActivity.class)));
        simple.addView(text(getString(R.string.simple_note),13));

        LinearLayout nav=section(getString(R.string.navigation));
        button(getString(R.string.nav_discovery),nav,v->startActivity(new Intent(this,ReWorkspaceActivity.class)));
        button(getString(R.string.nav_probe),nav,v->startActivity(new Intent(this,MenuBuilderActivity.class).putExtra("focus","probe")));
        button(getString(R.string.nav_menu),nav,v->startActivity(new Intent(this,MenuBuilderActivity.class)));
        button(getString(R.string.nav_reports),nav,v->startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-analysis.json"),21));

        LinearLayout work=section(getString(R.string.workspaces));
        button(getString(R.string.workspace_decompiler),work,v->startActivity(new Intent(this,DecompilerActivity.class)));
        button(getString(R.string.workspace_files),work,v->startActivity(new Intent(this,FileWorkspaceActivity.class)));
        button(getString(R.string.workspace_re),work,v->startActivity(new Intent(this,ReWorkspaceActivity.class)));
        button(getString(R.string.workspace_native),work,v->startActivity(new Intent(this,NativeWorkspaceActivity.class)));
        button(getString(R.string.workspace_patch),work,v->startActivity(new Intent(this,PatchPackActivity.class)));
        button(getString(R.string.workspace_menu),work,v->startActivity(new Intent(this,MenuBuilderActivity.class)));

        LinearLayout source=section(getString(R.string.section_target));
        files=text("",14);source.addView(files);
        installedGame=button(getString(R.string.installed_apps_games),source,v->showInstalledApps());
        game=button(getString(R.string.choose_source_apk),source,v->pickApk());
        metadata=button(getString(R.string.advanced_metadata),source,v->pick(10));
        library=button(getString(R.string.advanced_library),source,v->pick(11));

        LinearLayout analysis=section(getString(R.string.section_analysis));
        analyze=button(getString(R.string.analyze_pair),analysis,v->start(new Intent().putExtra("op","analyze")));
        progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);progress.setMax(100);progress.setIndeterminate(true);analysis.addView(progress,new LinearLayout.LayoutParams(-1,dp(8)));
        steps=text("",13);analysis.addView(steps);
        status=text("",14);status.setTextIsSelectable(true);analysis.addView(status);
        cancel=button(getString(R.string.cancel_operation),analysis,v->{app.cancelled.set(true);app.progress(getString(R.string.cancelling));});
        summary=text("",14);analysis.addView(summary);
        applicationDiscovery=text("",13);applicationDiscovery.setTextIsSelectable(true);analysis.addView(applicationDiscovery);
        gameplay=text("",13);gameplay.setTextIsSelectable(true);analysis.addView(gameplay);
        report=button(getString(R.string.save_analysis_report),analysis,v->startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-analysis.json"),21));
        dumpExport=button(getString(R.string.save_rodroid_dump),analysis,v->startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"rodroid-full-dump.zip"),23));

        LinearLayout changes=section(getString(R.string.section_discovery));
        search=new EditText(this);search.setSingleLine(true);search.setHint(getString(R.string.search_evidence));changes.addView(search);
        search.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int f){} public void onTextChanged(CharSequence s,int a,int before,int count){page=0;handler.removeCallbacks(searchDebounce);handler.postDelayed(searchDebounce,250);} public void afterTextChanged(Editable e){}});
        catalogToggle=button(getString(R.string.catalog_off),changes,v->{fullCatalog=!fullCatalog;page=0;renderRows();refreshCatalogToggle();});
        list=new LinearLayout(this);list.setOrientation(LinearLayout.VERTICAL);changes.addView(list);
        LinearLayout pages=new LinearLayout(this);pages.setGravity(Gravity.CENTER_VERTICAL);changes.addView(pages);
        prev=button(getString(R.string.back),pages,v->{page=Math.max(0,page-1);renderRows();});
        pageLabel=text("",14);pages.addView(pageLabel);
        next=button(getString(R.string.next),pages,v->{page++;renderRows();});

        LinearLayout result=section(getString(R.string.section_result));
        export=button(getString(R.string.save_mod),result,v->prepareExport());
        buildGame=button(getString(R.string.build_apk_or_set),result,v->prepareGameBuild());
        result.addView(text(getString(R.string.result_note),13));
        if (Build.VERSION.SDK_INT>=33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS")!=android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},50);
        if(getIntent().getBooleanExtra("autoInstalledPicker",false))handler.postDelayed(this::showInstalledApps,250);
    }
    private void showInstalledApps() {
        PackageManager pm=getPackageManager();
        Intent q=new Intent(Intent.ACTION_MAIN);q.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> resolved=pm.queryIntentActivities(q,0);
        final ArrayList<ResolveInfo> all=new ArrayList<>();HashSet<String> seen=new HashSet<>();
        for(ResolveInfo r:resolved){if(r==null||r.activityInfo==null||r.activityInfo.applicationInfo==null)continue;String pkg=r.activityInfo.packageName;if(pkg==null||pkg.equals(getPackageName())||!seen.add(pkg))continue;all.add(r);}
        Collections.sort(all,(a,b)->String.valueOf(a.loadLabel(pm)).compareToIgnoreCase(String.valueOf(b.loadLabel(pm))));

        LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(14),dp(8),dp(14),0);
        EditText filter=new EditText(this);filter.setHint(getString(R.string.installed_search));filter.setSingleLine(true);box.addView(filter);
        LinearLayout filters=new LinearLayout(this);filters.setOrientation(LinearLayout.HORIZONTAL);box.addView(filters);
        final int[] mode={0};
        final ArrayList<ResolveInfo> visible=new ArrayList<>();
        final Map<String,Drawable> iconCache=new HashMap<>();
        final AlertDialog[] dialogRef=new AlertDialog[1];

        RecyclerView listView=new RecyclerView(this);
        listView.setLayoutManager(new LinearLayoutManager(this));
        listView.setHasFixedSize(false);
        box.addView(listView,new LinearLayout.LayoutParams(-1,dp(500)));

        class AppHolder extends RecyclerView.ViewHolder {
            final ImageView icon; final TextView name; final TextView meta;
            AppHolder(View item,ImageView icon,TextView name,TextView meta){super(item);this.icon=icon;this.name=name;this.meta=meta;}
        }
        RecyclerView.Adapter<AppHolder> adapter=new RecyclerView.Adapter<AppHolder>(){
            @Override public AppHolder onCreateViewHolder(android.view.ViewGroup parent,int viewType){
                LinearLayout row=new LinearLayout(MainActivity.this);row.setOrientation(LinearLayout.HORIZONTAL);row.setGravity(Gravity.CENTER_VERTICAL);row.setPadding(dp(8),dp(8),dp(8),dp(8));
                ImageView icon=new ImageView(MainActivity.this);row.addView(icon,new LinearLayout.LayoutParams(dp(44),dp(44)));
                LinearLayout words=new LinearLayout(MainActivity.this);words.setOrientation(LinearLayout.VERTICAL);words.setPadding(dp(12),0,0,0);row.addView(words,new LinearLayout.LayoutParams(0,-2,1));
                TextView name=text("",15);name.setTypeface(null,Typeface.BOLD);name.setPadding(0,0,0,dp(2));words.addView(name);
                TextView meta=text("",12);meta.setTextColor(mutedColor());meta.setPadding(0,0,0,0);words.addView(meta);
                return new AppHolder(row,icon,name,meta);
            }
            @Override public void onBindViewHolder(AppHolder holder,int position){
                ResolveInfo r=visible.get(position);ApplicationInfo ai=r.activityInfo.applicationInfo;String pkg=r.activityInfo.packageName,label=String.valueOf(r.loadLabel(pm));boolean isGame=Build.VERSION.SDK_INT>=26&&ai.category==ApplicationInfo.CATEGORY_GAME;
                Drawable d=iconCache.get(pkg);if(d==null){try{d=r.loadIcon(pm);if(d!=null)iconCache.put(pkg,d);}catch(Exception ignored){}}
                holder.icon.setImageDrawable(d);holder.name.setText(label);holder.meta.setText(pkg+" · "+getString(isGame?R.string.profile_game:R.string.profile_app));
                holder.itemView.setOnClickListener(v->{int p=holder.getBindingAdapterPosition();if(p==RecyclerView.NO_POSITION||p>=visible.size())return;ResolveInfo selected=visible.get(p);String selectedPkg=selected.activityInfo.packageName,selectedLabel=String.valueOf(selected.loadLabel(pm));if(dialogRef[0]!=null)dialogRef[0].dismiss();start(new Intent().putExtra("op","scan_installed").putExtra("package",selectedPkg).putExtra("label",selectedLabel));});
            }
            @Override public int getItemCount(){return visible.size();}
        };
        listView.setAdapter(adapter);

        final Runnable[] rebuild=new Runnable[1];
        rebuild[0]=()->{String needle=filter.getText().toString().trim().toLowerCase(Locale.ROOT);visible.clear();for(ResolveInfo r:all){String label=String.valueOf(r.loadLabel(pm)),pkg=r.activityInfo.packageName;boolean isGame=Build.VERSION.SDK_INT>=26&&r.activityInfo.applicationInfo.category==ApplicationInfo.CATEGORY_GAME;if(mode[0]==1&&!isGame)continue;if(mode[0]==2&&isGame)continue;if(!needle.isEmpty()&&!label.toLowerCase(Locale.ROOT).contains(needle)&&!pkg.toLowerCase(Locale.ROOT).contains(needle))continue;visible.add(r);}adapter.notifyDataSetChanged();};
        Button allBtn=button(getString(R.string.filter_all),filters,v->{mode[0]=0;rebuild[0].run();});Button gamesBtn=button(getString(R.string.filter_games),filters,v->{mode[0]=1;rebuild[0].run();});Button appsBtn=button(getString(R.string.filter_apps),filters,v->{mode[0]=2;rebuild[0].run();});
        LinearLayout.LayoutParams fp=new LinearLayout.LayoutParams(0,-2,1);allBtn.setLayoutParams(fp);gamesBtn.setLayoutParams(new LinearLayout.LayoutParams(0,-2,1));appsBtn.setLayoutParams(new LinearLayout.LayoutParams(0,-2,1));
        filter.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int d){}public void onTextChanged(CharSequence s,int a,int b,int c){rebuild[0].run();}public void afterTextChanged(Editable e){}});rebuild[0].run();

        dialogRef[0]=new AlertDialog.Builder(this).setTitle(getString(R.string.installed_apps_games)).setView(box).setNegativeButton(getString(R.string.cancel),null).create();
        dialogRef[0].show();
    }

    private void pick(int code) {
        startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),code);
    }
    private void pickApk() {startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE),12);}
    private void start(Intent intent) {
        synchronized(app) {
            if(!app.busy.compareAndSet(false,true)) return;
            app.cancelled.set(false);app.progress(getString(R.string.preparing));
        }
        intent.setClass(this,WorkerService.class);
        try { startForegroundService(intent); }
        catch(Exception e) {app.busy.set(false);app.progress(getString(R.string.failed_to_start,e.getMessage()));}
        refresh();
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK || data==null || data.getData()==null) return;
        Uri uri=data.getData();
        if(request==10 || request==11 || request==12) {
            String display=uri.getLastPathSegment();
            try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)) {
                if(c!=null && c.moveToFirst())display=c.getString(0);
            }catch(Exception ignored){}
            String local=request==10?"metadata.bin":request==11?"library.so":"game.apk";
            start(new Intent().putExtra("op","import").putExtra("uri",uri.toString()).putExtra("name",local).putExtra("display",display));
        } else if(request==21) {
            start(new Intent().putExtra("op","report").putExtra("uri",uri.toString()));
        } else if(request==20) {
            start(new Intent().putExtra("op","export").putExtra("uri",uri.toString()).putExtra("selections",selections().toString()));
        } else if(request==22) {
            start(new Intent().putExtra("op","build_apk").putExtra("uri",uri.toString()).putExtra("selections",selections().toString()));
        } else if(request==23) {
            start(new Intent().putExtra("op","dump").putExtra("uri",uri.toString()));
        }
    }
    private JSONArray selections() {
        JSONArray a=new JSONArray();
        for(Map.Entry<Integer,String> e:selected.entrySet())try {a.put(new JSONObject().put("id",e.getKey()).put("value",e.getValue()));}catch(JSONException ignored){}
        return a;
    }
    private void saveSelections() {export.setText(getString(R.string.save_mod)+" · "+selected.size());getSharedPreferences("state",0).edit().putString("selections",selections().toString()).apply();}
    private void prepareExport() {
        if(selected.isEmpty()) {new AlertDialog.Builder(this).setMessage(getString(R.string.select_at_least_one_method)).setPositiveButton(getString(R.string.got_it),null).show();return;}
        for(String value:selected.values())if(value.trim().isEmpty()){new AlertDialog.Builder(this).setMessage(getString(R.string.fill_all_method_values)).setPositiveButton(getString(R.string.got_it),null).show();return;}
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-result.zip"),20);
    }
    private boolean validateSelections() {
        if(selected.isEmpty()) {new AlertDialog.Builder(this).setMessage(getString(R.string.select_at_least_one_method)).setPositiveButton(getString(R.string.got_it),null).show();return false;}
        for(String value:selected.values())if(value.trim().isEmpty()){new AlertDialog.Builder(this).setMessage(getString(R.string.fill_all_method_values)).setPositiveButton(getString(R.string.got_it),null).show();return false;}
        return true;
    }
    private boolean installedTargetIsSet(){try{File f=app.file("installed-target.json");if(!f.isFile())return false;JSONObject t=new JSONObject(new String(Files.readAllBytes(f.toPath()),java.nio.charset.StandardCharsets.UTF_8));return "apk-set".equals(t.optString("buildMode"))&&t.optInt("copiedApkCount",0)>1;}catch(Exception ignored){return false;}}
    private void prepareGameBuild() {
        if(!app.file("game.apk").exists()){new AlertDialog.Builder(this).setMessage(getString(R.string.choose_target_first)).setPositiveButton(getString(R.string.got_it),null).show();return;}
        if(!validateSelections())return;boolean set=installedTargetIsSet();
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(set?"application/zip":"application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,set?"modkit-package-test.apks":"modkit-app-test.apk"),22);
    }
    private void refreshCatalogToggle(){if(catalogToggle==null)return;File f=app.file("analysis.methods.jsonl");catalogToggle.setEnabled(f.isFile()&&!app.busy.get());catalogToggle.setText(fullCatalog?getString(R.string.catalog_on):getString(R.string.catalog_off));}
    private JSONObject readJson(File f){try{return f.isFile()?new JSONObject(new String(Files.readAllBytes(f.toPath()),java.nio.charset.StandardCharsets.UTF_8)):null;}catch(Exception ignored){return null;}}
    private JSONObject targetProfileOf(JSONObject result){
        if(result!=null){JSONObject p=result.optJSONObject("targetProfile");if(p!=null&&p.length()>0)return p;JSONObject re=result.optJSONObject("reDiscovery");if(re!=null&&(p=re.optJSONObject("targetProfile"))!=null&&p.length()>0)return p;JSONObject scan=result.optJSONObject("installedScan");if(scan!=null&&(p=scan.optJSONObject("targetProfile"))!=null&&p.length()>0)return p;}
        JSONObject scan=readJson(app.file("installed-scan.json"));return scan==null?null:scan.optJSONObject("targetProfile");
    }
    private JSONObject applicationDiscoveryOf(JSONObject result){
        if(result!=null){JSONObject d=result.optJSONObject("applicationDiscovery");if(d!=null&&d.length()>0)return d;JSONObject re=result.optJSONObject("reDiscovery");if(re!=null&&(d=re.optJSONObject("applicationDiscovery"))!=null&&d.length()>0)return d;JSONObject scan=result.optJSONObject("installedScan");if(scan!=null&&(d=scan.optJSONObject("applicationDiscovery"))!=null&&d.length()>0)return d;}
        JSONObject scan=readJson(app.file("installed-scan.json"));return scan==null?null:scan.optJSONObject("applicationDiscovery");
    }
    private String appDiscoverySummary(JSONObject discovery){
        if(discovery==null)return "";
        JSONObject ss=discovery.optJSONObject("summary");JSONArray cards=discovery.optJSONArray("cards");
        StringBuilder b=new StringBuilder("Application Discovery");
        if(ss!=null)b.append(" · confirmed ").append(ss.optInt("confirmed")).append(" · review ").append(ss.optInt("review")).append(" · not found local ").append(ss.optInt("notFoundLocal"));
        if(cards!=null)for(int i=0;i<cards.length();i++){
            JSONObject c=cards.optJSONObject(i);if(c==null||"NOT_FOUND_LOCAL".equals(c.optString("status")))continue;
            b.append("\n• ").append(c.optString("title",c.optString("domain"))).append(" — ").append(c.optString("status","REVIEW")).append(" · trust ").append(c.optString("trustBoundary","unknown")).append(" · local authority ").append(c.optString("localAuthority","unknown"));
            JSONArray methods=c.optJSONArray("methods");if(methods!=null&&methods.length()>0){JSONObject m=methods.optJSONObject(0);if(m!=null)b.append("\n  ↳ ").append(m.optString("label"));}
        }
        b.append("\nStatic evidence only; presence ≠ vulnerability.");return b.toString();
    }
    private int stageIndex(String stage){String[] order={"INPUT","INVENTORY","ANALYSIS","DISCOVERY","PROBE","MENU","OUTPUT"};for(int i=0;i<order.length;i++)if(order[i].equals(stage))return i;return "DONE".equals(stage)?order.length:-1;}
    private String stepperText(String stage){
        String[] codes={"INPUT","INVENTORY","ANALYSIS","DISCOVERY","PROBE","MENU","OUTPUT"};String[] names={getString(R.string.step_input),getString(R.string.step_inventory),getString(R.string.step_analysis),getString(R.string.step_discovery),getString(R.string.step_probe),getString(R.string.step_menu),getString(R.string.step_output)};int active=stageIndex(stage);StringBuilder b=new StringBuilder();
        for(int i=0;i<codes.length;i++){if(i>0)b.append("  ");b.append(i<active?"✓":i==active?"●":"○").append(' ').append(names[i]);}
        if("STOPPED".equals(stage))b.append("\n⚠ ").append(getString(R.string.operation_stopped));return b.toString();
    }
    private void renderTargetProfile(JSONObject p){
        String type=p==null?"UNKNOWN":p.optString("profile","UNKNOWN");double confidence=p==null?0:p.optDouble("confidence",0);profile.setText(getString(R.string.target_label)+" · "+type+(confidence>0?" · "+String.format(Locale.US,"%.0f%%",confidence*100):""));int fill=dark()?("GAME".equals(type)?Color.rgb(31,45,67):"APPLICATION".equals(type)?Color.rgb(29,58,54):"HYBRID".equals(type)?Color.rgb(52,39,67):Color.rgb(42,48,55)):("GAME".equals(type)?Color.rgb(234,241,255):"APPLICATION".equals(type)?Color.rgb(226,243,239):"HYBRID".equals(type)?Color.rgb(239,232,250):Color.rgb(236,240,244));profile.setBackground(rounded(fill,0,12));
        if(search!=null){if("GAME".equals(type))search.setHint(getString(R.string.search_game));else if("APPLICATION".equals(type))search.setHint(getString(R.string.search_application));else if("HYBRID".equals(type))search.setHint(getString(R.string.search_hybrid));else search.setHint(getString(R.string.search_evidence));}
    }
    private String gameplaySummary(JSONObject discovery) {
        if(discovery==null)return "";
        JSONArray cards=discovery.optJSONArray("cards");if(cards==null)return "";
        StringBuilder b=new StringBuilder("Gameplay Discovery");
        for(int i=0;i<cards.length();i++){JSONObject c=cards.optJSONObject(i);if(c==null)continue;
            b.append("\n\n").append(c.optString("title",c.optString("domain"))).append(" — ").append(c.optString("status","REVIEW"));
            JSONArray f=c.optJSONArray("fields");if(f!=null)for(int j=0;j<Math.min(3,f.length());j++)b.append("\n• ").append(f.optString(j));
            JSONArray m=c.optJSONArray("methods");if(m!=null)for(int j=0;j<Math.min(3,m.length());j++)b.append("\n→ ").append(m.optString(j));
            if("health".equals(c.optString("domain"))&&!c.optBoolean("numericHpSetterAttributed"))b.append("\nNumeric HP setter: not attributed");
            int pc=c.optInt("packageCount",0);if(pc>0)b.append("\nPackage/content evidence: ").append(pc);
        }
        return b.toString();
    }
    private void refresh() {
        if(revision==app.revision)return;revision=app.revision;
        boolean busy=app.busy.get();status.setText(app.status);steps.setText(stepperText(app.stage));progress.setVisibility(busy?View.VISIBLE:View.GONE);cancel.setVisibility(busy?View.VISIBLE:View.GONE);
        if(busy&&app.stageProgress>=0){progress.setIndeterminate(false);progress.setProgress(app.stageProgress);}else progress.setIndeterminate(true);
        metadata.setEnabled(!busy);library.setEnabled(!busy);game.setEnabled(!busy);installedGame.setEnabled(!busy);analyze.setEnabled(!busy&&app.file("metadata.bin").exists()&&app.file("library.so").exists());
        boolean patchModelReady=app.file("analysis.json").isFile()&&app.file("library.so").isFile();
        export.setEnabled(!busy&&patchModelReady);dumpExport.setEnabled(!busy&&app.result!=null);buildGame.setEnabled(!busy&&patchModelReady);buildGame.setText(installedTargetIsSet()?getString(R.string.build_apk_set):getString(R.string.build_apk));report.setEnabled(!busy&&app.result!=null);refreshCatalogToggle();
        files.setText(getString(R.string.files_summary,getSharedPreferences("state",0).getString("metadata.bin",getString(R.string.not_selected)),getSharedPreferences("state",0).getString("library.so",getString(R.string.not_selected)),getSharedPreferences("state",0).getString("game.apk",getString(R.string.not_selected)),getSharedPreferences("state",0).getString("installed.package",getString(R.string.not_selected))));
        long currentDeepStamp=app.file("analysis-deep").lastModified();boolean deepChanged=deepStamp!=currentDeepStamp;deepStamp=currentDeepStamp;boolean resultChanged=shown!=app.result;
        if(resultChanged){shown=app.result;selected.clear();page=0;try{JSONArray saved=new JSONArray(getSharedPreferences("state",0).getString("selections","[]"));for(int i=0;i<saved.length();i++)selected.put(saved.getJSONObject(i).getInt("id"),saved.getJSONObject(i).getString("value"));}catch(Exception ignored){}renderRows();}else if(deepChanged&&fullCatalog&&!busy)renderRows();
        JSONObject tp=targetProfileOf(shown);renderTargetProfile(tp);JSONObject ad=applicationDiscoveryOf(shown);applicationDiscovery.setText(appDiscoverySummary(ad));applicationDiscovery.setVisibility(ad==null?View.GONE:View.VISIBLE);
        String profileType=tp==null?"UNKNOWN":tp.optString("profile","UNKNOWN");
        if(shown==null){summary.setText(getString(R.string.choose_target_summary));gameplay.setText("");}
        else if(shown.optBoolean("installedScanOnly")){
            JSONObject scan=shown.optJSONObject("installedScan"),rs=shown.optJSONObject("reDiscovery");JSONObject ss=scan==null?null:scan.optJSONObject("summary");String completeness=scan==null?"UNKNOWN":scan.optString("scanCompleteness","UNKNOWN");
            gameplay.setText("");
            summary.setText("Installed APK-set · "+(scan==null?"split-discovery":scan.optString("mode","split-discovery"))+" · Target "+profileType+
                "\nSplits: "+(ss==null?0:ss.optInt("splitCount"))+" · DEX: "+(ss==null?0:ss.optInt("dexCount"))+" · .so: "+(ss==null?0:ss.optInt("nativeCount"))+
                "\nCompleteness: "+completeness+" · IL2CPP pair: "+(scan!=null&&scan.optBoolean("fullIl2cppPair")?"READY":getString(R.string.pair_not_complete))+
                "\nRE findings: "+(rs==null?0:rs.optInt("findingCount"))+" · Review candidates: "+(rs==null?0:rs.optInt("controlCandidateCount"))+
                "\n"+("COMPLETE".equals(completeness)?getString(R.string.all_splits_scanned):getString(R.string.partial_scan_note)));
        }else{
            String gp=gameplaySummary(shown.optJSONObject("gameplayDiscovery"));gameplay.setText(gp);gameplay.setVisibility(("APPLICATION".equals(profileType)&&gp.isEmpty())?View.GONE:View.VISIBLE);
            JSONArray a=shown.optJSONArray("candidates");int candidateCount=a!=null?a.length():shown.optInt("candidate_count",0);JSONObject resolver=shown.optJSONObject("metadata_callable_resolution");
            String universal=resolver==null?"":("\nTyped resolver window: "+shown.optInt("metadata_callable_count",resolver.optInt("resolved"))+" · BL-observed "+resolver.optInt("direct_bl_observed")+" · structural ready "+resolver.optInt("structurally_ready")+" · instance resolvers "+resolver.optInt("instance_resolvers"));
            JSONObject fullCatalogStats=shown.optJSONObject("metadata_method_catalog");String fullLine=fullCatalogStats==null||!fullCatalogStats.optBoolean("available")?"":("\n"+getString(R.string.full_catalog_summary,fullCatalogStats.optInt("rows"),fullCatalogStats.optInt("addressConfirmed"),fullCatalogStats.optInt("directBlObserved"),fullCatalogStats.optInt("typedAbi")));
            summary.setText(getString(R.string.analysis_summary_head,profileType,shown.optInt("metadata_version"),shown.optInt("types"))+
                "\n"+getString(R.string.analysis_summary_methods,shown.optInt("methods"),shown.optInt("resolved"))+
                "\n"+getString(R.string.analysis_summary_candidates,candidateCount)+universal+fullLine+(candidateCount==0?"\n"+getString(R.string.reasons_header)+": "+reasons(shown.optJSONObject("unavailable")):"\n"+getString(R.string.catalogs_disk_note)));
        }
    }
    private String reasons(JSONObject obj) {
        if(obj==null)return getString(R.string.no_data);StringBuilder b=new StringBuilder();
        for(Iterator<String> it=obj.keys();it.hasNext();){String key=it.next();b.append("\n• ").append(key).append(": ").append(obj.optInt(key));}return b.toString();
    }
    private void renderRows() {
        if(list==null || next==null)return;
        export.setText(getString(R.string.save_mod)+" · "+selected.size());
        JSONArray all=shown==null?null:shown.optJSONArray("candidates"),found=shown==null?null:shown.optJSONArray("discoveries");
        File index=fullCatalog?app.file("analysis.methods.jsonl"):app.file("analysis.ui.jsonl");
        if(fullCatalog&& !index.isFile()){fullCatalog=false;refreshCatalogToggle();index=app.file("analysis.ui.jsonl");}
        String currentQuery=search.getText().toString().trim();
        if(fullCatalog && currentQuery.isEmpty() && index.isFile() && app.file("analysis.methods.jsonl.pages.idx").isFile()) {renderFullCatalogPage(index);return;}
        if(shown!=null && all==null && index.isFile()) {renderRowsFromIndex(index);return;}
        rowGeneration.incrementAndGet();
        List<JSONObject> matches=new ArrayList<>();
        String query=search.getText().toString().trim().toLowerCase(Locale.ROOT);
        addMatches(all,query,matches);addMatches(found,query,matches);
        int totalPages=Math.max(1,(matches.size()+29)/30);page=Math.min(page,totalPages-1);
        List<JSONObject> rows=new ArrayList<>();
        for(int i=page*30;i<Math.min(matches.size(),page*30+30);i++)rows.add(matches.get(i));
        showPage(rows,matches.size());
    }
    private void renderFullCatalogPage(File index) {
        final int generation=rowGeneration.incrementAndGet();
        final int requestedPage=page;
        JSONObject stats=shown==null?null:shown.optJSONObject("metadata_method_catalog");
        final int total=stats==null?0:stats.optInt("rows",0);
        final int pageSize=stats==null?30:Math.max(1,stats.optInt("pageSize",30));
        final File offsets=app.file("analysis.methods.jsonl.pages.idx");
        list.removeAllViews();list.addView(text(getString(R.string.catalog_page_loading),14));
        prev.setEnabled(false);next.setEnabled(false);
        rowExecutor.execute(()->{
            List<JSONObject> rows=new ArrayList<>();String error=null;
            try(RandomAccessFile idx=new RandomAccessFile(offsets,"r")){
                long slot=(long)requestedPage*8L;
                if(slot+8L<=idx.length()){
                    idx.seek(slot);long byteOffset=idx.readLong();
                    try(FileInputStream fis=new FileInputStream(index)){
                        fis.getChannel().position(byteOffset);
                        try(BufferedReader reader=new BufferedReader(new InputStreamReader(fis,java.nio.charset.StandardCharsets.UTF_8),128*1024)){
                            String line;int count=0;
                            while(count<pageSize && (line=reader.readLine())!=null){
                                if(generation!=rowGeneration.get())return;
                                if(!line.trim().isEmpty()){rows.add(new JSONObject(line));count++;}
                            }
                        }
                    }
                }
            }catch(Exception e){error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            final String failure=error;
            handler.post(()->{
                if(generation!=rowGeneration.get())return;
                if(failure!=null){list.removeAllViews();list.addView(text(getString(R.string.catalog_page_error,failure),14));pageLabel.setText(" 1 / 1 ");return;}
                int maxPage=Math.max(0,(total-1)/pageSize);
                if(page>maxPage){page=maxPage;renderRows();return;}
                showPage(rows,total);
            });
        });
    }

    private long searchHash(String token){
        long h=0xcbf29ce484222325L;byte[] bytes=token.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for(byte b:bytes){h^=(long)(b&0xff);h*=0x100000001b3L;}return h;
    }
    private List<String> searchIndexTokens(String query){
        String raw=query==null?"":query.trim();if(raw.isEmpty())return Collections.emptyList();
        String camel=raw.replaceAll("([a-z0-9])([A-Z])","$1 $2").toLowerCase(Locale.ROOT);
        LinkedHashSet<String> out=new LinkedHashSet<>();StringBuilder compact=new StringBuilder();
        for(String w:camel.split("[^a-z0-9]+")){if(w.length()>=2&&w.length()<=64){out.add(w);compact.append(w);}}
        if(!raw.matches(".*\\s+.*")&&compact.length()>=3&&compact.length()<=64)out.add(compact.toString());
        return new ArrayList<>(out);
    }
    private Set<Integer> indexedMethodIds(File searchIndex,String query)throws IOException{
        List<String> tokens=searchIndexTokens(query);if(tokens.isEmpty())return null;
        try(RandomAccessFile raf=new RandomAccessFile(searchIndex,"r")){
            byte[] magic=new byte[8];raf.readFully(magic);if(!"MKSIDX1\u0000".equals(new String(magic,java.nio.charset.StandardCharsets.ISO_8859_1)))return null;
            int buckets=raf.readInt(),recordSize=raf.readInt();if(buckets<=0||(buckets&(buckets-1))!=0||recordSize!=12)return null;
            long[] offsets=new long[buckets+1];for(int i=0;i<offsets.length;i++)offsets[i]=raf.readLong();
            Set<Integer> current=null;
            for(String token:tokens){long h=searchHash(token);int bucket=(int)(h&(buckets-1));long pos=offsets[bucket],end=offsets[bucket+1];HashSet<Integer> ids=new HashSet<>();raf.seek(pos);
                while(raf.getFilePointer()+12<=end){long rh=raf.readLong();int id=raf.readInt();if(rh==h)ids.add(id);}
                if(current==null)current=ids;else current.retainAll(ids);if(current.isEmpty())return current;
            }
            return current;
        }
    }
    private String readUtf8Line(RandomAccessFile file,long offset)throws IOException{
        file.seek(offset);ByteArrayOutputStream out=new ByteArrayOutputStream(1024);int b;
        while((b=file.read())!=-1&&b!='\n'){out.write(b);if(out.size()>1024*1024)throw new IOException("catalog row too large");}
        return out.toString(java.nio.charset.StandardCharsets.UTF_8.name());
    }
    private JSONObject catalogRowById(RandomAccessFile catalog,RandomAccessFile dense,int id)throws Exception{
        if(id<0)return null;long slot=(long)id*8L;if(slot+8L>dense.length())return null;dense.seek(slot);long off=dense.readLong();if(off==-1L||off<0||off>=catalog.length())return null;
        String line=readUtf8Line(catalog,off);return line.trim().isEmpty()?null:new JSONObject(line);
    }
    private boolean renderRowsFromSearchIndex(File index,final int generation,final int requestedPage,final String query,final JSONObject aliases){
        final File searchIndex=app.file("analysis.methods.jsonl.search.idx"),denseIndex=app.file("analysis.methods.jsonl.idx");
        if(!fullCatalog||!searchIndex.isFile()||!denseIndex.isFile()||query.isEmpty())return false;
        rowExecutor.execute(()->{
            List<JSONObject> rows=new ArrayList<>();String error=null;int total=0;boolean fallback=false;
            try{
                Set<Integer> candidateSet=indexedMethodIds(searchIndex,query);
                if(candidateSet==null||candidateSet.isEmpty()||candidateSet.size()>25000){fallback=true;}
                else{
                    ArrayList<Integer> ids=new ArrayList<>(candidateSet);Collections.sort(ids);ArrayList<Integer> direct=new ArrayList<>(),semantic=new ArrayList<>();
                    try(RandomAccessFile catalog=new RandomAccessFile(index,"r");RandomAccessFile dense=new RandomAccessFile(denseIndex,"r")){
                        int checked=0;for(int id:ids){if((++checked&127)==0&&generation!=rowGeneration.get())return;JSONObject o=catalogRowById(catalog,dense,id);if(o==null)continue;int rank=matchRank(query,o,aliases);if(rank==2)direct.add(id);else if(rank==1)semantic.add(id);}
                        total=direct.size()+semantic.size();int first=requestedPage*30,last=first+30;int pos=0;
                        for(int id:direct){if(pos>=first&&pos<last){JSONObject o=catalogRowById(catalog,dense,id);if(o!=null)rows.add(o);}pos++;if(pos>=last)break;}
                        if(pos<last){for(int id:semantic){if(pos>=first&&pos<last){JSONObject o=catalogRowById(catalog,dense,id);if(o!=null)rows.add(o);}pos++;if(pos>=last)break;}}
                    }
                }
            }catch(Exception e){fallback=true;error=null;}
            final int matchCount=total;final String failure=error;final boolean useFallback=fallback;
            handler.post(()->{
                if(generation!=rowGeneration.get())return;
                if(useFallback){renderRowsFromIndexLinear(index,generation,requestedPage,query,aliases);return;}
                if(failure!=null){list.removeAllViews();list.addView(text(getString(R.string.catalog_read_error,failure),14));pageLabel.setText(" 1 / 1 ");return;}
                int maxPage=Math.max(0,(matchCount-1)/30);if(page>maxPage){page=maxPage;renderRows();return;}showPage(rows,matchCount);
            });
        });return true;
    }

    private void renderRowsFromIndex(File index) {
        final int generation=rowGeneration.incrementAndGet();
        final int requestedPage=page;
        final String query=search.getText().toString().trim().toLowerCase(Locale.ROOT);
        final JSONObject aliases=shown==null?null:shown.optJSONObject("semantic_categories");
        list.removeAllViews();list.addView(text(getString(R.string.catalog_searching),14));
        prev.setEnabled(false);next.setEnabled(false);
        if(renderRowsFromSearchIndex(index,generation,requestedPage,query,aliases))return;
        renderRowsFromIndexLinear(index,generation,requestedPage,query,aliases);
    }
    private void renderRowsFromIndexLinear(File index, final int generation, final int requestedPage, final String query, final JSONObject aliases) {
        rowExecutor.execute(()->{
            List<JSONObject> rows=new ArrayList<>();int directCount=0,semanticCount=0;String error=null;
            try(BufferedReader reader=new BufferedReader(new InputStreamReader(new FileInputStream(index),java.nio.charset.StandardCharsets.UTF_8),128*1024)){
                String line;int scanned=0;
                while((line=reader.readLine())!=null){
                    if((++scanned&255)==0 && generation!=rowGeneration.get())return;
                    JSONObject o=new JSONObject(line);int rank=matchRank(query,o,aliases);
                    if(rank==2)directCount++;else if(rank==1)semanticCount++;
                }
            }catch(Exception e){error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            int total=directCount+semanticCount;int first=requestedPage*30,last=first+30;
            if(error==null&&total>0){
                try(BufferedReader reader=new BufferedReader(new InputStreamReader(new FileInputStream(index),java.nio.charset.StandardCharsets.UTF_8),128*1024)){
                    String line;int scanned=0,di=0,si=0;
                    while((line=reader.readLine())!=null){
                        if((++scanned&255)==0 && generation!=rowGeneration.get())return;
                        JSONObject o=new JSONObject(line);int rank=matchRank(query,o,aliases);int pos=-1;
                        if(rank==2)pos=di++;else if(rank==1)pos=directCount+(si++);
                        if(pos>=first&&pos<last)rows.add(o);
                    }
                }catch(Exception e){error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            }
            final int matchCount=total;final String failure=error;
            handler.post(()->{
                if(generation!=rowGeneration.get())return;
                if(failure!=null){list.removeAllViews();list.addView(text(getString(R.string.catalog_read_error,failure),14));pageLabel.setText(" 1 / 1 ");return;}
                int maxPage=Math.max(0,(matchCount-1)/30);
                if(page>maxPage){page=maxPage;renderRows();return;}
                showPage(rows,matchCount);
            });
        });
    }
    private JSONObject deepResult(int id) {
        File f=new File(app.file("analysis-deep"),"method-"+id+".json");
        if(!f.isFile())return null;
        try{return new JSONObject(new String(Files.readAllBytes(f.toPath()),java.nio.charset.StandardCharsets.UTF_8));}catch(Exception ignored){return null;}
    }
    private String deepSummary(JSONObject d) {
        if(d==null)return "";StringBuilder b=new StringBuilder("\nDeep Resolver: ").append(d.optString("decision","review"));
        JSONObject sem=d.optJSONObject("semantic"),ctx=d.optJSONObject("contextVerification"),menu=d.optJSONObject("menuEligibility");
        if(sem!=null)b.append(" · semantic ").append(sem.optBoolean("verified")?"OK":"REVIEW").append("/").append(String.format(Locale.US,"%.2f",sem.optDouble("confidence",0)));
        if(ctx!=null)b.append(" · context ").append(ctx.optBoolean("verified")?"OK":"REVIEW").append("/").append(String.format(Locale.US,"%.2f",ctx.optDouble("confidence",0)));
        JSONArray direct=d.optJSONArray("incomingDirectCalls"),thunk=d.optJSONArray("incomingThunkCalls"),indirect=d.optJSONArray("incomingIndirectCalls"),virtExact=d.optJSONArray("incomingVirtualCalls"),virt=d.optJSONArray("incomingVirtualCandidates"),slots=d.optJSONArray("functionPointerSlots");
        b.append("\nDeep xrefs: direct ").append(direct==null?0:direct.length()).append(" · thunk ").append(thunk==null?0:thunk.length()).append(" · BLR ").append(indirect==null?0:indirect.length()).append(" · virtual exact ").append(virtExact==null?0:virtExact.length()).append(" · virtual/review ").append(virt==null?0:virt.length()).append(" · ptr slots ").append(slots==null?0:slots.length());
        JSONObject mc=d.optJSONObject("methodContext");if(mc!=null){JSONArray out=mc.optJSONArray("outgoingManagedCalls"),outi=mc.optJSONArray("outgoingIndirectCalls"),str=mc.optJSONArray("stringRefs"),fld=mc.optJSONArray("thisOffsetCandidates");b.append("\nDeep context: outgoing BL ").append(out==null?0:out.length()).append(" · outgoing BLR ").append(outi==null?0:outi.length()).append(" · strings ").append(str==null?0:str.length()).append(" · this+offset ").append(fld==null?0:fld.length());}
        JSONObject cache=d.optJSONObject("cache");if(cache!=null)b.append(" · cache ").append(cache.optBoolean("hit")?"HIT":"MISS");
        JSONObject resolver=d.optJSONObject("verifiedInstanceResolver");if(resolver!=null)b.append("\nInstance resolver: VERIFIED · ").append(resolver.optString("label")).append(" @0x").append(Long.toHexString(resolver.optLong("rva")));
        if(menu!=null)b.append("\nMenu gate: ").append(menu.optBoolean("eligible")?"CANDIDATE":"BLOCKED").append(menu.optString("blocker","").isEmpty()?"":" · "+menu.optString("blocker"));
        JSONObject runtime=d.optJSONObject("runtimeTruth");if(runtime!=null)b.append(" · runtime ").append(runtime.optString("status","not-observed"));
        return b.toString();
    }
    private void showPage(List<JSONObject> rows,int matchCount) {
        list.removeAllViews();
        int totalPages=Math.max(1,(matchCount+29)/30);page=Math.min(page,totalPages-1);
        pageLabel.setText(" "+(page+1)+" / "+totalPages+" ");prev.setEnabled(page>0);next.setEnabled(page+1<totalPages);
        if(rows.isEmpty()){list.addView(text(shown==null?getString(R.string.methods_after_analysis):getString(R.string.no_methods_query),14));return;}
        for(JSONObject o:rows) {
            int id=o.optInt("id");
            LinearLayout card=new LinearLayout(this);card.setOrientation(LinearLayout.VERTICAL);card.setPadding(dp(8),dp(8),dp(8),dp(12));list.addView(card);
            boolean selectable=o.optBoolean("selectable",false);boolean catalogOnly=o.optBoolean("catalog_only",false);
            CheckBox check=null;
            if(selectable&&!catalogOnly){check=new CheckBox(this);check.setText(o.optString("label"));check.setChecked(selected.containsKey(id));card.addView(check);}
            else{TextView h=text(o.optString("label"),16);h.setTypeface(null,Typeface.BOLD);card.addView(h);}
            String address=o.isNull("rva")||!o.has("rva")?getString(R.string.without_rva):"RVA 0x"+Long.toHexString(o.optLong("rva"));
            StringBuilder details=new StringBuilder(o.optString("image")+" · "+o.optString("kind")+" · "+address);
            if(o.optJSONArray("semantic")!=null)details.append(" · ").append(o.optJSONArray("semantic").toString());
            String provenance=o.optString("provenance","");if(!provenance.isEmpty())details.append("\nProvenance: ").append(provenance);if(catalogOnly){details.append("\nMetadata: id ").append(o.optInt("metadata_method_id",id)).append(" · token 0x").append(Integer.toHexString(o.optInt("metadata_token",0))).append(" · args ").append(o.optInt("arity",0));details.append("\nMapping: ").append(o.optString("resolution","review"));if(o.optBoolean("generic"))details.append(" · generic");if(o.optBoolean("abstract"))details.append(" · abstract");}
            JSONObject mv=o.optJSONObject("method_verification");if(mv!=null){details.append("\nVerification: ").append(mv.optString("confirmationLevel","review"));if(mv.has("structuralConfidence"))details.append(" · ").append(String.format(java.util.Locale.US,"%.2f",mv.optDouble("structuralConfidence")));details.append(" · address ").append(mv.optBoolean("addressConfirmed")?"OK":"REVIEW").append(" · ABI ").append(mv.optBoolean("abiConfirmed")?"OK":"REVIEW");if(!mv.optString("relationStatus","").isEmpty())details.append(" · xref ").append(mv.optString("relationStatus"));details.append(" · runtime ").append(mv.optString("runtimeStatus","not-observed"));}
            if(!o.optString("method_role","").isEmpty())details.append("\nMethod role: ").append(o.optString("method_role"));if(o.optInt("static_incoming_direct_bl_count",0)>0)details.append("\nNative relation: ").append(o.optInt("static_incoming_direct_bl_count")).append(" direct BL").append(o.has("static_first_call_rva")&&!o.isNull("static_first_call_rva")?" · first call 0x"+Long.toHexString(o.optLong("static_first_call_rva")):"");if(!o.optString("discovery_reason","").isEmpty())details.append("\nDiscovery: ").append(o.optString("discovery_reason"));
            if(o.has("is_static")){
                details.append("\nABI: ").append(o.optBoolean("is_static")?"static":"instance").append(" · ").append(o.optString("return_type",o.optString("kind"))).append("(");
                JSONArray ps=o.optJSONArray("parameter_types");if(ps!=null)for(int pi=0;pi<ps.length();pi++){if(pi>0)details.append(", ");details.append(ps.optString(pi,"?"));}details.append(")");
                String bind=o.optString("binding_suggestion","");if(!bind.isEmpty())details.append(" · binding ").append(bind);
            }
            String reason=matchReason(search.getText().toString().trim().toLowerCase(Locale.ROOT),o,shown==null?null:shown.optJSONObject("semantic_categories"));if(!reason.isEmpty())details.append("\n").append(getString(R.string.matched_prefix)).append(": ").append(reason);
            if(!selectable&&!o.optString("unavailable_reason","").isEmpty())details.append("\nReview: ").append(o.optString("unavailable_reason"));
            JSONObject deep=catalogOnly?deepResult(o.optInt("metadata_method_id",id)):null;
            if(catalogOnly){details.append("\n").append(getString(R.string.full_catalog_evidence_note));details.append(deepSummary(deep));}
            card.addView(text(details.toString(),12));
            if(catalogOnly){
                Button inspect=button(deep==null?getString(R.string.deep_check_method):getString(R.string.deep_repeat),card,v->start(new Intent().putExtra("op","deep_method").putExtra("method_id",o.optInt("metadata_method_id",id))));
                inspect.setEnabled(!app.busy.get());
                continue;
            }
            if(!selectable){card.addView(text(getString(R.string.evidence_only_not_patchable),12));continue;}
            final CheckBox patchCheck=check;
            EditText input=new EditText(this);input.setSingleLine(true);input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER|android.text.InputType.TYPE_NUMBER_FLAG_SIGNED|android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL);input.setHint(o.optString("kind").equals("bool")?getString(R.string.bool_hint):getString(R.string.number_hint));input.setText(selected.getOrDefault(id,"1"));input.setEnabled(patchCheck!=null&&patchCheck.isChecked());card.addView(input);
            patchCheck.setOnCheckedChangeListener((b,on)->{input.setEnabled(on);if(on)selected.put(id,input.getText().toString());else selected.remove(id);saveSelections();});
            input.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int f){}public void onTextChanged(CharSequence s,int a,int b,int c){if(patchCheck.isChecked()){selected.put(id,s.toString());saveSelections();}}public void afterTextChanged(Editable e){}});
        }
    }
    private void addMatches(JSONArray source,String query,List<JSONObject> out) {
        if(source==null)return;
        JSONObject aliases=shown==null?null:shown.optJSONObject("semantic_categories");
        for(int i=0;i<source.length();i++){
            JSONObject o=source.optJSONObject(i);if(o==null)continue;
            if(query.isEmpty()||wordMatch(query,o,aliases))out.add(o);
        }
    }
    private boolean wordMatch(String query,JSONObject o,JSONObject aliases) {return matchRank(query,o,aliases)>0;}
    private int matchRank(String query,JSONObject o,JSONObject aliases) {
        if(isSystem(o,query))return 0;if(query==null||query.isEmpty())return 2;
        String probe=o.optString("label")+" "+o.optString("image")+" "+o.optString("method_role")+" "+o.optString("resolution")+" "+o.optString("provenance");if(o.has("rva")&&!o.isNull("rva"))probe+=" 0x"+Long.toHexString(o.optLong("rva"));if(o.has("metadata_token"))probe+=" 0x"+Integer.toHexString(o.optInt("metadata_token"));Set<String> direct=words(probe);boolean allDirect=true;
        for(String part:query.split("\\s+"))if(!direct.contains(part)){allDirect=false;break;}if(allDirect)return 2;
        Set<String> tags=new HashSet<>();JSONArray ts=o.optJSONArray("semantic");if(ts!=null)for(int i=0;i<ts.length();i++)tags.add(ts.optString(i).toLowerCase(Locale.ROOT));
        if(aliases!=null){for(Iterator<String> it=aliases.keys();it.hasNext();){String category=it.next().toLowerCase(Locale.ROOT);JSONArray a=aliases.optJSONArray(category);if(category.equals(query)&&tags.contains(category))return 1;if(a!=null)for(int i=0;i<a.length();i++)if(query.equals(a.optString(i).toLowerCase(Locale.ROOT))&&tags.contains(category))return 1;}}
        boolean allTags=true;for(String part:query.split("\\s+"))if(!tags.contains(part)){allTags=false;break;}return allTags?1:0;
    }
    private String matchReason(String query,JSONObject o,JSONObject aliases){int rank=matchRank(query,o,aliases);if(rank==2)return query==null||query.isEmpty()?getString(R.string.match_catalog):getString(R.string.match_exact);if(rank==1){JSONArray ts=o.optJSONArray("semantic");return getString(R.string.match_semantic)+(ts!=null?" "+ts.toString():"");}return "";}
    private boolean isSystem(JSONObject o,String query){if(o.optBoolean("catalog_only",false))return false;String image=o.optString("image").toLowerCase(Locale.ROOT);return !query.contains("system")&&(image.startsWith("system")||image.startsWith("mscorlib")||image.startsWith("unityengine"));}
    private Set<String> words(String value) {
        String split=value.replaceAll("([a-z0-9])([A-Z])","$1 $2").toLowerCase(Locale.ROOT);
        Set<String> result=new HashSet<>();for(String x:split.split("[^a-z0-9]+"))if(!x.isEmpty())result.add(x);return result;
    }
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}
    @Override protected void onDestroy(){handler.removeCallbacks(searchDebounce);rowGeneration.incrementAndGet();rowExecutor.shutdownNow();super.onDestroy();}
}
