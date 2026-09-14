package dev.modkit.mobile;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.database.Cursor;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;

/** One target selector shared by automatic and full modes. Selection never runs analysis. */
public class TargetSelectionActivity extends AppCompatActivity {
    private static final int PICK_APK=910;
    private App app;
    private TextView status;
    private MaterialButton installed,apk,cancel;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private boolean waiting=false;
    private String waitingKind="";
    private long waitStarted=0L;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}
    private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}
    private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}
    private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));return t;}
    private MaterialButton button(String label,LinearLayout box,View.OnClickListener click){MaterialButton b=new MaterialButton(this);b.setText(label);b.setAllCaps(false);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(action()));b.setOnClickListener(click);box.addView(b);return b;}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("Выбор приложения / APK",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        TextView note=text("Target выбирается один раз. Здесь ModKit только копирует APK/APK-set; сам анализ начнётся после возврата и выполнится ровно один раз.",13);note.setTextColor(muted());root.addView(note);
        installed=button("Установленное приложение / игра",root,v->showInstalledApps());
        apk=button("Выбрать APK файл",root,v->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE),PICK_APK));
        cancel=button("Отмена",root,v->{if(app.busy.get()){app.cancelled.set(true);app.progress("Отмена подготовки target…");}else{setResult(RESULT_CANCELED);finish();}});
        status=text("Выберите источник.",14);status.setTextIsSelectable(true);root.addView(status);
        handler.post(poll);
    }

    private final Runnable poll=new Runnable(){public void run(){
        if(waiting){
            status.setText(app.status==null?"":app.status);
            setButtons(false);
            if(!app.busy.get()&&System.currentTimeMillis()-waitStarted>300){
                boolean ready="installed".equals(waitingKind)?app.file("installed-target.json").isFile():app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile();
                if(ready){Intent out=new Intent().putExtra("targetKind",waitingKind);setResult(RESULT_OK,out);finish();return;}
                waiting=false;setButtons(true);status.setText("Target не подготовлен: "+(app.status==null?"неизвестная ошибка":app.status));
            }
        }
        handler.postDelayed(this,350);
    }};

    private void setButtons(boolean enabled){installed.setEnabled(enabled);apk.setEnabled(enabled);cancel.setEnabled(true);}
    private void startPreparation(Intent i,String kind){
        if(!app.busy.compareAndSet(false,true)){toast("Сейчас выполняется другая операция");return;}
        waiting=true;waitingKind=kind;waitStarted=System.currentTimeMillis();app.cancelled.set(false);app.progress("Подготовка target без анализа…");i.setClass(this,TargetPreparationService.class);
        try{startForegroundService(i);}catch(Exception e){app.busy.set(false);waiting=false;setButtons(true);status.setText("Не удалось запустить подготовку target: "+e.getMessage());}
    }

    private void showInstalledApps(){
        PackageManager pm=getPackageManager();Intent q=new Intent(Intent.ACTION_MAIN);q.addCategory(Intent.CATEGORY_LAUNCHER);ArrayList<ResolveInfo> all=new ArrayList<>();HashSet<String> seen=new HashSet<>();
        for(ResolveInfo r:pm.queryIntentActivities(q,0)){if(r==null||r.activityInfo==null||r.activityInfo.applicationInfo==null)continue;String pkg=r.activityInfo.packageName;if(pkg==null||pkg.equals(getPackageName())||!seen.add(pkg))continue;all.add(r);}Collections.sort(all,(a,b)->String.valueOf(a.loadLabel(pm)).compareToIgnoreCase(String.valueOf(b.loadLabel(pm))));
        ArrayList<ResolveInfo> visible=new ArrayList<>(all);LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(12),dp(8),dp(12),0);EditText search=new EditText(this);search.setHint("Поиск по названию или package");search.setSingleLine(true);box.addView(search);
        LinearLayout filters=new LinearLayout(this);filters.setOrientation(LinearLayout.HORIZONTAL);box.addView(filters);final int[] mode={0};
        ListView list=new ListView(this);box.addView(list,new LinearLayout.LayoutParams(-1,dp(500)));final AlertDialog[] ref=new AlertDialog[1];
        BaseAdapter adapter=new BaseAdapter(){
            @Override public int getCount(){return visible.size();}@Override public Object getItem(int p){return visible.get(p);}@Override public long getItemId(int p){return p;}
            @Override public View getView(int p,View convert,ViewGroup parent){LinearLayout row;if(convert instanceof LinearLayout)row=(LinearLayout)convert;else{row=new LinearLayout(TargetSelectionActivity.this);row.setOrientation(LinearLayout.HORIZONTAL);row.setGravity(Gravity.CENTER_VERTICAL);row.setPadding(dp(8),dp(7),dp(8),dp(7));ImageView icon=new ImageView(TargetSelectionActivity.this);icon.setId(android.R.id.icon);row.addView(icon,new LinearLayout.LayoutParams(dp(44),dp(44)));LinearLayout words=new LinearLayout(TargetSelectionActivity.this);words.setId(android.R.id.content);words.setOrientation(LinearLayout.VERTICAL);words.setPadding(dp(12),0,0,0);row.addView(words,new LinearLayout.LayoutParams(0,-2,1));TextView name=text("",15);name.setId(android.R.id.text1);name.setTypeface(null,Typeface.BOLD);words.addView(name);TextView meta=text("",12);meta.setId(android.R.id.text2);meta.setTextColor(muted());words.addView(meta);}ResolveInfo r=visible.get(p);ApplicationInfo ai=r.activityInfo.applicationInfo;ImageView icon=row.findViewById(android.R.id.icon);TextView name=row.findViewById(android.R.id.text1);TextView meta=row.findViewById(android.R.id.text2);try{Drawable d=r.loadIcon(pm);icon.setImageDrawable(d);}catch(Exception ignored){}boolean game=Build.VERSION.SDK_INT>=26&&ai.category==ApplicationInfo.CATEGORY_GAME;name.setText(String.valueOf(r.loadLabel(pm)));meta.setText(r.activityInfo.packageName+" · "+(game?"GAME":"APP"));return row;}
        };list.setAdapter(adapter);
        Runnable rebuild=()->{String needle=search.getText().toString().trim().toLowerCase(Locale.ROOT);visible.clear();for(ResolveInfo r:all){ApplicationInfo ai=r.activityInfo.applicationInfo;boolean game=Build.VERSION.SDK_INT>=26&&ai.category==ApplicationInfo.CATEGORY_GAME;if(mode[0]==1&&!game)continue;if(mode[0]==2&&game)continue;String label=String.valueOf(r.loadLabel(pm));String pkg=r.activityInfo.packageName;if(!needle.isEmpty()&&!label.toLowerCase(Locale.ROOT).contains(needle)&&!pkg.toLowerCase(Locale.ROOT).contains(needle))continue;visible.add(r);}adapter.notifyDataSetChanged();};
        MaterialButton allBtn=button("Все",filters,v->{mode[0]=0;rebuild.run();});MaterialButton gamesBtn=button("Игры",filters,v->{mode[0]=1;rebuild.run();});MaterialButton appsBtn=button("Приложения",filters,v->{mode[0]=2;rebuild.run();});allBtn.setLayoutParams(new LinearLayout.LayoutParams(0,-2,1));gamesBtn.setLayoutParams(new LinearLayout.LayoutParams(0,-2,1));appsBtn.setLayoutParams(new LinearLayout.LayoutParams(0,-2,1));
        search.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int b,int c){}public void onTextChanged(CharSequence s,int a,int b,int c){rebuild.run();}public void afterTextChanged(android.text.Editable e){}});
        list.setOnItemClickListener((p,v,pos,id)->{ResolveInfo r=visible.get(pos);String pkg=r.activityInfo.packageName,label=String.valueOf(r.loadLabel(pm));if(ref[0]!=null)ref[0].dismiss();startPreparation(new Intent().putExtra("kind","installed").putExtra("package",pkg).putExtra("label",label),"installed");});
        ref[0]=new AlertDialog.Builder(this).setTitle("Установленные приложения / игры").setView(box).setNegativeButton("Отмена",null).create();ref[0].show();
    }

    private String display(Uri uri){String d=uri.getLastPathSegment();try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())d=c.getString(0);}catch(Exception ignored){}return d==null?"target.apk":d;}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(req==PICK_APK&&result==RESULT_OK&&data!=null&&data.getData()!=null){Uri uri=data.getData();startPreparation(new Intent().putExtra("kind","apk").putExtra("uri",uri.toString()).putExtra("display",display(uri)),"apk");}}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override protected void onDestroy(){handler.removeCallbacks(poll);super.onDestroy();}
}
