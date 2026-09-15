package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.database.Cursor;
import android.graphics.*;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class PatchPackActivity extends Activity {
    private App app;
    private LinearLayout root, issues;
    private TextView status, summary;
    private Button inspect, build;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long revision=-1;
    private final Runnable poll=new Runnable(){public void run(){refresh();handler.postDelayed(this,400);}};
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(getColor(R.color.mk_on_surface));t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}
    private Button button(String s,View.OnClickListener l){Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setOnClickListener(l);root.addView(b);return b;}
    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(20),dp(18),dp(24));root.setBackgroundColor(getColor(R.color.mk_background));scroll.addView(root);setContentView(scroll);
        TextView title=text("Patch Pack · DEX + SO",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text("Проверяет ZIP перед заменой файлов: потерю классов DEX, ABI ELF, DT_NEEDED и конфликт целевых путей. BLOCK не даст собрать несовместимый APK.",14));
        button("Выбрать ZIP с classes*.dex / .so",v->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE),200));
        inspect=button("Проверить совместимость",v->startWork(new Intent().putExtra("op","patchpack_inspect")));
        build=button("Применить и собрать подписанный APK",v->{JSONObject r=read("patchpack-report.json");if(r==null){toast("Сначала выполните проверку");return;}if(r.optBoolean("blocked")){toast("Сборка заблокирована: исправьте BLOCK-проблемы");return;}startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-patchpack-test.apk"),201);});
        status=text("",14);root.addView(status);summary=text("",13);root.addView(summary);issues=new LinearLayout(this);issues.setOrientation(LinearLayout.VERTICAL);root.addView(issues);
    }
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    private void deleteCreatedDocument(Intent i){String op=i.getStringExtra("op"),uriText=i.getStringExtra("uri");if(!"patchpack_build".equals(op)||uriText==null||uriText.isEmpty())return;try{android.provider.DocumentsContract.deleteDocument(getContentResolver(),Uri.parse(uriText));}catch(Exception ignored){}}
    private boolean startWork(Intent i){if(app.busy.get()){deleteCreatedDocument(i);toast("Сейчас выполняется другая операция");return false;}if(!app.file("game.apk").isFile()){deleteCreatedDocument(i);toast("На главном экране сначала выберите исходный APK");return false;}if(!app.file("patchpack.zip").isFile()&&!"patchpack_import".equals(i.getStringExtra("op"))){deleteCreatedDocument(i);toast("Сначала выберите ZIP");return false;}app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);try{startForegroundService(i);return true;}catch(Exception e){app.busy.set(false);app.revision++;deleteCreatedDocument(i);app.progress("Patch Pack: не удалось запустить операцию: "+e.getMessage());toast("Не удалось запустить Patch Pack-операцию");return false;}}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();if(request==200){String display=uri.getLastPathSegment();try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())display=c.getString(0);}catch(Exception ignored){}startWork(new Intent().putExtra("op","patchpack_import").putExtra("uri",uri.toString()).putExtra("display",display));}else if(request==201){startWork(new Intent().putExtra("op","patchpack_build").putExtra("uri",uri.toString()));}}
    private JSONObject read(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private void refresh(){if(revision==app.revision)return;revision=app.revision;status.setText(app.status);inspect.setEnabled(!app.busy.get()&&app.file("game.apk").isFile()&&app.file("patchpack.zip").isFile());JSONObject r=read("patchpack-report.json");issues.removeAllViews();if(r==null){summary.setText("Исходный APK: "+(app.file("game.apk").isFile()?"выбран":"не выбран")+"\nPatch Pack: "+(app.file("patchpack.zip").isFile()?"выбран":"не выбран"));build.setEnabled(false);return;}JSONArray m=r.optJSONArray("mappings"),is=r.optJSONArray("issues");summary.setText((r.optBoolean("blocked")?"BLOCKED":"Совместимо")+" · файлов: "+(m==null?0:m.length())+" · замечаний: "+(is==null?0:is.length()));build.setEnabled(!app.busy.get()&&!r.optBoolean("blocked"));if(is!=null)for(int i=0;i<is.length();i++){JSONObject x=is.optJSONObject(i);if(x!=null)issues.addView(text("["+x.optString("severity")+"] "+x.optString("code")+"\n"+x.optString("message")+"\n"+x.optString("artifact"),13));}}
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}
}
