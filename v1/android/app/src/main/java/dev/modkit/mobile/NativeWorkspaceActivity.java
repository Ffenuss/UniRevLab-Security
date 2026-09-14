package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.database.Cursor;
import android.graphics.*;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class NativeWorkspaceActivity extends Activity {
    private App app;
    private LinearLayout root, output;
    private TextView status, summary;
    private EditText query,rva,payload;
    private Spinner mode;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long revision=-1;
    private final Runnable poll=new Runnable(){public void run(){refresh();handler.postDelayed(this,400);}};
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(getColor(R.color.mk_on_surface));t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}
    private Button button(String s,View.OnClickListener l){Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setOnClickListener(l);root.addView(b);return b;}
    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();
        ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(20),dp(18),dp(24));root.setBackgroundColor(getColor(R.color.mk_background));scroll.addView(root);setContentView(scroll);
        TextView title=text("Native / SO Editor",28);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text("ELF64: секции, symbols/imports, strings, RVA ↔ file offset, ARM64 disassembly, HEX/ASM изменения и undo. Оригинал не перезаписывается.",14));
        button("Выбрать .so",v->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),100));
        status=text("",14);root.addView(status);summary=text("",13);root.addView(summary);
        query=new EditText(this);query.setSingleLine(true);query.setHint("Поиск символа/строки: il2cpp_, console, health…");root.addView(query);
        button("Поиск в .so",v->startWork(new Intent().putExtra("op","native_search").putExtra("query",query.getText().toString())));
        rva=new EditText(this);rva.setSingleLine(true);rva.setHint("RVA, например 0x183540");rva.setInputType(InputType.TYPE_CLASS_TEXT);root.addView(rva);
        button("Дизассемблировать от RVA",v->startWork(new Intent().putExtra("op","native_disasm").putExtra("rva",rva.getText().toString())));
        button("Найти прямые вызовы на RVA (static BL xrefs)",v->startWork(new Intent().putExtra("op","native_xrefs").putExtra("rva",rva.getText().toString())));
        mode=new Spinner(this);mode.setAdapter(new ArrayAdapter<String>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"HEX","ASM"}));root.addView(mode);
        payload=new EditText(this);payload.setHint("HEX: 1f 20 03 d5   или ASM: NOP / RET / MOV W0,#1 / B 0x...");root.addView(payload);
        button("Применить изменение к рабочей копии",v->startWork(new Intent().putExtra("op","native_patch").putExtra("rva",rva.getText().toString()).putExtra("mode",mode.getSelectedItem().toString().toLowerCase()).putExtra("payload",payload.getText().toString())));
        button("Undo последнего изменения",v->startWork(new Intent().putExtra("op","native_undo")));
        button("Сохранить изменённую .so",v->{if(!app.file("native-working.so").isFile()){toast("Сначала выберите .so");return;}startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-patched.so"),101);});
        output=new LinearLayout(this);output.setOrientation(LinearLayout.VERTICAL);root.addView(output);
    }
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    private void startWork(Intent i){if(app.busy.get()){toast("Сейчас выполняется другая операция");return;}if(!app.file("native-working.so").isFile()&&!"native_import".equals(i.getStringExtra("op"))){toast("Сначала выберите .so");return;}app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);startForegroundService(i);}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();if(request==100){String display=uri.getLastPathSegment();try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())display=c.getString(0);}catch(Exception ignored){}startWork(new Intent().putExtra("op","native_import").putExtra("uri",uri.toString()).putExtra("display",display));}else if(request==101){startWork(new Intent().putExtra("op","native_save_uri").putExtra("uri",uri.toString()));}}
    private JSONObject readObj(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private JSONArray readArr(String name){try{return new JSONArray(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private void refresh(){if(revision==app.revision)return;revision=app.revision;status.setText(app.status);output.removeAllViews();JSONObject info=readObj("native-info.json");if(info!=null){JSONObject s=info.optJSONObject("summary");if(s!=null)summary.setText("Архитектура: "+s.optString("arch")+" · размер: "+s.optLong("size")+" · sections: "+s.optInt("sections")+" · symbols: "+s.optInt("symbols")+"\nSONAME: "+s.optString("soname","—")+"\nDT_NEEDED: "+s.optJSONArray("needed")+"\nИзменений: "+s.optInt("changes"));}
        JSONObject sr=readObj("native-search.json");if(sr!=null){JSONArray sy=sr.optJSONArray("symbols"),st=sr.optJSONArray("strings");StringBuilder b=new StringBuilder("Поиск:\n");if(sy!=null)for(int i=0;i<Math.min(30,sy.length());i++){JSONObject x=sy.optJSONObject(i);b.append("SYM  ").append(x.optString("name")).append("  RVA 0x").append(Long.toHexString(x.optLong("rva"))).append("\n");}if(st!=null)for(int i=0;i<Math.min(30,st.length());i++){JSONObject x=st.optJSONObject(i);b.append("STR  RVA 0x").append(Long.toHexString(x.optLong("rva"))).append("  ").append(x.optString("text")).append("\n");}output.addView(text(b.toString(),12));}
        JSONArray dis=readArr("native-disasm.json");if(dis!=null){StringBuilder b=new StringBuilder("Disassembly:\n");for(int i=0;i<Math.min(160,dis.length());i++){JSONObject x=dis.optJSONObject(i);b.append(String.format(java.util.Locale.ROOT,"0x%x  %-12s  %s\n",x.optLong("rva"),x.optString("bytes"),x.optString("asm")));}output.addView(text(b.toString(),12));}
        JSONArray xr=readArr("native-xrefs.json");if(xr!=null){StringBuilder b=new StringBuilder("Static direct-call xrefs (ARM64 BL):\n");for(int i=0;i<Math.min(120,xr.length());i++){JSONObject x=xr.optJSONObject(i);if(x==null)continue;String src=x.optString("sourceFunction");if(src.isEmpty())src="sub_"+Long.toHexString(x.optLong("callRva"));b.append(src).append(" @ call 0x").append(Long.toHexString(x.optLong("callRva"))).append(" → 0x").append(Long.toHexString(x.optLong("targetRva"))).append("\n");}output.addView(text(b.toString(),12));}
    }
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}
}
