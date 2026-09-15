package dev.modkit.mobile;

import android.app.*;
import android.content.*;
import android.content.res.ColorStateList;
import android.graphics.*;
import android.net.Uri;
import android.os.*;
import android.text.*;
import android.view.*;
import android.widget.*;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Unified dev36 APK/DEX decompiler workspace. */
public class DecompilerActivity extends androidx.appcompat.app.AppCompatActivity {
    private enum Mode { JAVA, SMALI, RESOURCES }
    private App app;
    private DecompilerEngine engine;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final AtomicInteger generation=new AtomicInteger();
    private final AtomicBoolean cancelSearch=new AtomicBoolean(false);
    private Mode mode=Mode.JAVA;
    private String selectedClass;
    private RecyclerView list;
    private ItemAdapter adapter;
    private EditText query;
    private TextView status,viewer,selection;
    private ProgressBar progress;
    private MaterialButton javaBtn,smaliBtn,resBtn,searchCodeBtn,xrefsBtn,exportBtn,cancelBtn;
    private Uri pendingExportUri;

    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return (getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(16,20,24):Color.rgb(244,247,251);}
    private int surface(){return dark()?Color.rgb(23,28,33):Color.WHITE;}
    private int fg(){return dark()?Color.rgb(221,227,234):Color.rgb(25,40,62);}
    private int muted(){return dark()?Color.rgb(158,170,181):Color.rgb(92,108,126);}
    private int button(){return dark()?Color.rgb(39,54,59):Color.rgb(232,243,247);}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);app=(App)getApplication();engine=new DecompilerEngine(this);buildUi();openTarget();
    }

    private void buildUi(){
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(14),dp(14),dp(14),dp(14));root.setBackgroundColor(bg());
        TextView title=text(getString(R.string.decompiler_title),26,true);root.addView(title);
        root.addView(text(getString(R.string.decompiler_subtitle),13,false));
        status=text(getString(R.string.decompiler_loading),13,false);status.setTextColor(muted());status.setTextIsSelectable(true);root.addView(status);
        progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);progress.setIndeterminate(true);root.addView(progress,new LinearLayout.LayoutParams(-1,dp(7)));

        LinearLayout modes=new LinearLayout(this);modes.setOrientation(LinearLayout.HORIZONTAL);root.addView(modes,new LinearLayout.LayoutParams(-1,-2));
        javaBtn=button(getString(R.string.decompiler_java),modes,v->{mode=Mode.JAVA;refreshMode();});
        smaliBtn=button(getString(R.string.decompiler_smali),modes,v->{mode=Mode.SMALI;refreshMode();});
        resBtn=button(getString(R.string.decompiler_resources),modes,v->{mode=Mode.RESOURCES;selectedClass=null;viewer.setText("");selection.setText("");refreshList();});
        button(getString(R.string.decompiler_native),modes,v->{new AlertDialog.Builder(this).setTitle(R.string.decompiler_native).setMessage(R.string.decompiler_native_note).setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.open_native,(d,w)->startActivity(new Intent(this,NativeWorkspaceActivity.class))).show();});

        LinearLayout tools=new LinearLayout(this);tools.setOrientation(LinearLayout.HORIZONTAL);root.addView(tools,new LinearLayout.LayoutParams(-1,-2));
        searchCodeBtn=button(getString(R.string.decompiler_search_code),tools,v->searchInCode());
        xrefsBtn=button(getString(R.string.decompiler_xrefs),tools,v->showXrefs());
        exportBtn=button(getString(R.string.decompiler_export),tools,v->startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"modkit-decompiled.zip"),71));
        cancelBtn=button(getString(R.string.cancel),tools,v->{cancelSearch.set(true);generation.incrementAndGet();status.setText(R.string.decompiler_cancelling);});

        query=new EditText(this);query.setSingleLine(true);query.setHint(R.string.decompiler_filter);query.setTextColor(fg());query.setHintTextColor(muted());root.addView(query,new LinearLayout.LayoutParams(-1,-2));
        query.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int b,int c){}public void onTextChanged(CharSequence s,int a,int b,int c){ui.removeCallbacks(refreshDebounce);ui.postDelayed(refreshDebounce,220);}public void afterTextChanged(Editable e){}});

        selection=text("",13,true);selection.setTextColor(muted());root.addView(selection);
        LinearLayout panes=new LinearLayout(this);panes.setOrientation(LinearLayout.VERTICAL);root.addView(panes,new LinearLayout.LayoutParams(-1,0,1f));
        list=new RecyclerView(this);list.setLayoutManager(new LinearLayoutManager(this));adapter=new ItemAdapter();list.setAdapter(adapter);panes.addView(list,new LinearLayout.LayoutParams(-1,0,0.38f));
        ScrollView codeScroll=new ScrollView(this);viewer=text("",12,false);viewer.setTypeface(Typeface.MONOSPACE);viewer.setTextIsSelectable(true);viewer.setPadding(dp(12),dp(8),dp(12),dp(24));codeScroll.addView(viewer,new ScrollView.LayoutParams(-1,-2));panes.addView(codeScroll,new LinearLayout.LayoutParams(-1,0,0.62f));
        setContentView(root);
    }
    private final Runnable refreshDebounce=this::refreshList;

    private TextView text(String s,int size,boolean bold){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));if(bold)t.setTypeface(null,Typeface.BOLD);return t;}
    private MaterialButton button(String s,LinearLayout parent,View.OnClickListener listener){MaterialButton b=new MaterialButton(this);b.setText(s);b.setAllCaps(false);b.setTextSize(12);b.setTextColor(fg());b.setBackgroundTintList(ColorStateList.valueOf(button()));b.setOnClickListener(listener);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1f);lp.setMargins(dp(2),dp(2),dp(2),dp(2));parent.addView(b,lp);return b;}

    private void openTarget(){
        progress.setVisibility(View.VISIBLE);setControls(false);status.setText(R.string.decompiler_loading);
        worker.execute(()->{
            try{engine.open();List<File> inputs=engine.inputFiles();StringBuilder names=new StringBuilder();for(File f:inputs){if(names.length()>0)names.append(", ");names.append(f.getName());}
                ui.post(()->{progress.setVisibility(View.GONE);setControls(true);status.setText(getString(R.string.decompiler_ready,DecompilerEngine.BACKEND,engine.classCount(),engine.resourceCount(),engine.errorCount(),engine.warnCount(),names));refreshList();});
            }catch(Throwable t){ui.post(()->{progress.setVisibility(View.GONE);status.setText(getString(R.string.decompiler_error,msg(t)));viewer.setText(R.string.decompiler_choose_target);});}
        });
    }

    private void refreshMode(){
        if(mode==Mode.RESOURCES)mode=Mode.JAVA;
        refreshList();
        if(selectedClass!=null)showClass(selectedClass);
    }

    private void refreshList(){
        if(!engine.isOpen())return;String q=query.getText()==null?"":query.getText().toString();
        worker.execute(()->{try{
            final ArrayList<Row> rows=new ArrayList<>();
            if(mode==Mode.RESOURCES){for(String n:engine.resources(q,800))rows.add(new Row(n,n,"resource"));}
            else{for(DecompilerEngine.ClassEntry c:engine.classes(q,800))rows.add(new Row(c.fullName,c.fullName,"class"));}
            ui.post(()->{adapter.setRows(rows);status.setText(getString(mode==Mode.RESOURCES?R.string.decompiler_list_resources:R.string.decompiler_list_classes,rows.size()));});
        }catch(Throwable t){ui.post(()->status.setText(getString(R.string.decompiler_error,msg(t))));}});
    }

    private void clickRow(Row row){
        if("resource".equals(row.kind)){showResource(row.key);return;}selectedClass=row.key;showClass(row.key);
    }
    private void showClass(String name){
        if(!engine.isOpen())return;int gen=generation.incrementAndGet();progress.setVisibility(View.VISIBLE);selection.setText(name);viewer.setText(R.string.decompiler_decoding);
        worker.execute(()->{try{String code=(mode==Mode.SMALI)?engine.smaliCode(name):engine.javaCode(name);ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);viewer.setText(code);status.setText((mode==Mode.SMALI?"Smali · ":"Java · ")+name);});}
            catch(Throwable t){ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);viewer.setText(getString(R.string.decompiler_error,msg(t)));});}});
    }
    private void showResource(String name){
        int gen=generation.incrementAndGet();progress.setVisibility(View.VISIBLE);selection.setText(name);viewer.setText(R.string.decompiler_decoding);
        worker.execute(()->{try{String s=engine.resourcePreview(name);ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);viewer.setText(s);status.setText("Resource · "+name);});}catch(Throwable t){ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);viewer.setText(getString(R.string.decompiler_error,msg(t)));});}});
    }

    private void showXrefs(){
        if(selectedClass==null){Toast.makeText(this,R.string.decompiler_select_class,Toast.LENGTH_SHORT).show();return;}int gen=generation.incrementAndGet();progress.setVisibility(View.VISIBLE);viewer.setText(R.string.decompiler_resolving_xrefs);
        worker.execute(()->{try{String s=engine.xrefs(selectedClass);ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);viewer.setText(s);status.setText("Xrefs · "+selectedClass);});}catch(Throwable t){ui.post(()->{progress.setVisibility(View.GONE);viewer.setText(getString(R.string.decompiler_error,msg(t)));});}});
    }

    private void searchInCode(){
        String q=query.getText()==null?"":query.getText().toString().trim();if(q.length()<2){Toast.makeText(this,R.string.decompiler_search_min,Toast.LENGTH_SHORT).show();return;}
        cancelSearch.set(false);int gen=generation.incrementAndGet();progress.setVisibility(View.VISIBLE);setControls(false);status.setText(getString(R.string.decompiler_search_running,q));viewer.setText("");
        worker.execute(()->{try{List<DecompilerEngine.SearchHit> found=engine.searchCode(q,cancelSearch);ArrayList<Row> rows=new ArrayList<>();for(DecompilerEngine.SearchHit h:found)rows.add(new Row(h.className,h.className+":"+h.line+"  "+h.preview,"class"));ui.post(()->{if(gen!=generation.get())return;progress.setVisibility(View.GONE);setControls(true);adapter.setRows(rows);status.setText(getString(R.string.decompiler_search_done,rows.size(),DecompilerEngine.MAX_SEARCH_HITS));});}
            catch(Throwable t){ui.post(()->{progress.setVisibility(View.GONE);setControls(true);status.setText(getString(R.string.decompiler_error,msg(t)));});}});
    }

    private void deleteCreatedDocument(Uri uri){if(uri==null)return;try{android.provider.DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    private void exportTo(Uri uri){
        pendingExportUri=uri;cancelSearch.set(false);progress.setVisibility(View.VISIBLE);setControls(false);status.setText(R.string.decompiler_export_running);
        worker.execute(()->{try{File zip=engine.exportAllZip(cancelSearch);try(InputStream in=new BufferedInputStream(new FileInputStream(zip));OutputStream out=getContentResolver().openOutputStream(uri,"w")){if(out==null)throw new IOException("openOutputStream returned null");byte[] b=new byte[128*1024];int n;while((n=in.read(b))!=-1){if(cancelSearch.get()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("export cancelled");out.write(b,0,n);}}ui.post(()->{progress.setVisibility(View.GONE);setControls(true);status.setText(R.string.decompiler_export_done);});}
            catch(Throwable t){deleteCreatedDocument(uri);ui.post(()->{progress.setVisibility(View.GONE);setControls(true);status.setText(getString(R.string.decompiler_error,msg(t)));});}});
    }

    private void setControls(boolean enabled){for(MaterialButton b:new MaterialButton[]{javaBtn,smaliBtn,resBtn,searchCodeBtn,xrefsBtn,exportBtn})if(b!=null)b.setEnabled(enabled);if(cancelBtn!=null)cancelBtn.setEnabled(true);}
    private static String msg(Throwable t){String m=t.getMessage();return m==null?t.getClass().getSimpleName():m;}

    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){super.onActivityResult(requestCode,resultCode,data);if(requestCode==71&&resultCode==RESULT_OK&&data!=null&&data.getData()!=null)exportTo(data.getData());}
    @Override protected void onDestroy(){cancelSearch.set(true);generation.incrementAndGet();worker.shutdownNow();if(engine!=null)engine.close();super.onDestroy();}

    private static final class Row {final String key,label,kind;Row(String key,String label,String kind){this.key=key;this.label=label;this.kind=kind;}}
    private final class ItemAdapter extends RecyclerView.Adapter<ItemHolder>{private final ArrayList<Row> rows=new ArrayList<>();void setRows(List<Row> r){rows.clear();rows.addAll(r);notifyDataSetChanged();}@Override public ItemHolder onCreateViewHolder(ViewGroup p,int type){TextView t=text("",12,false);t.setPadding(dp(10),dp(10),dp(8),dp(10));t.setBackgroundColor(surface());return new ItemHolder(t);}@Override public void onBindViewHolder(ItemHolder h,int pos){Row r=rows.get(pos);h.text.setText(r.label);h.text.setOnClickListener(v->clickRow(r));}@Override public int getItemCount(){return rows.size();}}
    private static final class ItemHolder extends RecyclerView.ViewHolder{final TextView text;ItemHolder(TextView t){super(t);text=t;}}
}
