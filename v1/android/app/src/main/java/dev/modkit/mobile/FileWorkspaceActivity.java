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
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Format-aware file/APK-entry editor used by the professional workspace. */
public class FileWorkspaceActivity extends Activity {
    private static final int OPEN_FILE=301, EXPORT_FILE=302, BUILD_APK=303;
    private static final int MAX_EDIT_BYTES=16*1024*1024;
    private App app;
    private TextView status,meta;
    private EditText editor;
    private Button save,export,patch,build,modeButton,specialized;
    private byte[] original=new byte[0];
    private boolean hexMode=false;
    private String displayName="",targetEntry=null;
    private File sourceApk=null;
    private FileFormatDetector.Result format;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long revision=-1;
    private final Runnable poll=new Runnable(){public void run(){refreshStatus();handler.postDelayed(this,400);}};

    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(Color.rgb(225,230,235));t.setPadding(0,dp(5),0,dp(5));t.setTextIsSelectable(true);return t;}
    private Button button(String s,LinearLayout parent,View.OnClickListener l){Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setOnClickListener(l);parent.addView(b);return b;}

    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(14),dp(14),dp(14),dp(18));root.setBackgroundColor(Color.rgb(16,20,24));
        TextView title=text("Файлы приложения · редактор",26);title.setTypeface(null,Typeface.BOLD);root.addView(title);
        root.addView(text("Определяет формат по magic/header, а не по доле печатных байтов. DEX/ELF/IL2CPP/Unity/AXML/ARSC/SQLite/images/ZIP не открываются как случайный UTF-8. Текст редактируется как UTF-8; бинарные файлы — как HEX. Изменение сохраняется только в рабочую копию и может быть упаковано в Patch Pack.",13));
        LinearLayout top=new LinearLayout(this);top.setOrientation(LinearLayout.HORIZONTAL);root.addView(top);
        button("Открыть любой файл",top,v->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),OPEN_FILE));
        button("Файл из APK / split",top,v->showApkSources());
        modeButton=button("Режим: AUTO",root,v->{if(original.length==0)return;hexMode=!hexMode;render();});
        specialized=button("Специализированный просмотр",root,v->openSpecialized());specialized.setVisibility(View.GONE);
        meta=text("Файл не открыт",13);root.addView(meta);
        editor=new EditText(this);editor.setTextColor(Color.WHITE);editor.setHintTextColor(Color.GRAY);editor.setTypeface(Typeface.MONOSPACE);editor.setTextSize(12);editor.setGravity(Gravity.TOP|Gravity.START);editor.setHorizontallyScrolling(true);editor.setSingleLine(false);editor.setPadding(dp(10),dp(10),dp(10),dp(10));
        ScrollView scroll=new ScrollView(this);scroll.addView(editor,new ScrollView.LayoutParams(-1,-2));root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1f));
        LinearLayout actions=new LinearLayout(this);actions.setOrientation(LinearLayout.HORIZONTAL);root.addView(actions);
        save=button("Сохранить рабочую копию",actions,v->saveWorking());
        export=button("Экспортировать файл",actions,v->exportEdited());
        patch=button("Подготовить Patch Pack",root,v->preparePatch());
        build=button("Собрать APK / APK-set",root,v->buildPatched());
        status=text("",13);root.addView(status);setContentView(root);updateButtons();
    }

    private void updateButtons(){boolean opened=original.length>0;save.setEnabled(opened);export.setEnabled(opened);boolean apk=opened&&sourceApk!=null&&targetEntry!=null;patch.setEnabled(apk);build.setEnabled(apk&&app.file("workspace-patch.zip").isFile());specialized.setVisibility(opened&&format!=null&&specialRouteSupported(format.kind)?View.VISIBLE:View.GONE);if(opened&&format!=null)specialized.setText("Открыть: "+format.route);}
    private boolean specialRouteSupported(FileFormatDetector.Kind kind){return kind==FileFormatDetector.Kind.DEX||kind==FileFormatDetector.Kind.ELF||kind==FileFormatDetector.Kind.IL2CPP_METADATA||kind==FileFormatDetector.Kind.UNITY_BUNDLE||kind==FileFormatDetector.Kind.UNITY_ASSET;}
    private void openSpecialized(){if(format==null)return;switch(format.kind){case DEX:startActivity(new Intent(this,DecompilerActivity.class));break;case ELF:startActivity(new Intent(this,NativeWorkspaceActivity.class));break;case IL2CPP_METADATA:case UNITY_BUNDLE:case UNITY_ASSET:startActivity(new Intent(this,ReWorkspaceActivity.class));break;default:toast("Для этого формата отдельный viewer ещё не требуется");}}

    private String display(Uri uri){String d=uri.getLastPathSegment();try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())d=c.getString(0);}catch(Exception ignored){}return d==null?"file":d;}
    private void setOpened(byte[] data,String name,File apk,String entry,String openedStatus){displayName=name;sourceApk=apk;targetEntry=entry;original=data;format=FileFormatDetector.detect(entry==null?name:entry,data);hexMode=format.defaultHex;render();status.setText(openedStatus+"\nФормат: "+format.label+" · маршрут: "+format.route);AnalysisJournal.append(this,"FILE_OPEN","Workspace file opened",new JSONObjectSafe().put("name",name).put("format",format.kind.name()).put("bytes",data.length).json());}
    private void openUri(Uri uri){try(InputStream in=getContentResolver().openInputStream(uri)){if(in==null)throw new IOException("openInputStream returned null");byte[] data=readLimited(in,MAX_EDIT_BYTES+1);if(data.length>MAX_EDIT_BYTES)throw new IOException("Файл больше 16 МБ. Для больших файлов используйте Native/Decompiler/RE workspace вместо встроенного редактора.");setOpened(data,display(uri),null,null,"Открыт внешний файл. Изменения можно экспортировать, но автоматическая сборка APK доступна только для entry из APK.");}catch(Exception e){toast(e.getMessage());}}

    private void showApkSources(){List<File> files=new ArrayList<>();List<String> labels=new ArrayList<>();try{TargetResolver.Target target=TargetResolver.resolve(app);for(TargetResolver.Member member:target.members){files.add(member.file);labels.add(member.name);}}catch(Exception ignored){}
        if(files.isEmpty()){toast("Сначала выберите APK или установленное приложение на главном экране");return;}
        new AlertDialog.Builder(this).setTitle("Выберите APK / split").setItems(labels.toArray(new String[0]),(d,w)->showEntries(files.get(w),labels.get(w))).setNegativeButton(android.R.string.cancel,null).show();
    }

    private void showEntries(File apk,String apkLabel){try(ZipFile z=new ZipFile(apk)){ArrayList<String> names=new ArrayList<>();Enumeration<? extends ZipEntry> en=z.entries();while(en.hasMoreElements()){ZipEntry e=en.nextElement();if(!e.isDirectory())names.add(e.getName());}Collections.sort(names,String.CASE_INSENSITIVE_ORDER);
        LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);int pad=dp(10);box.setPadding(pad,pad,pad,pad);EditText filter=new EditText(this);filter.setHint("Фильтр: lua, json, classes.dex, assets/…");box.addView(filter);ListView list=new ListView(this);box.addView(list,new LinearLayout.LayoutParams(-1,dp(520)));ArrayAdapter<String> adapter=new ArrayAdapter<>(this,android.R.layout.simple_list_item_1,new ArrayList<>(names));list.setAdapter(adapter);filter.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int b,int c){}public void onTextChanged(CharSequence s,int a,int b,int c){String q=s.toString().toLowerCase(Locale.ROOT);ArrayList<String> v=new ArrayList<>();for(String n:names)if(q.isEmpty()||n.toLowerCase(Locale.ROOT).contains(q))v.add(n);adapter.clear();adapter.addAll(v);adapter.notifyDataSetChanged();}public void afterTextChanged(android.text.Editable e){}});
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle(apkLabel+" · файлов "+names.size()).setView(box).setNegativeButton(android.R.string.cancel,null).create();list.setOnItemClickListener((p,v,pos,id)->{String name=adapter.getItem(pos);dialog.dismiss();openEntry(apk,name);});dialog.show();
    }catch(Exception e){toast("Не удалось открыть APK: "+e.getMessage());}}

    private void openEntry(File apk,String name){try(ZipFile z=new ZipFile(apk)){ZipEntry e=z.getEntry(name);if(e==null)throw new FileNotFoundException(name);if(e.getSize()>MAX_EDIT_BYTES)throw new IOException("Entry больше 16 МБ. Для больших DEX/.so/Unity data используйте Decompiler, Native или RE Workspace.");byte[] data;try(InputStream in=z.getInputStream(e)){data=readLimited(in,MAX_EDIT_BYTES+1);}setOpened(data,apk.getName()+"!"+name,apk,name,"APK entry открыт. После редактирования можно подготовить Patch Pack и собрать подписанный APK/APK-set.");}catch(Exception ex){toast(ex.getMessage());}}

    private void render(){if(original.length==0)return;if(format==null)format=FileFormatDetector.detect(targetEntry==null?displayName:targetEntry,original);if(hexMode){editor.setText(toHex(original));modeButton.setText("Режим: HEX · "+format.label);}else{editor.setText(new String(original,StandardCharsets.UTF_8));modeButton.setText("Режим: UTF-8 · "+format.label);}String inspection=BinaryFormatInspector.inspect(format,original,displayName);meta.setText(displayName+" · "+original.length+" bytes"+(targetEntry==null?"":"\nAPK: "+sourceApk.getName()+"\nEntry: "+targetEntry)+"\n"+inspection);updateButtons();}
    private byte[] editedBytes() throws Exception{String s=editor.getText()==null?"":editor.getText().toString();return hexMode?fromHex(s):s.getBytes(StandardCharsets.UTF_8);}
    private void saveWorking(){try{byte[] b=editedBytes();Files.write(app.file("workspace-edit.bin").toPath(),b);original=b;format=FileFormatDetector.detect(targetEntry==null?displayName:targetEntry,b);meta.setText(displayName+" · "+b.length+" bytes · рабочая копия сохранена\n"+BinaryFormatInspector.inspect(format,b,displayName));status.setText("Рабочая копия сохранена. Исходный APK не изменён.");}catch(Exception e){toast("Ошибка: "+e.getMessage());}}
    private void exportEdited(){if(original.length==0)return;startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,targetEntry==null?displayName:new File(targetEntry).getName()),EXPORT_FILE);}
    private void writeEdited(Uri uri){try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){if(out==null)throw new IOException("openOutputStream returned null");out.write(editedBytes());out.flush();status.setText("Изменённый файл экспортирован.");}catch(Exception e){deleteCreatedDocument(uri);toast(e.getMessage());}}

    private void preparePatch(){try{if(sourceApk==null||targetEntry==null)throw new IOException("Откройте entry из APK");byte[] b=editedBytes();File zip=app.file("workspace-patch.zip"),tmp=app.file("workspace-patch.zip.tmp");JSONObject manifest=new JSONObject().put("schema","modkit-workspace-patch-1.0").put("sourceApk",sourceApk.getCanonicalPath()).put("entries",new JSONArray().put(new JSONObject().put("packPath","files/edit.bin").put("targetPath",targetEntry).put("display",displayName)));
        try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){z.putNextEntry(new ZipEntry("files/edit.bin"));z.write(b);z.closeEntry();z.putNextEntry(new ZipEntry("modkit-workspace.json"));z.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));z.closeEntry();}
        Files.move(tmp.toPath(),zip.toPath(),StandardCopyOption.REPLACE_EXISTING);Files.write(app.file("workspace-source.json").toPath(),new JSONObject().put("sourceApk",sourceApk.getCanonicalPath()).put("targetEntry",targetEntry).toString(2).getBytes(StandardCharsets.UTF_8));
        startWork(new Intent().putExtra("op","workspace_inspect").putExtra("source",sourceApk.getCanonicalPath()));status.setText("Patch Pack подготовлен; запускаю проверку совместимости…");updateButtons();
    }catch(Exception e){toast(e.getMessage());}}

    private void buildPatched(){if(!app.file("workspace-patch.zip").isFile()){toast("Сначала подготовьте Patch Pack");return;}boolean set=isInstalledSet();String title=set?"modkit-workspace-test.apks":"modkit-workspace-test.apk";startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(set?"application/zip":"application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,title),BUILD_APK);}
    private boolean isInstalledSet(){try{return TargetResolver.resolve(app).apkSet;}catch(Exception e){return false;}}
    private void deleteCreatedDocument(Uri uri){if(uri==null)return;try{android.provider.DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    private void startBuild(Uri uri){try{JSONObject s=new JSONObject(Io.readUtf8(app.file("workspace-source.json")));String source=s.getString("sourceApk");startWork(new Intent().putExtra("op","workspace_build").putExtra("source",source).putExtra("uri",uri.toString()));}catch(Exception e){deleteCreatedDocument(uri);toast(e.getMessage());}}
    private boolean startWork(Intent i){boolean buildOp="workspace_build".equals(i.getStringExtra("op"));Uri output=null;String uriText=i.getStringExtra("uri");if(buildOp&&uriText!=null&&!uriText.isEmpty())output=Uri.parse(uriText);if(app.busy.get()){if(buildOp)deleteCreatedDocument(output);toast("Сейчас выполняется другая операция");return false;}app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);try{startForegroundService(i);return true;}catch(Exception e){app.busy.set(false);app.revision++;if(buildOp)deleteCreatedDocument(output);app.progress("File Workspace: не удалось запустить операцию: "+e.getMessage());toast("Не удалось запустить File Workspace-операцию");return false;}}

    private void refreshStatus(){if(revision==app.revision)return;revision=app.revision;if(app.status!=null&&!app.status.isEmpty())status.setText(app.status);build.setEnabled(sourceApk!=null&&targetEntry!=null&&app.file("workspace-patch.zip").isFile()&&!app.busy.get());}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;if(req==OPEN_FILE)openUri(data.getData());else if(req==EXPORT_FILE)writeEdited(data.getData());else if(req==BUILD_APK)startBuild(data.getData());}
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}

    private static byte[] readLimited(InputStream in,int limit)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[65536];int n,total=0;while((n=in.read(buf))!=-1){total+=n;if(total>limit){out.write(buf,0,n-(total-limit));break;}out.write(buf,0,n);}return out.toByteArray();}
    private static String toHex(byte[] b){StringBuilder s=new StringBuilder(b.length*3);for(int i=0;i<b.length;i++){if(i>0){if(i%16==0)s.append('\n');else s.append(' ');}s.append(String.format(Locale.ROOT,"%02X",b[i]&255));}return s.toString();}
    private static byte[] fromHex(String s)throws IOException{String clean=s.replaceAll("[^0-9A-Fa-f]","");if((clean.length()&1)!=0)throw new IOException("HEX содержит нечётное число цифр");byte[] out=new byte[clean.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(clean.substring(i*2,i*2+2),16);return out;}

    /** Tiny builder which absorbs JSONObject checked exceptions for diagnostics-only metadata. */
    private static final class JSONObjectSafe{private final JSONObject value=new JSONObject();JSONObjectSafe put(String k,Object v){try{value.put(k,v);}catch(Exception ignored){}return this;}JSONObject json(){return value;}}
}
