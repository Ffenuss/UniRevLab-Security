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
    private String sourceEntrySha256="";
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

    private void updateButtons(){boolean opened=original.length>0;save.setEnabled(opened);export.setEnabled(opened);boolean apk=opened&&sourceApk!=null&&targetEntry!=null;patch.setEnabled(apk&&!app.busy.get());build.setEnabled(apk&&app.file("workspace-patch.zip").isFile()&&!app.busy.get());specialized.setVisibility(opened&&format!=null&&specialRouteSupported(format.kind)?View.VISIBLE:View.GONE);if(opened&&format!=null)specialized.setText("Открыть: "+format.route);}
    private boolean specialRouteSupported(FileFormatDetector.Kind kind){switch(kind){case DEX:case ELF:case IL2CPP_METADATA:case UNITY_BUNDLE:case UNITY_ASSET:case SQLITE:case PNG:case JPEG:case WEBP:case APK_ZIP:case ZIP:case AXML:case ARSC:return true;default:return false;}}
    private void openSpecialized(){
        if(format==null)return;
        try{
            switch(format.kind){
                case DEX:startActivity(new Intent(this,DecompilerActivity.class));break;
                case ELF:startActivity(new Intent(this,NativeWorkspaceActivity.class));break;
                case IL2CPP_METADATA:case UNITY_BUNDLE:case UNITY_ASSET:startActivity(new Intent(this,ReWorkspaceActivity.class));break;
                case SQLITE:case PNG:case JPEG:case WEBP:case APK_ZIP:case ZIP:case AXML:case ARSC:persistPreview(editedBytes());startActivity(new Intent(this,StructuredFilePreviewActivity.class));break;
                default:toast("Для этого формата отдельный viewer ещё не требуется");
            }
        }catch(Exception e){AnalysisJournal.exception(this,"FILE_PREVIEW_FAILED",e);toast("Не удалось открыть preview: "+e.getMessage());}
    }

    private String display(Uri uri){String d=uri.getLastPathSegment();try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())d=c.getString(0);}catch(Exception ignored){}return d==null?"file":d;}
    private void setOpened(byte[] data,String name,File apk,String entry,String openedStatus)throws Exception{displayName=name;sourceApk=apk;targetEntry=entry;original=data;sourceEntrySha256=apk!=null&&entry!=null?sha256(data):"";format=FileFormatDetector.detect(entry==null?name:entry,data);hexMode=format.defaultHex;render();status.setText(openedStatus+"\nФормат: "+format.label+" · маршрут: "+format.route);AnalysisJournal.append(this,"FILE_OPEN","Workspace file opened",new JSONObjectSafe().put("name",name).put("format",format.kind.name()).put("bytes",data.length).put("sourceEntrySha256",sourceEntrySha256).json());}
    private void openUri(Uri uri){try(InputStream in=getContentResolver().openInputStream(uri)){if(in==null)throw new IOException("openInputStream returned null");byte[] data=readLimited(in,MAX_EDIT_BYTES+1);if(data.length>MAX_EDIT_BYTES)throw new IOException("Файл больше 16 МБ. Для больших файлов используйте Native/Decompiler/RE workspace вместо встроенного редактора.");setOpened(data,display(uri),null,null,"Открыт внешний файл. Изменения можно экспортировать, но автоматическая сборка APK доступна только для entry из APK.");}catch(Exception e){toast(e.getMessage());}}

    private void showApkSources(){List<File> files=new ArrayList<>();List<String> labels=new ArrayList<>();try{TargetResolver.Target target=TargetResolver.resolve(app);TargetResolver.requireVerified(target,app.cancelled);for(TargetResolver.Member member:target.members){files.add(member.file);labels.add(member.name);}}catch(Exception e){toast("Target не готов: "+e.getMessage());return;}
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
    private void saveWorking(){try{byte[] b=editedBytes();Files.write(app.file("workspace-edit.bin").toPath(),b);original=b;format=FileFormatDetector.detect(targetEntry==null?displayName:targetEntry,b);meta.setText(displayName+" · "+b.length+" bytes · рабочая копия сохранена\n"+BinaryFormatInspector.inspect(format,b,displayName));status.setText("Рабочая копия сохранена. SHA-256 исходного APK entry сохранён отдельно и не меняется.");updateButtons();}catch(Exception e){toast("Ошибка: "+e.getMessage());}}
    private void exportEdited(){if(original.length==0)return;startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,targetEntry==null?displayName:new File(targetEntry).getName()),EXPORT_FILE);}
    private void writeEdited(Uri uri){try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){if(out==null)throw new IOException("openOutputStream returned null");out.write(editedBytes());out.flush();status.setText("Изменённый файл экспортирован.");}catch(Exception e){deleteCreatedDocument(uri);toast(e.getMessage());}}

    private void persistPreview(byte[] bytes)throws Exception{
        File destination=app.file("workspace-preview.bin"),tmp=app.file("workspace-preview.bin.part");Files.deleteIfExists(tmp.toPath());try{Files.write(tmp.toPath(),bytes);Files.move(tmp.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}
        JSONObject preview=new JSONObject().put("schema","modkit-workspace-preview-1.0").put("name",targetEntry==null?displayName:targetEntry).put("displayName",displayName).put("bytes",bytes.length).put("sha256",sha256(bytes)).put("format",format==null?"":format.kind.name()).put("createdAtMs",System.currentTimeMillis());if(sourceApk!=null)preview.put("sourceApk",sourceApk.getCanonicalPath());if(targetEntry!=null)preview.put("targetEntry",targetEntry);writeAtomicJson(app.file("workspace-preview.json"),preview);
    }

    private TargetResolver.Member sourceMember(TargetResolver.Target target)throws Exception{if(sourceApk==null)throw new IOException("Source APK отсутствует");String source=sourceApk.getCanonicalPath();for(TargetResolver.Member member:target.members)if(member.file.getCanonicalPath().equals(source))return member;throw new IOException("Открытый APK больше не принадлежит текущему canonical target");}
    private void preparePatch(){try{
        if(sourceApk==null||targetEntry==null)throw new IOException("Откройте entry из APK");if(sourceEntrySha256.isEmpty())throw new IOException("SHA-256 исходного APK entry отсутствует; откройте entry заново");TargetResolver.Target target=TargetResolver.resolve(app);JSONObject verification=TargetResolver.requireVerified(target,app.cancelled);TargetResolver.Member member=sourceMember(target);byte[] b=editedBytes();String originalSha=sourceEntrySha256,editedSha=sha256(b);
        File zip=app.file("workspace-patch.zip"),tmp=app.file("workspace-patch.zip.tmp");Files.deleteIfExists(tmp.toPath());
        JSONObject binding=new JSONObject().put("schema","modkit-workspace-source-1.1").put("targetId",target.targetId).put("targetFingerprint",target.fingerprint).put("targetDigest",verification.optString("currentTargetDigest")).put("sourceApk",sourceApk.getCanonicalPath()).put("sourceSplitIndex",member.index).put("sourceSplitName",member.name).put("sourceSplitExpectedSha256",member.sha256).put("targetEntry",targetEntry).put("originalEntrySha256",originalSha).put("editedEntrySha256",editedSha).put("createdAtMs",System.currentTimeMillis());
        JSONObject manifest=new JSONObject().put("schema","modkit-workspace-patch-1.1").put("target",new JSONObject(binding.toString())).put("entries",new JSONArray().put(new JSONObject().put("packPath","files/edit.bin").put("targetPath",targetEntry).put("display",displayName).put("originalSha256",originalSha).put("editedSha256",editedSha)));
        try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){ZipEntry edit=new ZipEntry("files/edit.bin");edit.setTime(0L);z.putNextEntry(edit);z.write(b);z.closeEntry();ZipEntry metaEntry=new ZipEntry("modkit-workspace.json");metaEntry.setTime(0L);z.putNextEntry(metaEntry);z.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));z.closeEntry();}
        Files.move(tmp.toPath(),zip.toPath(),StandardCopyOption.REPLACE_EXISTING);writeAtomicJson(app.file("workspace-source.json"),binding);AnalysisJournal.append(this,"WORKSPACE_PATCH_READY","File Workspace patch bound to canonical target",binding);
        startWork(new Intent().putExtra("op","workspace_inspect").putExtra("source",sourceApk.getCanonicalPath()));status.setText("Patch Pack подготовлен и привязан к target SHA; запускаю проверку совместимости…");updateButtons();
    }catch(Exception e){AnalysisJournal.exception(this,"WORKSPACE_PATCH_FAILED",e);toast(e.getMessage());}}

    private void buildPatched(){if(!app.file("workspace-patch.zip").isFile()||!app.file("workspace-source.json").isFile()){toast("Сначала подготовьте Patch Pack");return;}boolean set=isInstalledSet();String title=set?"modkit-workspace-test.apks":"modkit-workspace-test.apk";startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(set?"application/zip":"application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,title),BUILD_APK);}
    private boolean isInstalledSet(){try{return TargetResolver.resolve(app).apkSet;}catch(Exception e){return false;}}
    private void deleteCreatedDocument(Uri uri){if(uri==null)return;try{android.provider.DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    private void startBuild(Uri uri){
        if(app.busy.get()){deleteCreatedDocument(uri);toast("Сейчас выполняется другая операция");return;}
        if(!app.file("workspace-source.json").isFile()||!app.file("workspace-patch.zip").isFile()){deleteCreatedDocument(uri);toast("Patch Pack/binding отсутствует; подготовьте заново");return;}
        app.cancelled.set(false);app.busy.set(true);app.progress("File Workspace build: проверяю canonical target…");Intent i=new Intent(this,WorkspaceBuildGuardService.class).putExtra("uri",uri.toString());try{startForegroundService(i);}catch(Exception e){app.busy.set(false);app.revision++;deleteCreatedDocument(uri);AnalysisJournal.exception(this,"WORKSPACE_BUILD_GUARD_START_FAILED",e);app.progress("File Workspace: не удалось запустить build guard: "+e.getMessage());toast("Не удалось запустить проверку сборки");}
    }
    private boolean startWork(Intent i){Uri output=null;String uriText=i.getStringExtra("uri");if(uriText!=null&&!uriText.isEmpty())output=Uri.parse(uriText);if(app.busy.get()){if(output!=null)deleteCreatedDocument(output);toast("Сейчас выполняется другая операция");return false;}app.cancelled.set(false);app.busy.set(true);app.progress("Подготовка…");i.setClass(this,WorkerService.class);try{startForegroundService(i);return true;}catch(Exception e){app.busy.set(false);app.revision++;if(output!=null)deleteCreatedDocument(output);app.progress("File Workspace: не удалось запустить операцию: "+e.getMessage());toast("Не удалось запустить File Workspace-операцию");return false;}}

    private void refreshStatus(){if(revision==app.revision)return;revision=app.revision;if(app.status!=null&&!app.status.isEmpty())status.setText(app.status);updateButtons();}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;if(req==OPEN_FILE)openUri(data.getData());else if(req==EXPORT_FILE)writeEdited(data.getData());else if(req==BUILD_APK)startBuild(data.getData());}
    @Override protected void onResume(){super.onResume();handler.post(poll);}
    @Override protected void onPause(){handler.removeCallbacks(poll);super.onPause();}

    private static void writeAtomicJson(File destination,JSONObject value)throws Exception{File tmp=new File(destination.getParentFile(),destination.getName()+".part");Files.deleteIfExists(tmp.toPath());try{Files.write(tmp.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(tmp.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}}
    private static String sha256(byte[] value)throws Exception{java.security.MessageDigest d=java.security.MessageDigest.getInstance("SHA-256");byte[] hash=d.digest(value);StringBuilder out=new StringBuilder(64);for(byte b:hash)out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();}
    private static byte[] readLimited(InputStream in,int limit)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[65536];int n,total=0;while((n=in.read(buf))!=-1){total+=n;if(total>limit){out.write(buf,0,n-(total-limit));break;}out.write(buf,0,n);}return out.toByteArray();}
    private static String toHex(byte[] b){StringBuilder s=new StringBuilder(b.length*3);for(int i=0;i<b.length;i++){if(i>0){if(i%16==0)s.append('\n');else s.append(' ');}s.append(String.format(Locale.ROOT,"%02X",b[i]&255));}return s.toString();}
    private static byte[] fromHex(String s)throws IOException{String clean=s.replaceAll("[^0-9A-Fa-f]","");if((clean.length()&1)!=0)throw new IOException("HEX содержит нечётное число цифр");byte[] out=new byte[clean.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(clean.substring(i*2,i*2+2),16);return out;}

    /** Tiny builder which absorbs JSONObject checked exceptions for diagnostics-only metadata. */
    private static final class JSONObjectSafe{private final JSONObject value=new JSONObject();JSONObjectSafe put(String k,Object v){try{value.put(k,v);}catch(Exception ignored){}return this;}JSONObject json(){return value;}}
}
