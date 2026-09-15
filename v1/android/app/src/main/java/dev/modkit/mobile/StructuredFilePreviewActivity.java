package dev.modkit.mobile;

import android.app.Activity;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Bounded read-only viewers for formats which should not be interpreted as UTF-8 source. */
public class StructuredFilePreviewActivity extends Activity {
    private static final int MAX_ARCHIVE_ROWS=1200;
    private static final int MAX_SQLITE_ROWS=400;
    private static final int MAX_RESOURCE_CHUNKS=600;
    private App app;private LinearLayout root;

    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(Color.rgb(225,230,235));t.setTextIsSelectable(true);t.setPadding(0,dp(5),0,dp(5));return t;}

    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(16),dp(16),dp(24));root.setBackgroundColor(Color.rgb(16,20,24));scroll.addView(root);setContentView(scroll);TextView title=text("Структурный просмотр",26);title.setTypeface(null,Typeface.BOLD);root.addView(title);render();}

    private void render(){
        File file=app.file("workspace-preview.bin"),metaFile=app.file("workspace-preview.json");if(!file.isFile()){root.addView(text("Preview отсутствует. Вернитесь в File Workspace и откройте файл заново.",14));return;}
        JSONObject meta=read(metaFile);String name=meta==null?"file":meta.optString("name","file");byte[] header=readPrefix(file,64*1024);FileFormatDetector.Result format=FileFormatDetector.detect(name,header);root.addView(text(name+" · "+file.length()+" bytes · "+format.label,14));
        try{
            switch(format.kind){
                case PNG:case JPEG:case WEBP:renderImage(file);break;
                case APK_ZIP:case ZIP:renderArchive(file);break;
                case SQLITE:renderSqlite(file);break;
                case AXML:case ARSC:renderResourceChunks(header,file.length(),format);break;
                default:root.addView(text(BinaryFormatInspector.inspect(format,header,name),13));break;
            }
        }catch(Throwable e){AnalysisJournal.exception(this,"STRUCTURED_PREVIEW_FAILED",e);root.addView(text("Не удалось построить структурный preview: "+e.getClass().getSimpleName()+" · "+safe(e),13));}
    }

    private void renderImage(File file){
        BitmapFactory.Options bounds=new BitmapFactory.Options();bounds.inJustDecodeBounds=true;BitmapFactory.decodeFile(file.getAbsolutePath(),bounds);int sample=1;while(bounds.outWidth/sample>2048||bounds.outHeight/sample>2048)sample*=2;BitmapFactory.Options options=new BitmapFactory.Options();options.inSampleSize=Math.max(1,sample);options.inPreferredConfig=Bitmap.Config.ARGB_8888;Bitmap bitmap=BitmapFactory.decodeFile(file.getAbsolutePath(),options);root.addView(text("Image: "+bounds.outWidth+"×"+bounds.outHeight+" · preview sample 1/"+Math.max(1,sample),13));if(bitmap==null){root.addView(text("Android BitmapFactory не смог декодировать изображение.",13));return;}ImageView view=new ImageView(this);view.setAdjustViewBounds(true);view.setScaleType(ImageView.ScaleType.FIT_CENTER);view.setImageBitmap(bitmap);root.addView(view,new LinearLayout.LayoutParams(-1,-2));
    }

    private void renderArchive(File file)throws Exception{
        long files=0,uncompressed=0,compressed=0;List<String> rows=new ArrayList<>();try(ZipFile zip=new ZipFile(file)){Enumeration<? extends ZipEntry> it=zip.entries();while(it.hasMoreElements()){ZipEntry e=it.nextElement();if(e.isDirectory())continue;files++;if(e.getSize()>0)uncompressed+=e.getSize();if(e.getCompressedSize()>0)compressed+=e.getCompressedSize();if(rows.size()<MAX_ARCHIVE_ROWS)rows.add(e.getName()+" · "+e.getSize()+" B · "+(e.getMethod()==ZipEntry.STORED?"STORE":"DEFLATE"));}}Collections.sort(rows,String.CASE_INSENSITIVE_ORDER);root.addView(text("Archive entries: "+files+" · uncompressed "+human(uncompressed)+" · compressed "+human(compressed)+(files>rows.size()?" · показано "+rows.size():""),13));StringBuilder out=new StringBuilder();for(String row:rows)out.append(row).append('\n');TextView listing=text(out.toString(),11);listing.setTypeface(Typeface.MONOSPACE);root.addView(listing);
    }

    private void renderSqlite(File file){
        byte[] h=readPrefix(file,100);int page=h.length>=18?u16be(h,16):0;if(page==1)page=65536;long change=h.length>=28?u32be(h,24):-1;long pages=h.length>=32?u32be(h,28):-1;root.addView(text("SQLite format 3 · page_size="+page+" · change_counter="+change+" · pages="+pages,13));SQLiteDatabase db=null;Cursor cursor=null;try{db=SQLiteDatabase.openDatabase(file.getAbsolutePath(),null,SQLiteDatabase.OPEN_READONLY|SQLiteDatabase.NO_LOCALIZED_COLLATORS);cursor=db.rawQuery("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT "+MAX_SQLITE_ROWS,null);StringBuilder out=new StringBuilder();int rows=0;while(cursor.moveToNext()){rows++;out.append(cursor.getString(0)).append(" · ").append(cursor.getString(1)).append(" · table=").append(cursor.getString(2));String sql=cursor.getString(3);if(sql!=null&&!sql.isEmpty())out.append("\n  ").append(shorten(sql,500));out.append('\n');}root.addView(text("sqlite_master rows: "+rows,13));TextView listing=text(out.toString(),11);listing.setTypeface(Typeface.MONOSPACE);root.addView(listing);}catch(Throwable e){root.addView(text("SQLite read-only catalog недоступен: "+e.getClass().getSimpleName()+" · "+safe(e)+". HEX-редактор остаётся доступен в File Workspace.",12));}finally{if(cursor!=null)cursor.close();if(db!=null)db.close();}
    }

    private void renderResourceChunks(byte[] prefix,long total,FileFormatDetector.Result format){
        StringBuilder out=new StringBuilder();int pos=0,count=0;while(pos+8<=prefix.length&&count<MAX_RESOURCE_CHUNKS){int type=u16le(prefix,pos),header=u16le(prefix,pos+2);long size=u32le(prefix,pos+4);if(header<8||size<header||size<=0||pos+size>total)break;out.append(String.format(Locale.ROOT,"0x%08X · type=0x%04X · header=%d · size=%d",pos,type,header,size)).append('\n');count++;if(size>Integer.MAX_VALUE)break;pos+=(int)size;if(pos>=prefix.length)break;}root.addView(text(format.label+" · chunks parsed from bounded prefix: "+count+" · total "+human(total),13));TextView listing=text(out.length()==0?"Chunk table не распознана в первых 64 KiB.":out.toString(),11);listing.setTypeface(Typeface.MONOSPACE);root.addView(listing);
    }

    private JSONObject read(File file){try{return file.isFile()?new JSONObject(Io.readUtf8(file)):null;}catch(Exception e){return null;}}
    private static byte[] readPrefix(File file,int max){try(java.io.FileInputStream in=new java.io.FileInputStream(file)){byte[] out=new byte[(int)Math.min(file.length(),max)];int pos=0,n;while(pos<out.length&&(n=in.read(out,pos,out.length-pos))>0)pos+=n;if(pos==out.length)return out;return java.util.Arrays.copyOf(out,pos);}catch(Exception e){return new byte[0];}}
    private static int u16le(byte[] b,int p){return(b[p]&255)|((b[p+1]&255)<<8);}private static int u16be(byte[] b,int p){return((b[p]&255)<<8)|(b[p+1]&255);}private static long u32le(byte[] b,int p){return((long)b[p]&255)|(((long)b[p+1]&255)<<8)|(((long)b[p+2]&255)<<16)|(((long)b[p+3]&255)<<24);}private static long u32be(byte[] b,int p){return(((long)b[p]&255)<<24)|(((long)b[p+1]&255)<<16)|(((long)b[p+2]&255)<<8)|((long)b[p+3]&255);}
    private static String human(long b){if(b<1024)return b+" B";if(b<1024L*1024L)return String.format(Locale.ROOT,"%.1f KiB",b/1024.0);return String.format(Locale.ROOT,"%.1f MiB",b/1048576.0);}
    private static String shorten(String s,int n){return s.length()<=n?s:s.substring(0,n)+"…";}private static String safe(Throwable e){String m=e==null?null:e.getMessage();return m==null?(e==null?"unknown":e.getClass().getSimpleName()):m;}
}
