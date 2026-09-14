package dev.modkit.mobile;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Data-only bridge for evidence exported by heavyweight desktop/runtime engines. */
public class EngineBridgeActivity extends AppCompatActivity {
    private static final int PICK = 4127;
    private Spinner tool;
    private TextView status;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));scroll.addView(root);setContentView(scroll);
        TextView title=new TextView(this);title.setText("External Engine Bridge");title.setTextSize(26);title.setTextColor(Color.rgb(31,41,55));root.addView(title);
        TextView note=new TextView(this);note.setText("Импортирует результаты Ghidra / Rizin / Cpp2IL / Hermes / Flutter / Frida / Apktool / ptrace как подтверждаемые Evidence. ModKit не исполняет импортированный код.");note.setTextSize(14);note.setPadding(0,dp(10),0,dp(12));root.addView(note);
        tool=new Spinner(this);String[] tools={"ghidra","rizin","cpp2il","hermes","flutter","frida","apktool","ptrace"};tool.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,tools));root.addView(tool);
        Button pick=new Button(this);pick.setText("Выбрать файл результата");pick.setOnClickListener(v->pick());root.addView(pick);
        status=new TextView(this);status.setText("Файл не выбран.");status.setTextIsSelectable(true);status.setPadding(0,dp(14),0,0);root.addView(status);
    }

    private void pick(){
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("*/*");startActivityForResult(i,PICK);
    }

    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);if(request!=PICK||result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();String selected=String.valueOf(tool.getSelectedItem());status.setText("Импорт: "+selected+"…");
        new Thread(()->{
            try{
                File input=new File(getFilesDir(),"external-engine-input.dat");
                try(InputStream in=getContentResolver().openInputStream(uri)){if(in==null)throw new java.io.IOException("Не удалось открыть файл");Files.copy(in,input.toPath(), StandardCopyOption.REPLACE_EXISTING);}
                if(!Python.isStarted())Python.start(new AndroidPlatform(this));
                File out=new File(getFilesDir(),"external-evidence-"+selected+".json");
                PyObject mod=Python.getInstance().getModule("modkit.engines.bridges");
                JSONObject obj=new JSONObject(mod.callAttr("normalize_file",selected,input.getPath(),out.getPath()).toString());
                input.delete();
                runOnUiThread(()->status.setText("Готово: "+obj.optInt("recordCount")+" записей\nEngine: "+obj.optString("engineId")+"\nSHA-256: "+obj.optString("sourceSha256")+"\nСтатус: IMPORTED_EVIDENCE\nФайл включается в Evidence Bundle автоматически."));
            }catch(Exception e){runOnUiThread(()->status.setText("Ошибка импорта: "+e.getMessage()));}
        },"engine-bridge").start();
    }
}
