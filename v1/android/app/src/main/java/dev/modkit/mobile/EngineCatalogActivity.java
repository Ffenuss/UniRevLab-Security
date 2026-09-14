package dev.modkit.mobile;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

/** Human-readable view of bundled engines and external bridge contracts. */
public class EngineCatalogActivity extends AppCompatActivity {
    private int dp(int n) { return (int)(n * getResources().getDisplayMetrics().density); }
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(31,41,55);}
    private int builtin(){return dark()?Color.rgb(27,52,43):Color.rgb(237,247,243);}
    private int optional(){return dark()?Color.rgb(37,42,49):Color.rgb(247,248,250);}
    private TextView text(String s, int size) { TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(fg());t.setPadding(0,dp(5),0,dp(5));return t; }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));scroll.addView(root);setContentView(scroll);
        TextView title=text("Движки ModKit 1.0",28);title.setTypeface(null,android.graphics.Typeface.BOLD);root.addView(title);
        root.addView(text("Единый registry выбирает analyzer / decoder / decompiler / reconstructor / runtime backend по типу артефакта. ✓ = выполняется внутри APK, ○ = внешний движок подключён через Evidence Bridge.",14));
        Button bridge=new Button(this);bridge.setText("Импорт Ghidra / Rizin / Cpp2IL / Hermes / Frida…");bridge.setOnClickListener(v->startActivity(new Intent(this,EngineBridgeActivity.class)));root.addView(bridge);
        try {
            if(!Python.isStarted()) Python.start(new AndroidPlatform(this));
            PyObject module=Python.getInstance().getModule("modkit.engines");
            JSONObject catalog=new JSONObject(module.callAttr("catalog_json").toString());
            root.addView(text("Всего entry points: "+catalog.optInt("count")+" · встроено: "+catalog.optInt("bundled")+" · bridge/optional: "+catalog.optInt("optional"),14));
            JSONArray engines=catalog.optJSONArray("engines");
            if(engines!=null) for(int i=0;i<engines.length();i++){
                JSONObject e=engines.optJSONObject(i);if(e==null)continue;
                boolean bundled=e.optBoolean("bundled");
                TextView row=text((bundled?"✓ ":"○ ")+e.optString("name")+"\n"+e.optString("engine_id")+" · "+e.optString("kind")+" · "+e.optString("state")+"\n"+e.optJSONArray("capabilities"),13);
                row.setPadding(dp(12),dp(10),dp(12),dp(10));row.setBackgroundColor(bundled?builtin():optional());
                LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(6),0,dp(6));root.addView(row,lp);
            }
        } catch(Exception e) {
            root.addView(text("Не удалось открыть engine registry: "+e.getMessage(),14));
        }
    }
}
