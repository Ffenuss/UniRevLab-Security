package dev.modkit.mobile;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

/** Human-readable view of bundled engines and prepared extension points. */
public class EngineCatalogActivity extends AppCompatActivity {
    private int dp(int n) { return (int)(n * getResources().getDisplayMetrics().density); }
    private TextView text(String s, int size) { TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(Color.rgb(31,41,55));t.setPadding(0,dp(5),0,dp(5));return t; }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(18),dp(18),dp(28));scroll.addView(root);setContentView(scroll);
        TextView title=text("Движки ModKit 1.0",28);title.setTypeface(null,android.graphics.Typeface.BOLD);root.addView(title);
        root.addView(text("Единый registry: один pipeline выбирает подходящий analyzer / decoder / decompiler / runtime backend по типу артефакта.",14));
        try {
            if(!Python.isStarted()) Python.start(new AndroidPlatform(this));
            PyObject module=Python.getInstance().getModule("modkit.engines");
            JSONObject catalog=new JSONObject(module.callAttr("catalog_json").toString());
            root.addView(text("Всего entry points: "+catalog.optInt("count")+" · bundled: "+catalog.optInt("bundled")+" · optional/prepared: "+catalog.optInt("optional"),14));
            JSONArray engines=catalog.optJSONArray("engines");
            if(engines!=null) for(int i=0;i<engines.length();i++){
                JSONObject e=engines.optJSONObject(i);if(e==null)continue;
                boolean bundled=e.optBoolean("bundled");
                TextView row=text((bundled?"✓ ":"○ ")+e.optString("name")+"\n"+e.optString("engine_id")+" · "+e.optString("kind")+" · "+e.optString("state")+"\n"+e.optJSONArray("capabilities"),13);
                row.setPadding(dp(12),dp(10),dp(12),dp(10));
                row.setBackgroundColor(bundled?Color.rgb(237,247,243):Color.rgb(247,248,250));
                LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(6),0,dp(6));root.addView(row,lp);
            }
        } catch(Exception e) {
            root.addView(text("Не удалось открыть engine registry: "+e.getMessage(),14));
        }
    }
}
