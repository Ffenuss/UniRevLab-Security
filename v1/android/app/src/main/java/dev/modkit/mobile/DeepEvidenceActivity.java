package dev.modkit.mobile;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import org.json.JSONArray;
import org.json.JSONObject;

/** Compact human-readable view over embedded Lua/Hermes/native/Cocos/Flutter evidence. */
public class DeepEvidenceActivity extends AppCompatActivity {
    private App app;private LinearLayout root,cards;private TextView summary;
    private int dp(int n){return(int)(n*getResources().getDisplayMetrics().density);}
    private boolean dark(){return(getResources().getConfiguration().uiMode&android.content.res.Configuration.UI_MODE_NIGHT_MASK)==android.content.res.Configuration.UI_MODE_NIGHT_YES;}
    private int bg(){return dark()?Color.rgb(15,19,23):Color.rgb(245,247,250);}private int surface(){return dark()?Color.rgb(24,29,34):Color.WHITE;}private int fg(){return dark()?Color.rgb(228,232,237):Color.rgb(29,39,52);}private int muted(){return dark()?Color.rgb(157,168,180):Color.rgb(92,105,121);}private int outline(){return dark()?Color.rgb(57,66,76):Color.rgb(220,226,233);}private int action(){return dark()?Color.rgb(36,54,58):Color.rgb(232,244,242);}
    private TextView text(String s,int sp){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(fg());t.setPadding(0,dp(4),0,dp(4));t.setTextIsSelectable(true);return t;}
    private JSONObject json(String name){try{return new JSONObject(Io.readUtf8(app.file(name)));}catch(Exception e){return null;}}
    private String state(JSONObject value){if(value==null)return "нет отчёта";if(value.optBoolean("available")||value.optBoolean("detected")||value.optInt("analyzedLibraryCount")>0)return "evidence найден";return "не обнаружено";}
    private String value(JSONObject o,String key){Object v=o==null?null:o.opt(key);return v==null||v==JSONObject.NULL?"0":String.valueOf(v);}

    @Override public void onCreate(Bundle state){super.onCreate(state);app=(App)getApplication();ScrollView scroll=new ScrollView(this);root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(16),dp(18),dp(16),dp(30));root.setBackgroundColor(bg());scroll.addView(root);setContentView(scroll);
        TextView title=text("Deep evidence",29);title.setTypeface(null,Typeface.BOLD);root.addView(title);TextView note=text("Сводка встроенных backend'ов. Exact RVA означает подтверждённый статический адрес в бинарнике; structural/indirect evidence не выдаётся за runtime-наблюдение. Нажмите находку, чтобы увидеть исходный JSON evidence.",13);note.setTextColor(muted());root.addView(note);
        MaterialButton refresh=new MaterialButton(this);refresh.setText("Обновить сводку");refresh.setAllCaps(false);refresh.setTextColor(fg());refresh.setBackgroundTintList(ColorStateList.valueOf(action()));refresh.setOnClickListener(v->render());root.addView(refresh);
        summary=text("",14);root.addView(summary);cards=new LinearLayout(this);cards.setOrientation(LinearLayout.VERTICAL);root.addView(cards);render();
    }

    private void card(String title,String subtitle,String body,JSONObject report){MaterialCardView c=new MaterialCardView(this);c.setCardBackgroundColor(surface());c.setStrokeColor(outline());c.setStrokeWidth(dp(1));c.setRadius(dp(16));LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(14),dp(11),dp(14),dp(13));c.addView(box);TextView h=text(title,18);h.setTypeface(null,Typeface.BOLD);box.addView(h);TextView s=text(subtitle,13);s.setTextColor(muted());box.addView(s);TextView b=text(body,14);box.addView(b);appendFindings(box,report);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(0,dp(6),0,dp(6));cards.addView(c,lp);}

    private void appendFindings(LinearLayout box,JSONObject report){if(report==null)return;JSONArray rows=report.optJSONArray("findings");if(rows==null||rows.length()==0)return;TextView label=text("Примеры evidence",13);label.setTypeface(null,Typeface.BOLD);box.addView(label);int shown=0;for(int i=0;i<rows.length()&&shown<6;i++){JSONObject row=rows.optJSONObject(i);if(row==null)continue;String title=row.optString("title",row.optString("function",row.optString("kind","evidence")));StringBuilder meta=new StringBuilder();String kind=row.optString("kind","");String status=row.optString("status","");String entry=row.optString("entry",row.optString("library",""));if(!kind.isEmpty())meta.append(kind);if(!status.isEmpty()){if(meta.length()>0)meta.append(" · ");meta.append(status);}if(!entry.isEmpty()){if(meta.length()>0)meta.append("\n");meta.append(entry);}if(row.has("rva")){if(meta.length()>0)meta.append(" · ");meta.append("RVA 0x").append(Long.toHexString(row.optLong("rva")));}if(row.has("nativeRva")){if(meta.length()>0)meta.append(" · ");meta.append("native RVA 0x").append(Long.toHexString(row.optLong("nativeRva")));}TextView item=text("• "+title+(meta.length()>0?"\n  "+meta:""),13);item.setPadding(dp(5),dp(5),dp(5),dp(5));item.setOnClickListener(v->new AlertDialog.Builder(this).setTitle(title).setMessage(row.toString()).setPositiveButton("OK",null).show());box.addView(item);shown++;}}

    private void render(){cards.removeAllViews();JSONObject lua=json("lua-deep.json"),hermes=json("hermes-deep.json"),nativeReport=json("native-deep.json"),cocos=json("cocos-deep.json"),flutter=json("flutter-deep.json");int available=0;if(lua!=null&&lua.optBoolean("available"))available++;if(hermes!=null&&hermes.optBoolean("available"))available++;if(nativeReport!=null&&nativeReport.optInt("analyzedLibraryCount")>0)available++;if(cocos!=null&&cocos.optBoolean("available"))available++;if(flutter!=null&&flutter.optBoolean("detected"))available++;summary.setText("Deep backend'ов с evidence: "+available+"/5");
        int decoded=0,opaque=0;if(lua!=null){JSONArray chunks=lua.optJSONArray("chunks");if(chunks!=null)for(int i=0;i<chunks.length();i++){JSONObject row=chunks.optJSONObject(i);if(row==null)continue;if("BYTECODE_DISASSEMBLED".equals(row.optString("status")))decoded++;if("OPAQUE".equals(row.optString("recoveryLevel")))opaque++;}}card("Lua bytecode",state(lua),"chunks: "+value(lua,"chunkCount")+" · decoded 5.1–5.3: "+decoded+" · opaque/custom: "+opaque+" · findings: "+value(lua,"findingCount"),lua);
        card("Hermes HBC",state(hermes),"bundles: "+value(hermes,"bundleCount")+" · findings: "+value(hermes,"findingCount"),hermes);
        long direct=0,tail=0,indirect=0;if(nativeReport!=null){JSONArray libs=nativeReport.optJSONArray("libraries");if(libs!=null)for(int i=0;i<libs.length();i++){JSONObject row=libs.optJSONObject(i);if(row==null)continue;direct+=row.optLong("directCallCount");tail+=row.optLong("tailCallCount");indirect+=row.optLong("indirectSlotCount");}}card("Native ARM64 / ELF",state(nativeReport),"libraries: "+value(nativeReport,"analyzedLibraryCount")+" · findings: "+value(nativeReport,"findingCount")+" · direct BL: "+direct+" · tail B: "+tail+" · indirect slots: "+indirect,nativeReport);
        card("Cocos script ↔ native",state(cocos),"confidence: "+(cocos==null?"—":cocos.optString("detectionConfidence","—"))+" · scripts: "+value(cocos,"scriptArtifactCount")+" · native libs: "+value(cocos,"nativeLibraryCount")+" · bridges: "+value(cocos,"bridgeSymbolCount")+" · correlations: "+value(cocos,"correlationCount"),cocos);
        card("Flutter / Dart AOT",state(flutter),"artifacts: "+value(flutter,"artifactCount")+" · findings: "+value(flutter,"findingCount")+" · original Dart source не заявляется как восстановленный",flutter);
    }
}
