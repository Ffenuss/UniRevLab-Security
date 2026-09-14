package dev.modkit.mobile;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/** Compatibility entry point for pre-1.1 intents. Redirects to the unified automatic analysis UI. */
public class SimpleModeActivity extends AppCompatActivity {
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        Intent next=new Intent(this,AutoAnalysisActivity.class);
        next.putExtra("autoStart",getIntent()==null||getIntent().getBooleanExtra("autoStart",true));
        startActivity(next);
        finish();
    }
}
