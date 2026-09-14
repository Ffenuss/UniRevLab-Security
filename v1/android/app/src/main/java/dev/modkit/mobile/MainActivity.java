package dev.modkit.mobile;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/** Compatibility entry point for old shortcuts and notifications. */
public class MainActivity extends AppCompatActivity {
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        Intent next=new Intent(this,FullModeActivity.class);
        if(getIntent()!=null&&getIntent().getBooleanExtra("autoInstalledPicker",false))next.putExtra("openTargetPicker",true);
        startActivity(next);
        finish();
    }
}
