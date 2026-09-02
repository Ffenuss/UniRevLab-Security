package org.unirevlab.testtarget;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class AuthActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String candidate = getIntent() == null ? null : getIntent().getStringExtra("license");
        boolean accepted = SecuritySurfaces.grantFixtureLicense(this, candidate);
        TextView text = new TextView(this);
        text.setPadding(32, 32, 32, 32);
        text.setText("Fixture local license accepted=" + accepted);
        setContentView(text);
    }
}
