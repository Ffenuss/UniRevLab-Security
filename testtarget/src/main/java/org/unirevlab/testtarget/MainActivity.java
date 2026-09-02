package org.unirevlab.testtarget;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setPadding(32, 32, 32, 32);
        text.setText(buildStatus(getIntent()));
        text.setOnClickListener(v -> startActivity(new Intent(this, WebViewLabActivity.class)));
        setContentView(text);
    }

    private String buildStatus(Intent intent) {
        Uri uri = intent == null ? null : intent.getData();
        boolean premium = SecuritySurfaces.isPremiumUnlocked(this);
        boolean integrity = SecuritySurfaces.localIntegrityGate(this);
        boolean rooted = SecuritySurfaces.rootIndicatorPresent();
        boolean emulator = SecuritySurfaces.emulatorIndicatorPresent();
        return "UniRevLab TestTarget\n" +
                "premium=" + premium + "\n" +
                "integrity=" + integrity + "\n" +
                "root=" + rooted + " emulator=" + emulator + "\n" +
                "uri=" + (uri == null ? "<none>" : uri.toString()) + "\n\n" +
                "Tap to open the WebView fixture.";
    }
}
