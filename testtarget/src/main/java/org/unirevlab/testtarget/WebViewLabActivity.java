package org.unirevlab.testtarget;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;

public final class WebViewLabActivity extends Activity {
    @Override
    @SuppressWarnings("deprecation")
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        WebView.setWebContentsDebuggingEnabled(true);
        webView.addJavascriptInterface(new LabBridge(), "LabBridge");
        webView.loadDataWithBaseURL(
                SecuritySurfaces.FIXTURE_HTTP_ENDPOINT,
                "<html><body>UniRevLab controlled WebView fixture</body></html>",
                "text/html",
                "UTF-8",
                null);
        setContentView(webView);
    }

    public final class LabBridge {
        @JavascriptInterface
        public String fixtureState() {
            return "premium=" + SecuritySurfaces.isPremiumUnlocked(WebViewLabActivity.this);
        }
    }
}
