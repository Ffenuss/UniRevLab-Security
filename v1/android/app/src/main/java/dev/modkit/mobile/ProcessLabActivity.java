package dev.modkit.mobile;

import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Root-aware process observation workspace. Root is requested only by explicit button press. */
public class ProcessLabActivity extends AppCompatActivity {
    private static final int SAVE_SESSION = 701;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private App app;
    private LinearLayout root, processList, sessionBox;
    private TextView rootState, selectedState, sessionState, engineState;
    private EditText filter;
    private ProgressBar progress;
    private Button refreshButton, attachButton, detachButton, saveButton, correlateButton;
    private RootAccess.ProbeResult rootProbe;
    private RootProcessEngine.ProcessInfo selected;
    private RootProcessEngine.RuntimeSession session;
    private JSONObject correlation;
    private List<RootProcessEngine.ProcessInfo> processes = new ArrayList<>();

    private int dp(int n) { return (int) (n * getResources().getDisplayMetrics().density); }
    private TextView text(String value, int sp) {
        TextView view = new TextView(this);
        view.setText(value); view.setTextSize(sp); view.setTextColor(Color.rgb(31, 41, 55));
        view.setPadding(0, dp(5), 0, dp(5)); return view;
    }
    private Button button(String label, LinearLayout parent, View.OnClickListener listener) {
        com.google.android.material.button.MaterialButton b = new com.google.android.material.button.MaterialButton(this);
        b.setText(label); b.setAllCaps(false); b.setOnClickListener(listener); parent.addView(b); return b;
    }
    private LinearLayout section(String title) {
        com.google.android.material.card.MaterialCardView card = new com.google.android.material.card.MaterialCardView(this);
        card.setRadius(dp(18)); card.setCardElevation(dp(1)); card.setStrokeWidth(dp(1)); card.setStrokeColor(Color.rgb(222, 228, 235));
        LinearLayout body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL); body.setPadding(dp(16), dp(12), dp(16), dp(16));
        card.addView(body); TextView h = text(title, 18); h.setTypeface(null, android.graphics.Typeface.BOLD); body.addView(h);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.setMargins(0, dp(7), 0, dp(7)); root.addView(card, lp); return body;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state); app = (App)getApplication();
        ScrollView scroll = new ScrollView(this); root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(16), dp(16), dp(16), dp(28));
        scroll.addView(root); setContentView(scroll);
        TextView title = text("Process Lab", 30); title.setTypeface(null, android.graphics.Typeface.BOLD); root.addView(title);
        root.addView(text("Root · процессы · load base · RVA→runtime VA · потоки", 14));
        root.addView(text("Root не запрашивается автоматически. Подключение читает только procfs: память процесса не открывается, не изменяется и код не внедряется.", 13));

        LinearLayout access = section("1 · Root-доступ");
        rootState = text("Root ещё не проверялся.", 14); access.addView(rootState);
        button("Проверить root", access, v -> checkRoot());
        engineState = text("Runtime backend: root-procfs · read-only. Статические RVA связываются только с наблюдаемой раскладкой загруженных модулей.", 13); access.addView(engineState);

        LinearLayout inventory = section("2 · Процессы");
        filter = new EditText(this); filter.setSingleLine(true); filter.setHint("Фильтр: package, имя, PID…"); inventory.addView(filter);
        refreshButton = button("Обновить список процессов", inventory, v -> refreshProcesses()); refreshButton.setEnabled(false);
        selectedState = text("Процесс не выбран.", 14); inventory.addView(selectedState);
        processList = new LinearLayout(this); processList.setOrientation(LinearLayout.VERTICAL); inventory.addView(processList);
        filter.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { renderProcesses(); }
            @Override public void afterTextChanged(Editable s) {}
        });

        LinearLayout attach = section("3 · Runtime session");
        progress = new ProgressBar(this); progress.setVisibility(View.GONE); attach.addView(progress);
        attachButton = button("Подключить read-only session", attach, v -> attach()); attachButton.setEnabled(false);
        correlateButton = button("Пересчитать RVA → runtime VA", attach, v -> recomputeCorrelation()); correlateButton.setEnabled(false);
        detachButton = button("Отключить session", attach, v -> detach()); detachButton.setEnabled(false);
        saveButton = button("Сохранить snapshot JSON", attach, v -> saveSession()); saveButton.setEnabled(false);
        sessionState = text("После подключения здесь появятся process status, load base модулей, точные file mappings и потоки.", 13); sessionState.setTextIsSelectable(true); attach.addView(sessionState);
        sessionBox = new LinearLayout(this); sessionBox.setOrientation(LinearLayout.VERTICAL); attach.addView(sessionBox);
    }

    private void checkRoot() {
        setBusy(true, "Запрашиваем root и проверяем фактические capabilities…");
        worker.execute(() -> {
            RootAccess.ProbeResult result = RootAccess.probe();
            main.post(() -> {
                rootProbe = result; setBusy(false, null);
                if (result.granted) {
                    rootState.setText("ROOT: подтверждён · uid=0\nCapabilities: " + String.join(", ", result.capabilities) + "\n" + result.detail);
                    refreshButton.setEnabled(true); refreshProcesses();
                } else {
                    rootState.setText("ROOT: не подтверждён\n" + result.detail + (result.hints.isEmpty() ? "" : "\nHints: " + String.join(", ", result.hints)));
                    refreshButton.setEnabled(false); processList.removeAllViews();
                }
            });
        });
    }

    private void refreshProcesses() {
        if (rootProbe == null || !rootProbe.granted) return;
        setBusy(true, "Читаем /proc через подтверждённый root…");
        worker.execute(() -> {
            try {
                List<RootProcessEngine.ProcessInfo> loaded = RootProcessEngine.listProcesses();
                main.post(() -> { processes = loaded; setBusy(false, null); renderProcesses(); });
            } catch (Exception e) {
                main.post(() -> { setBusy(false, null); showError("Не удалось получить процессы: " + e.getMessage()); });
            }
        });
    }

    private void renderProcesses() {
        if (processList == null) return;
        processList.removeAllViews();
        String q = filter == null ? "" : filter.getText().toString().trim().toLowerCase(Locale.ROOT);
        int shown = 0;
        for (RootProcessEngine.ProcessInfo p : processes) {
            String hay = (p.pid + " " + p.uid + " " + p.name + " " + p.cmdline).toLowerCase(Locale.ROOT);
            if (!q.isEmpty() && !hay.contains(q)) continue;
            if (q.isEmpty() && p.uid < 10_000) continue;
            Button row = button(p.label(), processList, v -> selectProcess(p));
            row.setGravity(android.view.Gravity.START | android.view.Gravity.CENTER_VERTICAL);
            if (++shown >= 100) break;
        }
        if (shown == 0) processList.addView(text(q.isEmpty() ? "Нет видимых app-процессов. Запустите приложение/игру или используйте поиск для системных процессов." : "Совпадений нет.", 13));
    }

    private void selectProcess(RootProcessEngine.ProcessInfo p) {
        selected = p; session = null; correlation = null; attachButton.setEnabled(true); correlateButton.setEnabled(false); detachButton.setEnabled(false); saveButton.setEnabled(false);
        selectedState.setText("Выбран: " + p.label()); sessionState.setText("Готово к read-only подключению."); sessionBox.removeAllViews();
    }

    private void attach() {
        if (selected == null || rootProbe == null || !rootProbe.granted) return;
        setBusy(true, "Открываем runtime session для PID " + selected.pid + "…");
        final RootProcessEngine.ProcessInfo target = selected;
        worker.execute(() -> {
            try {
                RootProcessEngine.RuntimeSession created = RootProcessEngine.attachReadOnly(target);
                JSONObject linked = persistAndCorrelate(created);
                main.post(() -> { session = created; correlation = linked; setBusy(false, null); renderSession(); });
            } catch (Exception e) {
                main.post(() -> { setBusy(false, null); showError("Подключение не удалось: " + e.getMessage()); });
            }
        });
    }

    private JSONObject persistAndCorrelate(RootProcessEngine.RuntimeSession created) throws Exception {
        JSONObject snapshot = created.toJson(rootProbe);
        Files.write(app.file("runtime-session.json").toPath(), snapshot.toString(2).getBytes(StandardCharsets.UTF_8));
        try {
            if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
            PyObject module = Python.getInstance().getModule("modkit.mobile.runtime_correlate");
            return new JSONObject(module.callAttr("build_workspace_correlation", getFilesDir().getPath(), app.file("runtime-session.json").getPath(), app.file("runtime-correlation.json").getPath()).toString());
        } catch (Exception e) {
            return new JSONObject().put("schema", "modkit-runtime-correlation-error-1.0").put("error", String.valueOf(e.getMessage())).put("correlationCount", 0).put("mappedRuntimeVaCount", 0);
        }
    }

    private void recomputeCorrelation() {
        if (session == null) return;
        setBusy(true, "Связываем статические RVA с наблюдаемыми load base…");
        final RootProcessEngine.RuntimeSession current = session;
        worker.execute(() -> {
            try {
                JSONObject linked = persistAndCorrelate(current);
                main.post(() -> { correlation = linked; setBusy(false, null); renderSession(); });
            } catch (Exception e) {
                main.post(() -> { setBusy(false, null); showError("Runtime correlation не построена: " + e.getMessage()); });
            }
        });
    }

    private void renderSession() {
        if (session == null) return;
        detachButton.setEnabled(true); saveButton.setEnabled(true); correlateButton.setEnabled(true); attachButton.setEnabled(true);
        String linked = "";
        if (correlation != null) {
            if (correlation.has("error")) linked = "\nRuntime correlation: ошибка · " + correlation.optString("error");
            else linked = "\nRVA correlation: " + correlation.optInt("correlationCount") + " · mapped VA: " + correlation.optInt("mappedRuntimeVaCount") + " · unresolved: " + correlation.optInt("unresolvedCount");
        }
        sessionState.setText("CONNECTED · read-only · PID " + session.process.pid + " · uid " + session.process.uid +
                "\nПотоков: " + session.threads.size() + " · module images: " + session.moduleImages.size() + " · file mappings: " + session.mappings.size() +
                (session.mapsTruncated ? " · maps output truncated" : "") + linked +
                "\nRuntime evidence не делает finding buildable автоматически.");
        sessionBox.removeAllViews();
        int limit = Math.min(30, session.moduleImages.size());
        if (limit > 0) {
            sessionBox.addView(text("Загруженные модули / load base:", 14));
            for (int i = 0; i < limit; i++) {
                RootProcessEngine.ModuleImage module = session.moduleImages.get(i);
                sessionBox.addView(text("• " + module.basename() + " @ " + String.format(Locale.ROOT, "0x%x", module.loadBase) + " · maps " + module.mappingCount + " · " + module.path, 12));
            }
            if (session.moduleImages.size() > limit) sessionBox.addView(text("… ещё " + (session.moduleImages.size() - limit) + " — в runtime-session.json", 12));
        }
    }

    private void detach() {
        session = null; correlation = null; detachButton.setEnabled(false); saveButton.setEnabled(false); correlateButton.setEnabled(false); sessionBox.removeAllViews();
        sessionState.setText("Session отключена. Процесс не изменялся.");
    }

    private void saveSession() {
        if (session == null) return;
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json")
                .addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE, "modkit-runtime-session-" + session.process.pid + ".json"), SAVE_SESSION);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != SAVE_SESSION || resultCode != RESULT_OK || data == null || data.getData() == null || session == null) return;
        Uri uri = data.getData();
        try (OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
            if (out == null) throw new java.io.IOException("output stream unavailable");
            out.write(session.toJson(rootProbe).toString(2).getBytes(StandardCharsets.UTF_8)); out.flush();
            sessionState.append("\nSnapshot сохранён. Внутренние runtime-session.json и runtime-correlation.json уже доступны Evidence Bundle.");
        } catch (Exception e) { showError("Не удалось сохранить snapshot: " + e.getMessage()); }
    }

    private void setBusy(boolean busy, String message) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (message != null) sessionState.setText(message);
        refreshButton.setEnabled(!busy && rootProbe != null && rootProbe.granted);
        attachButton.setEnabled(!busy && selected != null);
        correlateButton.setEnabled(!busy && session != null);
    }

    private void showError(String message) {
        new AlertDialog.Builder(this).setTitle("Process Lab").setMessage(message).setPositiveButton("OK", null).show();
    }

    @Override protected void onDestroy() {
        worker.shutdownNow(); super.onDestroy();
    }
}
