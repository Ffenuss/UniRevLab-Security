package dev.modkit.mobile;

import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
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

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Root-aware process observation and explicitly armed Instrumentation v1 workspace. */
public class ProcessLabActivity extends AppCompatActivity {
    private static final int SAVE_SESSION = 701;
    private static final int MAX_INSTRUMENTATION_AUDIT_EVENTS = 64;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private App app;
    private LinearLayout root, processList, sessionBox;
    private TextView rootState, selectedState, sessionState, engineState, instrumentationState;
    private EditText filter, moduleInput, rvaInput, lengthInput, expectedInput, replacementInput;
    private ProgressBar progress, instrumentationProgress;
    private Button refreshButton, attachButton, detachButton, saveButton, correlateButton;
    private Button armInstrumentationButton, resolveReadButton, writeButton, rollbackButton;
    private RootAccess.ProbeResult rootProbe;
    private RootProcessEngine.ProcessInfo selected;
    private RootProcessEngine.RuntimeSession session;
    private RootMemoryInstrumentation.ProcessLease instrumentationLease;
    private RootModuleAddressResolver.ResolvedAddress resolvedAddress;
    private RootMemoryInstrumentation.WriteReceipt lastWrite;
    private byte[] lastReadBytes;
    private JSONObject correlation;
    private List<RootProcessEngine.ProcessInfo> processes = new ArrayList<>();
    private boolean baseBusy, instrumentationBusy;

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
    private EditText field(String hint, LinearLayout parent) {
        EditText value = new EditText(this); value.setSingleLine(true); value.setHint(hint);
        value.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS); value.setSelectAllOnFocus(true);
        parent.addView(value); return value;
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
        root.addView(text("Root · процессы · load base · RVA→runtime VA · Instrumentation v1", 14));
        root.addView(text("Root не запрашивается автоматически. Runtime session остаётся read-only. Чтение/запись памяти вынесены в отдельный Instrumentation v1 и включаются только явным действием для выбранного процесса.", 13));

        LinearLayout access = section("1 · Root-доступ");
        rootState = text("Root ещё не проверялся.", 14); access.addView(rootState);
        button("Проверить root", access, v -> checkRoot());
        engineState = text("Runtime backend: root-procfs · read-only. Instrumentation backend: отдельная PID+UID+start-time lease, bounded read и compare-before-write.", 13); access.addView(engineState);

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

        LinearLayout instrumentation = section("4 · Instrumentation v1");
        instrumentation.addView(text("Сначала подключите read-only session, затем отдельно зафиксируйте instrumentation lease. Module/RVA каждый раз заново сверяются с live /proc/<pid>/maps. Запись разрешена только после чтения, с точным expected-original и проверяемым rollback.", 13));
        instrumentationProgress = new ProgressBar(this); instrumentationProgress.setVisibility(View.GONE); instrumentation.addView(instrumentationProgress);
        armInstrumentationButton = button("Включить Instrumentation v1 для session", instrumentation, v -> armInstrumentation());
        moduleInput = field("Модуль: libil2cpp.so или точный /path/to/lib.so", instrumentation);
        rvaInput = field("RVA: 0x1234", instrumentation);
        lengthInput = field("Длина чтения, байт (1…4096)", instrumentation); lengthInput.setText("16");
        resolveReadButton = button("Resolve RVA + прочитать память", instrumentation, v -> resolveAndRead());
        expectedInput = field("Expected original HEX — заполняется последним чтением", instrumentation);
        replacementInput = field("Replacement HEX — ровно столько же байт", instrumentation);
        writeButton = button("Guarded write · сравнить → записать → проверить", instrumentation, v -> confirmWrite());
        rollbackButton = button("Rollback последней подтверждённой записи", instrumentation, v -> confirmRollback());
        instrumentationState = text("Instrumentation выключен. Никакие байты процесса не читаются и не изменяются.", 13); instrumentationState.setTextIsSelectable(true); instrumentation.addView(instrumentationState);
        updateInstrumentationControls();
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
                    clearInstrumentation("Instrumentation выключен: root не подтверждён.", true);
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
        if (lastWrite != null) {
            showError("Есть незакрытая Instrumentation-запись. Сначала выполните rollback либо явно отключите текущую session без rollback.");
            return;
        }
        selected = p; session = null; correlation = null; attachButton.setEnabled(true); correlateButton.setEnabled(false); detachButton.setEnabled(false); saveButton.setEnabled(false);
        selectedState.setText("Выбран: " + p.label()); sessionState.setText("Готово к read-only подключению."); sessionBox.removeAllViews();
        clearInstrumentation("Новый процесс выбран. Сначала подключите read-only session, затем включите Instrumentation v1.", true);
    }

    private void attach() {
        if (selected == null || rootProbe == null || !rootProbe.granted) return;
        setBusy(true, "Открываем runtime session для PID " + selected.pid + "…");
        final RootProcessEngine.ProcessInfo target = selected;
        worker.execute(() -> {
            try {
                RootProcessEngine.RuntimeSession created = RootProcessEngine.attachReadOnly(target);
                JSONObject linked = persistAndCorrelate(created);
                main.post(() -> { session = created; correlation = linked; setBusy(false, null); renderSession(); updateInstrumentationControls(); });
            } catch (Exception e) {
                main.post(() -> { setBusy(false, null); showError("Подключение не удалось: " + e.getMessage()); });
            }
        });
    }

    private void writeAtomicJson(String name,JSONObject value) throws Exception {
        java.io.File destination=app.file(name),part=app.file(name+".part");
        Files.deleteIfExists(part.toPath());
        try{Files.write(part.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        catch(Exception e){Files.deleteIfExists(part.toPath());throw e;}
    }

    private void writeRuntimeSession(JSONObject snapshot) throws Exception { writeAtomicJson("runtime-session.json",snapshot); }

    private JSONObject persistAndCorrelate(RootProcessEngine.RuntimeSession created) throws Exception {
        JSONObject snapshot = created.toJson(rootProbe);
        writeRuntimeSession(snapshot);
        java.io.File destination=app.file("runtime-correlation.json"),backendTemp=app.file("runtime-correlation.json.build");
        Files.deleteIfExists(destination.toPath());Files.deleteIfExists(app.file("runtime-correlation.json.part").toPath());Files.deleteIfExists(backendTemp.toPath());
        try {
            if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
            PyObject module = Python.getInstance().getModule("modkit.mobile.runtime_correlate");
            JSONObject linked=new JSONObject(module.callAttr("build_workspace_correlation", getFilesDir().getPath(), app.file("runtime-session.json").getPath(), backendTemp.getPath()).toString());
            Files.deleteIfExists(backendTemp.toPath());
            writeAtomicJson("runtime-correlation.json",linked);
            return linked;
        } catch (Exception e) {
            Files.deleteIfExists(backendTemp.toPath());Files.deleteIfExists(app.file("runtime-correlation.json.part").toPath());Files.deleteIfExists(destination.toPath());
            JSONObject error=new JSONObject().put("schema", "modkit-runtime-correlation-error-1.0").put("error", String.valueOf(e.getMessage())).put("correlationCount", 0).put("mappedRuntimeVaCount", 0);
            try{writeAtomicJson("runtime-correlation.json",error);}catch(Exception ignored){}
            return error;
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
            if (moduleInput != null && moduleInput.getText().toString().trim().isEmpty()) {
                RootProcessEngine.ModuleImage suggested = null;
                for (RootProcessEngine.ModuleImage module : session.moduleImages) if ("libil2cpp.so".equals(module.basename())) { suggested = module; break; }
                if (suggested == null) for (RootProcessEngine.ModuleImage module : session.moduleImages) if (module.basename().endsWith(".so")) { suggested = module; break; }
                if (suggested != null) moduleInput.setText(suggested.basename());
            }
        }
        updateInstrumentationControls();
    }

    private void detach() {
        if (lastWrite != null) {
            new AlertDialog.Builder(this).setTitle("Отключить session?")
                    .setMessage("Есть подтверждённая Instrumentation-запись, для которой ещё доступен guarded rollback. При отключении текущий in-memory receipt будет потерян. Рекомендуется сначала rollback.")
                    .setNegativeButton("Отмена", null)
                    .setPositiveButton("Отключить без rollback", (d, w) -> detachNow())
                    .show();
            return;
        }
        detachNow();
    }

    private void detachNow() {
        session = null; correlation = null; detachButton.setEnabled(false); saveButton.setEnabled(false); correlateButton.setEnabled(false); sessionBox.removeAllViews();
        sessionState.setText("Session отключена. Read-only session не изменяла процесс.");
        clearInstrumentation("Instrumentation выключен вместе с session.", true);
    }

    private void armInstrumentation() {
        if (session == null || rootProbe == null || !rootProbe.granted) { showError("Сначала подтвердите root и подключите read-only session."); return; }
        if (lastWrite != null) { showError("Сначала закройте предыдущую запись через rollback."); return; }
        final RootProcessEngine.RuntimeSession current = session;
        setInstrumentationBusy(true, "Проверяем PID/UID/start-time и фиксируем instrumentation lease…");
        worker.execute(() -> {
            try {
                RootMemoryInstrumentation.ProcessLease lease = RootMemoryInstrumentation.captureLease(current.process.pid, current.process.uid);
                appendInstrumentationAudit("LEASE_ARMED", new JSONObject().put("lease", lease.toJson()));
                main.post(() -> {
                    instrumentationLease = lease; resolvedAddress = null; lastReadBytes = null; lastWrite = null;
                    setInstrumentationBusy(false, null);
                    instrumentationState.setText("ARMED · PID " + lease.pid + " · uid " + lease.uid + " · startTicks " + lease.startTicks +
                            "\nRead ≤ " + RootMemoryInstrumentation.MAX_READ_BYTES + " B · guarded write ≤ " + RootMemoryInstrumentation.MAX_WRITE_BYTES + " B.");
                    updateInstrumentationControls();
                });
            } catch (Exception e) {
                appendInstrumentationAuditQuietly("LEASE_FAILED", errorPayload(e));
                main.post(() -> { setInstrumentationBusy(false, null); showError("Instrumentation не включён: " + e.getMessage()); });
            }
        });
    }

    private void resolveAndRead() {
        if (instrumentationLease == null) { showError("Сначала включите Instrumentation v1 для текущей session."); return; }
        final String selector = moduleInput.getText().toString().trim();
        final long rva;
        final int length;
        try { rva = parseAddress(rvaInput.getText().toString()); length = parseLength(lengthInput.getText().toString()); }
        catch (Exception e) { showError(e.getMessage()); return; }
        final RootMemoryInstrumentation.ProcessLease lease = instrumentationLease;
        setInstrumentationBusy(true, "Re-resolve module + RVA и bounded read…");
        worker.execute(() -> {
            try {
                RootModuleAddressResolver.ResolvedAddress resolved = RootModuleAddressResolver.resolve(lease, selector, rva, length, false);
                byte[] bytes = RootModuleAddressResolver.read(resolved);
                JSONObject evidence = new JSONObject().put("resolved", resolved.toJson()).put("bytesHex", bytesToHex(bytes)).put("length", bytes.length);
                appendInstrumentationAudit("READ_VERIFIED", evidence);
                main.post(() -> {
                    resolvedAddress = resolved; lastReadBytes = bytes.clone();
                    expectedInput.setText(bytesToHex(bytes)); replacementInput.setText("");
                    setInstrumentationBusy(false, null);
                    instrumentationState.setText("READ VERIFIED\nModule: " + resolved.modulePath +
                            "\nLoad bias: " + hex(resolved.loadBias) + " · RVA: " + hex(resolved.rva) + " · VA: " + hex(resolved.address) +
                            " · perms: " + resolved.perms + "\nBytes[" + bytes.length + "]: " + bytesToHex(bytes));
                    updateInstrumentationControls();
                });
            } catch (Exception e) {
                appendInstrumentationAuditQuietly("READ_FAILED", errorPayload(e));
                main.post(() -> { resolvedAddress = null; lastReadBytes = null; setInstrumentationBusy(false, null); showError("Instrumentation read не выполнен: " + e.getMessage()); });
            }
        });
    }

    private void confirmWrite() {
        if (instrumentationLease == null || resolvedAddress == null || lastReadBytes == null) { showError("Сначала выполните Resolve RVA + чтение."); return; }
        if (lastWrite != null) { showError("Есть незакрытая запись. Сначала rollback последней записи."); return; }
        final byte[] expected, replacement;
        try { expected = parseHexBytes(expectedInput.getText().toString()); replacement = parseHexBytes(replacementInput.getText().toString()); }
        catch (Exception e) { showError(e.getMessage()); return; }
        if (expected.length != resolvedAddress.length || replacement.length != resolvedAddress.length) {
            showError("Expected и replacement должны содержать ровно " + resolvedAddress.length + " байт."); return;
        }
        if (replacement.length > RootMemoryInstrumentation.MAX_WRITE_BYTES) {
            showError("Guarded write ограничен " + RootMemoryInstrumentation.MAX_WRITE_BYTES + " байтами."); return;
        }
        if (!Arrays.equals(expected, lastReadBytes)) {
            showError("Expected original отличается от последнего подтверждённого чтения. Выполните чтение заново."); return;
        }
        final RootModuleAddressResolver.ResolvedAddress target = resolvedAddress;
        String message = "Процесс: PID " + target.lease.pid + " · uid " + target.lease.uid +
                "\nМодуль: " + target.modulePath + "\nRVA: " + hex(target.rva) + " · VA: " + hex(target.address) +
                "\nExpected: " + bytesToHex(expected) + "\nReplacement: " + bytesToHex(replacement) +
                "\n\nПеред записью target будет re-resolve, expected байты сравнятся ещё раз, а результат будет перечитан и проверен.";
        new AlertDialog.Builder(this).setTitle("Подтвердить guarded write")
                .setMessage(message).setNegativeButton("Отмена", null)
                .setPositiveButton("Записать и проверить", (d, w) -> performWrite(target, expected, replacement)).show();
    }

    private void performWrite(RootModuleAddressResolver.ResolvedAddress target, byte[] expected, byte[] replacement) {
        setInstrumentationBusy(true, "Compare-before-write → write → readback verify…");
        worker.execute(() -> {
            try {
                RootMemoryInstrumentation.WriteReceipt receipt = RootModuleAddressResolver.guardedWrite(target, expected, replacement);
                appendInstrumentationAudit("WRITE_VERIFIED", new JSONObject().put("receipt", receipt.toJson()));
                main.post(() -> {
                    lastWrite = receipt; lastReadBytes = receipt.replacement.clone(); expectedInput.setText(bytesToHex(receipt.replacement)); replacementInput.setText("");
                    setInstrumentationBusy(false, null);
                    instrumentationState.setText("WRITE VERIFIED · rollback доступен\nVA: " + hex(receipt.address) + " · " + receipt.replacement.length + " B\n" +
                            bytesToHex(receipt.original) + " → " + bytesToHex(receipt.replacement));
                    updateInstrumentationControls();
                });
            } catch (Exception e) {
                appendInstrumentationAuditQuietly("WRITE_FAILED", errorPayload(e));
                main.post(() -> { setInstrumentationBusy(false, null); showError("Guarded write отклонён/не выполнен: " + e.getMessage()); });
            }
        });
    }

    private void confirmRollback() {
        if (lastWrite == null) { showError("Нет подтверждённой записи для rollback."); return; }
        final RootMemoryInstrumentation.WriteReceipt receipt = lastWrite;
        new AlertDialog.Builder(this).setTitle("Rollback последней записи")
                .setMessage("Rollback выполнится только если текущие байты всё ещё точно равны записанным ModKit.\nVA: " + hex(receipt.address) +
                        "\nCurrent expected: " + bytesToHex(receipt.replacement) + "\nRestore: " + bytesToHex(receipt.original))
                .setNegativeButton("Отмена", null).setPositiveButton("Rollback + verify", (d, w) -> performRollback(receipt)).show();
    }

    private void performRollback(RootMemoryInstrumentation.WriteReceipt receipt) {
        setInstrumentationBusy(true, "Проверяем lease/current bytes → rollback → readback verify…");
        worker.execute(() -> {
            try {
                RootMemoryInstrumentation.rollback(receipt);
                appendInstrumentationAudit("ROLLBACK_VERIFIED", new JSONObject().put("receipt", receipt.toJson()));
                main.post(() -> {
                    lastWrite = null; lastReadBytes = receipt.original.clone(); expectedInput.setText(bytesToHex(receipt.original)); replacementInput.setText("");
                    setInstrumentationBusy(false, null);
                    instrumentationState.setText("ROLLBACK VERIFIED\nVA: " + hex(receipt.address) + " восстановлен: " + bytesToHex(receipt.original));
                    updateInstrumentationControls();
                });
            } catch (Exception e) {
                appendInstrumentationAuditQuietly("ROLLBACK_FAILED", errorPayload(e));
                main.post(() -> { setInstrumentationBusy(false, null); showError("Rollback заблокирован/не выполнен: " + e.getMessage()); });
            }
        });
    }

    private void appendInstrumentationAudit(String type, JSONObject payload) throws Exception {
        java.io.File file = app.file("instrumentation-audit.json");
        JSONObject journal;
        try { journal = file.isFile() ? new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8)) : new JSONObject(); }
        catch (Exception ignored) { journal = new JSONObject(); }
        journal.put("schema", "modkit-instrumentation-audit-1.0");
        JSONArray old = journal.optJSONArray("events"), events = new JSONArray();
        if (old != null) {
            int start = Math.max(0, old.length() - (MAX_INSTRUMENTATION_AUDIT_EVENTS - 1));
            for (int i = start; i < old.length(); i++) events.put(old.get(i));
        }
        JSONObject event = new JSONObject().put("type", type).put("atMs", System.currentTimeMillis()).put("payload", payload == null ? new JSONObject() : payload);
        if (instrumentationLease != null) event.put("lease", instrumentationLease.toJson());
        events.put(event); journal.put("events", events).put("eventCount", events.length()).put("updatedAtMs", System.currentTimeMillis());
        writeAtomicJson("instrumentation-audit.json", journal);
    }

    private void appendInstrumentationAuditQuietly(String type, JSONObject payload) {
        try { appendInstrumentationAudit(type, payload); } catch (Exception ignored) {}
    }

    private JSONObject errorPayload(Exception e) {
        try { return new JSONObject().put("errorClass", e == null ? "unknown" : e.getClass().getName()).put("error", e == null ? "unknown" : String.valueOf(e.getMessage())); }
        catch (Exception ignored) { return new JSONObject(); }
    }

    private long parseAddress(String raw) throws Exception {
        String value = raw == null ? "" : raw.trim().replace("_", "");
        if (value.isEmpty()) throw new Exception("Укажите RVA.");
        try {
            long parsed = value.startsWith("0x") || value.startsWith("0X") ? Long.parseUnsignedLong(value.substring(2), 16) : Long.parseUnsignedLong(value, 10);
            if (parsed < 0) throw new NumberFormatException("too large");
            return parsed;
        } catch (NumberFormatException e) { throw new Exception("Некорректный RVA: используйте 0xHEX или десятичное значение."); }
    }

    private int parseLength(String raw) throws Exception {
        try {
            int value = Integer.parseInt(raw == null ? "" : raw.trim());
            if (value <= 0 || value > RootMemoryInstrumentation.MAX_READ_BYTES) throw new NumberFormatException("range");
            return value;
        } catch (NumberFormatException e) { throw new Exception("Длина чтения должна быть 1…" + RootMemoryInstrumentation.MAX_READ_BYTES + " байт."); }
    }

    private byte[] parseHexBytes(String raw) throws Exception {
        String value = raw == null ? "" : raw.replace("0x", "").replace("0X", "").replaceAll("[\\s:_-]+", "");
        if (value.isEmpty() || (value.length() & 1) != 0) throw new Exception("HEX должен содержать непустое чётное число hex-символов.");
        if (!value.matches("[0-9a-fA-F]+")) throw new Exception("HEX содержит недопустимые символы.");
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte)Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return out.toString();
    }

    private String hex(long value) { return String.format(Locale.ROOT, "0x%x", value); }

    private void clearInstrumentation(String message, boolean clearInputs) {
        instrumentationLease = null; resolvedAddress = null; lastReadBytes = null; lastWrite = null;
        if (clearInputs && moduleInput != null) { moduleInput.setText(""); rvaInput.setText(""); expectedInput.setText(""); replacementInput.setText(""); }
        if (instrumentationState != null && message != null) instrumentationState.setText(message);
        updateInstrumentationControls();
    }

    private void updateInstrumentationControls() {
        if (armInstrumentationButton == null) return;
        boolean idle = !baseBusy && !instrumentationBusy;
        armInstrumentationButton.setEnabled(idle && session != null && rootProbe != null && rootProbe.granted && lastWrite == null);
        resolveReadButton.setEnabled(idle && instrumentationLease != null);
        writeButton.setEnabled(idle && instrumentationLease != null && resolvedAddress != null && lastReadBytes != null && lastReadBytes.length <= RootMemoryInstrumentation.MAX_WRITE_BYTES && lastWrite == null);
        rollbackButton.setEnabled(idle && lastWrite != null);
    }

    private void setInstrumentationBusy(boolean busy, String message) {
        instrumentationBusy = busy;
        if (instrumentationProgress != null) instrumentationProgress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (message != null && instrumentationState != null) instrumentationState.setText(message);
        updateInstrumentationControls();
    }

    private void saveSession() {
        if (session == null) return;
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json")
                .addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE, "modkit-runtime-session-" + session.process.pid + ".json"), SAVE_SESSION);
    }

    private void deleteCreatedDocument(Uri uri){if(uri==null)return;try{android.provider.DocumentsContract.deleteDocument(getContentResolver(),uri);}catch(Exception ignored){}}
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != SAVE_SESSION || resultCode != RESULT_OK || data == null || data.getData() == null || session == null) return;
        Uri uri = data.getData();
        try (OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
            if (out == null) throw new java.io.IOException("output stream unavailable");
            out.write(session.toJson(rootProbe).toString(2).getBytes(StandardCharsets.UTF_8)); out.flush();
            sessionState.append("\nSnapshot сохранён. Внутренние runtime-session.json и runtime-correlation.json уже доступны Evidence Bundle.");
        } catch (Exception e) { deleteCreatedDocument(uri); showError("Не удалось сохранить snapshot: " + e.getMessage()); }
    }

    private void setBusy(boolean busy, String message) {
        baseBusy = busy;
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (message != null) sessionState.setText(message);
        refreshButton.setEnabled(!busy && rootProbe != null && rootProbe.granted);
        attachButton.setEnabled(!busy && selected != null);
        correlateButton.setEnabled(!busy && session != null);
        detachButton.setEnabled(!busy && session != null);
        saveButton.setEnabled(!busy && session != null);
        updateInstrumentationControls();
    }

    private void showError(String message) {
        new AlertDialog.Builder(this).setTitle("Process Lab").setMessage(message).setPositiveButton("OK", null).show();
    }

    @Override protected void onDestroy() {
        worker.shutdownNow(); super.onDestroy();
    }
}
