package dev.modkit.mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Explicit, capability-based root access. No root prompt is issued until the user requests it. */
final class RootAccess {
    private RootAccess() {}

    static final class ExecResult {
        final int exitCode;
        final String output;
        final boolean timedOut;
        final boolean truncated;

        ExecResult(int exitCode, String output, boolean timedOut, boolean truncated) {
            this.exitCode = exitCode;
            this.output = output;
            this.timedOut = timedOut;
            this.truncated = truncated;
        }
    }

    static final class ProbeResult {
        final boolean granted;
        final int uid;
        final String identity;
        final List<String> capabilities;
        final List<String> hints;
        final String detail;

        ProbeResult(boolean granted, int uid, String identity, List<String> capabilities, List<String> hints, String detail) {
            this.granted = granted;
            this.uid = uid;
            this.identity = identity;
            this.capabilities = capabilities;
            this.hints = hints;
            this.detail = detail;
        }

        JSONObject toJson() {
            return new JSONObject()
                    .put("schema", "modkit-root-capability-1.0")
                    .put("granted", granted)
                    .put("uid", uid)
                    .put("identity", identity)
                    .put("capabilities", new JSONArray(capabilities))
                    .put("hints", new JSONArray(hints))
                    .put("detail", detail);
        }
    }

    static ProbeResult probe() {
        ArrayList<String> hints = new ArrayList<>();
        for (String path : new String[]{"/system/bin/su", "/system/xbin/su", "/sbin/su", "/debug_ramdisk/su", "/data/adb/ksu/bin/su"}) {
            if (new java.io.File(path).exists()) hints.add("su-path:" + path);
        }

        ExecResult id = runSu("id", 12_000, 64 * 1024);
        int uid = parseUid(id.output);
        boolean granted = !id.timedOut && id.exitCode == 0 && uid == 0;
        if (!granted) {
            String detail = id.timedOut ? "Root-запрос не завершился вовремя." :
                    "Root не подтверждён. Наличие менеджера/root-файлов само по себе не считается доступом.";
            return new ProbeResult(false, uid, sanitizeLine(id.output), new ArrayList<>(), hints, detail);
        }

        ArrayList<String> caps = new ArrayList<>();
        caps.add("root-shell");
        if (rootTest("test -r /proc/1/status")) caps.add("procfs-processes");
        if (rootTest("test -r /proc/1/maps")) caps.add("procfs-maps");
        if (rootTest("command -v debuggerd >/dev/null 2>&1 || command -v debuggerd64 >/dev/null 2>&1")) caps.add("debuggerd");
        if (rootTest("pidof frida-server >/dev/null 2>&1 || command -v frida-server >/dev/null 2>&1")) caps.add("frida-server-detected");
        if (rootTest("test -r /sys/fs/selinux/enforce")) caps.add("selinux-state-readable");
        return new ProbeResult(true, uid, sanitizeLine(id.output), caps, hints,
                "Root подтверждён фактическим uid=0. Доступные возможности определены отдельными проверками.");
    }

    private static boolean rootTest(String command) {
        ExecResult result = runSu(command, 5_000, 16 * 1024);
        return !result.timedOut && result.exitCode == 0;
    }

    static ExecResult runSu(String fixedCommand, long timeoutMs, int maxCaptureBytes) {
        if (fixedCommand == null || fixedCommand.trim().isEmpty()) return new ExecResult(-1, "empty command", false, false);
        Process process = null;
        ExecutorService io = Executors.newSingleThreadExecutor();
        try {
            process = new ProcessBuilder(Arrays.asList("su", "-c", fixedCommand)).redirectErrorStream(true).start();
            final Process readerProcess = process;
            Future<Captured> outputFuture = io.submit(new Callable<Captured>() {
                @Override public Captured call() throws Exception {
                    StringBuilder out = new StringBuilder();
                    boolean truncated = false;
                    int bytes = 0;
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(readerProcess.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            int add = line.getBytes(StandardCharsets.UTF_8).length + 1;
                            if (bytes + add <= maxCaptureBytes) {
                                out.append(line).append('\n');
                                bytes += add;
                            } else {
                                truncated = true;
                            }
                        }
                    }
                    return new Captured(out.toString(), truncated);
                }
            });
            boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroy();
                if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly();
                Captured captured = getCaptured(outputFuture, 800);
                return new ExecResult(-1, captured.text, true, captured.truncated);
            }
            Captured captured = getCaptured(outputFuture, 1_500);
            return new ExecResult(process.exitValue(), captured.text, false, captured.truncated);
        } catch (Exception e) {
            return new ExecResult(-1, e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()), false, false);
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            io.shutdownNow();
        }
    }

    private static final class Captured {
        final String text;
        final boolean truncated;
        Captured(String text, boolean truncated) { this.text = text; this.truncated = truncated; }
    }

    private static Captured getCaptured(Future<Captured> future, long timeoutMs) {
        try { return future.get(timeoutMs, TimeUnit.MILLISECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); return new Captured("", false); }
        catch (ExecutionException | TimeoutException e) { return new Captured("", false); }
    }

    private static int parseUid(String output) {
        if (output == null) return -1;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(?:^|\\s)uid=(\\d+)").matcher(output);
        if (!matcher.find()) return -1;
        try { return Integer.parseInt(matcher.group(1)); } catch (NumberFormatException ignored) { return -1; }
    }

    static String sanitizeLine(String raw) {
        if (raw == null) return "";
        String normalized = raw.replace('\u0000', ' ').replace('\r', ' ').replace('\n', ' ').trim();
        if (normalized.length() > 400) normalized = normalized.substring(0, 400) + "…";
        return normalized;
    }
}
