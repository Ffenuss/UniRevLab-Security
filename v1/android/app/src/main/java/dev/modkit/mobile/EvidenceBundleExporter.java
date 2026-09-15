package dev.modkit.mobile;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.net.Uri;

import com.chaquo.python.Python;
import com.chaquo.python.PyObject;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Streaming technical evidence package. Raw APK/.so/metadata are fingerprinted by existing reports, not duplicated. */
final class EvidenceBundleExporter {
    private static final long MAX_SINGLE_FILE = 96L * 1024L * 1024L;
    private static final long MAX_TEXT_TOTAL = 768L * 1024L * 1024L;
    private static final int BUFFER = 256 * 1024;

    private EvidenceBundleExporter() {}

    private static void checkInterrupted() throws java.io.InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException("Evidence Bundle export cancelled");
    }

    private static JSONObject terminalPipeline(Context context) throws Exception {
        checkInterrupted();
        App app = (App)context.getApplicationContext();
        JSONObject pipeline = readJson(new File(app.getFilesDir(), "automatic-evidence.json"));
        if (app.busy.get() || (pipeline != null && "RUNNING".equals(pipeline.optString("status")))) {
            throw new java.io.IOException("Анализ ещё выполняется. Экспорт доступен после завершения или отмены текущего прогона.");
        }
        if (pipeline == null) throw new java.io.IOException("Нет завершённого pipeline manifest. Сначала запустите полный анализ.");
        String status = pipeline.optString("status", "");
        if (!("SUCCESS".equals(status) || "PARTIAL".equals(status) || "FAILED".equals(status) || "CANCELLED".equals(status))) {
            throw new java.io.IOException("Pipeline state не является terminal: " + (status.isEmpty() ? "UNKNOWN" : status));
        }
        return pipeline;
    }

    private static String pipelineEpoch(JSONObject pipeline) {
        return pipeline.optString("schema", "") + "|" + pipeline.optString("status", "") + "|" +
                pipeline.optLong("startedAtMs", -1L) + "|" + pipeline.optLong("finishedAtMs", -1L) + "|" +
                pipeline.optLong("updatedAtMs", -1L);
    }

    private static boolean diagnosticFreshOnly(JSONObject pipeline) {
        String status = pipeline.optString("status", "");
        return "FAILED".equals(status) || "CANCELLED".equals(status);
    }

    private static boolean belongsToFailureEpoch(File file, JSONObject pipeline) {
        long startedAt = pipeline.optLong("startedAtMs", -1L);
        return startedAt > 0L && file.lastModified() >= startedAt;
    }

    static void ensureExportable(Context context) throws Exception { terminalPipeline(context); }
    static String exportEpoch(Context context) throws Exception { return pipelineEpoch(terminalPipeline(context)); }
    static boolean shouldBuildConnectedReport(Context context) throws Exception {
        String status = terminalPipeline(context).optString("status", "");
        return "SUCCESS".equals(status) || "PARTIAL".equals(status);
    }

    static JSONObject export(Context context, Uri output) throws Exception {
        JSONObject initialPipeline = terminalPipeline(context);
        String initialEpoch = pipelineEpoch(initialPipeline);
        boolean freshOnly = diagnosticFreshOnly(initialPipeline);
        App app = (App)context.getApplicationContext();
        List<File> candidates = collect(app.getFilesDir());
        JSONArray entries = new JSONArray();
        long[] total = {0L};
        int[] staleExcluded = {0};
        int[] budgetExcluded = {0};
        try {
            try (OutputStream raw = context.getContentResolver().openOutputStream(output, "wt")) {
                if (raw == null) throw new java.io.IOException("Не удалось открыть Evidence Bundle для записи");
                try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(raw, BUFFER))) {
                    for (File file : candidates) {
                        checkInterrupted();
                        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_SINGLE_FILE) continue;
                        String relative = app.getFilesDir().toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/');
                        if (!isEvidenceFile(relative)) continue;
                        if (freshOnly && !belongsToFailureEpoch(file, initialPipeline)) { staleExcluded[0]++; continue; }
                        if (total[0] + file.length() > MAX_TEXT_TOTAL) { budgetExcluded[0]++; continue; }
                        String hash = sha256(file);
                        ZipEntry ze = new ZipEntry("evidence/" + relative); ze.setTime(0L); zip.putNextEntry(ze);
                        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER)) {
                            byte[] buf = new byte[BUFFER]; int n;
                            while ((n = in.read(buf)) != -1) { checkInterrupted(); zip.write(buf, 0, n); }
                        }
                        zip.closeEntry(); total[0] += file.length();
                        entries.put(new JSONObject().put("path", relative).put("size", file.length()).put("sha256", hash));
                    }

                    checkInterrupted();
                    String finalEpoch = exportEpoch(context);
                    if (!initialEpoch.equals(finalEpoch)) throw new java.io.IOException("Pipeline изменился во время экспорта; Evidence Bundle отменён для защиты epoch consistency.");
                    String engineCatalog = engineCatalog(context);
                    writeText(zip, "toolchain/engine-catalog.json", engineCatalog);
                    JSONObject pipeline = terminalPipeline(context);
                    if (!initialEpoch.equals(pipelineEpoch(pipeline))) throw new java.io.IOException("Pipeline изменился во время экспорта; Evidence Bundle отменён для защиты epoch consistency.");
                    JSONArray degradedReasons = pipeline.optJSONArray("degradedReasons");
                    if (degradedReasons == null) degradedReasons = new JSONArray();
                    JSONObject manifest = new JSONObject()
                            .put("schema", "modkit-evidence-bundle-1.0")
                            .put("createdAtMs", System.currentTimeMillis())
                            .put("modkitVersion", appVersion(context))
                            .put("evidenceFiles", entries)
                            .put("evidenceFileCount", entries.length())
                            .put("evidenceBytes", total[0])
                            .put("pipelineStatus", pipeline.optString("status", "UNKNOWN"))
                            .put("pipelineComplete", pipeline.optBoolean("complete", false))
                            .put("pipelineDegraded", pipeline.optBoolean("degraded", false))
                            .put("pipelineDegradedReasons", degradedReasons)
                            .put("diagnosticFreshOnly", freshOnly)
                            .put("staleEvidenceFilesExcluded", staleExcluded[0])
                            .put("budgetEvidenceFilesExcluded", budgetExcluded[0])
                            .put("rawTargetBinariesIncluded", false)
                            .put("historicalProjectTreesIncluded", false)
                            .put("note", freshOnly
                                    ? "FAILED/CANCELLED diagnostic bundle contains only evidence modified in the current pipeline epoch; older cache evidence is excluded. Historical projects and generated Menu Builder source trees are never traversed."
                                    : "Target APK/SO/metadata are intentionally not duplicated; hashes/locators remain in analysis evidence. Historical projects and generated Menu Builder source trees are never traversed.");
                    if (!pipeline.optString("error", "").isEmpty()) manifest.put("pipelineError", pipeline.optString("error"));
                    writeText(zip, "bundle-manifest.json", manifest.toString(2));

                    StringBuilder hashes = new StringBuilder();
                    for (int i = 0; i < entries.length(); i++) {
                        checkInterrupted();
                        JSONObject row = entries.getJSONObject(i);
                        hashes.append(row.getString("sha256")).append("  evidence/").append(row.getString("path")).append('\n');
                    }
                    writeText(zip, "hashes.sha256", hashes.toString());
                    checkInterrupted();
                    if (!initialEpoch.equals(exportEpoch(context))) throw new java.io.IOException("Pipeline изменился до завершения экспорта; Evidence Bundle отменён для защиты epoch consistency.");
                    return manifest;
                }
            }
        } catch (Exception error) {
            clearFailedOutput(context, output);
            throw error;
        }
    }

    private static void clearFailedOutput(Context context, Uri output) {
        try (OutputStream wipe = context.getContentResolver().openOutputStream(output, "wt")) {
            if (wipe != null) wipe.flush();
        } catch (Exception ignored) { }
    }

    private static JSONObject readJson(File file) {
        try {
            if (!file.isFile()) return null;
            return new JSONObject(new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String appVersion(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return info.versionName == null || info.versionName.trim().isEmpty() ? "unknown" : info.versionName;
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private static List<File> collect(File root) throws java.io.InterruptedIOException {
        checkInterrupted();
        ArrayList<File> out = new ArrayList<>();
        collectInto(root, root, out, 0);
        checkInterrupted();
        out.sort(Comparator.comparing(File::getAbsolutePath));
        return out;
    }

    private static void collectInto(File root, File node, List<File> out, int depth) throws java.io.InterruptedIOException {
        checkInterrupted();
        if (depth > 8 || node == null || !node.exists()) return;
        if (node.isFile()) { out.add(node); return; }
        String rel = root.toPath().relativize(node.toPath()).toString().replace(File.separatorChar, '/');
        if (rel.equals("projects") || rel.startsWith("projects/") ||
                rel.equals("menu-project") || rel.startsWith("menu-project/") ||
                rel.startsWith("installed-apks") || rel.startsWith("target-signed-set") ||
                rel.startsWith("decompiler/cache") || rel.startsWith("decompiler/tmp")) return;
        File[] children = node.listFiles(); if (children == null) return;
        Arrays.sort(children, Comparator.comparing(File::getName));
        for (File child : children) collectInto(root, child, out, depth + 1);
    }

    private static boolean isEvidenceFile(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        for (String suffix : new String[]{".json", ".jsonl", ".idx", ".txt", ".md", ".csv", ".tsv", ".log", ".map", ".cs", ".xml", ".html", ".sarif"}) {
            if (lower.endsWith(suffix)) return true;
        }
        return lower.endsWith("session") || lower.endsWith("manifest");
    }

    private static String engineCatalog(Context context) throws java.io.InterruptedIOException {
        checkInterrupted();
        try {
            if (!Python.isStarted()) Python.start(new AndroidPlatform(context));
            PyObject module = Python.getInstance().getModule("modkit.engines");
            String value = module.callAttr("catalog_json").toString();
            checkInterrupted();
            return value;
        } catch (java.io.InterruptedIOException cancelled) {
            throw cancelled;
        } catch (Exception e) {
            String message = String.valueOf(e.getMessage()).replace("\\", "\\\\").replace("\"", "\\\"");
            return "{\"schema\":\"modkit-engine-catalog-error-1.0\",\"error\":\"" + message + "\"}";
        }
    }

    private static void writeText(ZipOutputStream zip, String name, String text) throws Exception {
        checkInterrupted();
        ZipEntry entry = new ZipEntry(name); entry.setTime(0L); zip.putNextEntry(entry);
        zip.write(text.getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
        checkInterrupted();
    }

    private static String sha256(File file) throws Exception {
        checkInterrupted();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER)) {
            byte[] buf = new byte[BUFFER]; int n; while ((n = in.read(buf)) != -1) { checkInterrupted(); digest.update(buf, 0, n); }
        }
        checkInterrupted();
        StringBuilder out = new StringBuilder(); for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b));
        return out.toString();
    }
}