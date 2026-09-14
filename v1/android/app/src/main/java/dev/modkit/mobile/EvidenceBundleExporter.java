package dev.modkit.mobile;

import android.content.Context;
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

    static JSONObject export(Context context, Uri output) throws Exception {
        App app = (App)context.getApplicationContext();
        List<File> candidates = collect(app.getFilesDir());
        JSONArray entries = new JSONArray();
        long[] total = {0L};
        try (OutputStream raw = context.getContentResolver().openOutputStream(output, "wt")) {
            if (raw == null) throw new java.io.IOException("Не удалось открыть Evidence Bundle для записи");
            try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(raw, BUFFER))) {
                for (File file : candidates) {
                    if (!file.isFile() || file.length() <= 0 || file.length() > MAX_SINGLE_FILE) continue;
                    if (total[0] + file.length() > MAX_TEXT_TOTAL) break;
                    String relative = app.getFilesDir().toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/');
                    if (!isEvidenceFile(relative)) continue;
                    String hash = sha256(file);
                    ZipEntry ze = new ZipEntry("evidence/" + relative); ze.setTime(0L); zip.putNextEntry(ze);
                    try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER)) {
                        byte[] buf = new byte[BUFFER]; int n;
                        while ((n = in.read(buf)) != -1) zip.write(buf, 0, n);
                    }
                    zip.closeEntry(); total[0] += file.length();
                    entries.put(new JSONObject().put("path", relative).put("size", file.length()).put("sha256", hash));
                }

                String engineCatalog = engineCatalog(context);
                writeText(zip, "toolchain/engine-catalog.json", engineCatalog);
                JSONObject manifest = new JSONObject()
                        .put("schema", "modkit-evidence-bundle-1.0")
                        .put("createdAtMs", System.currentTimeMillis())
                        .put("modkitVersion", BuildConfig.VERSION_NAME)
                        .put("evidenceFiles", entries)
                        .put("evidenceFileCount", entries.length())
                        .put("evidenceBytes", total[0])
                        .put("rawTargetBinariesIncluded", false)
                        .put("note", "Target APK/SO/metadata are intentionally not duplicated; hashes/locators remain in analysis evidence.");
                writeText(zip, "bundle-manifest.json", manifest.toString(2));

                StringBuilder hashes = new StringBuilder();
                for (int i = 0; i < entries.length(); i++) {
                    JSONObject row = entries.getJSONObject(i);
                    hashes.append(row.getString("sha256")).append("  evidence/").append(row.getString("path")).append('\n');
                }
                writeText(zip, "hashes.sha256", hashes.toString());
                return manifest;
            }
        }
    }

    private static List<File> collect(File root) {
        ArrayList<File> out = new ArrayList<>();
        collectInto(root, root, out, 0);
        out.sort(Comparator.comparing(File::getAbsolutePath));
        return out;
    }

    private static void collectInto(File root, File node, List<File> out, int depth) {
        if (depth > 8 || node == null || !node.exists()) return;
        if (node.isFile()) { out.add(node); return; }
        String rel = root.toPath().relativize(node.toPath()).toString().replace(File.separatorChar, '/');
        if (rel.startsWith("installed-apks") || rel.startsWith("target-signed-set") || rel.startsWith("decompiler/cache") || rel.startsWith("decompiler/tmp")) return;
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

    private static String engineCatalog(Context context) {
        try {
            if (!Python.isStarted()) Python.start(new AndroidPlatform(context));
            PyObject module = Python.getInstance().getModule("modkit.engines");
            return module.callAttr("catalog_json").toString();
        } catch (Exception e) {
            return new JSONObject().put("schema", "modkit-engine-catalog-error-1.0").put("error", String.valueOf(e.getMessage())).toString(2);
        }
    }

    private static void writeText(ZipOutputStream zip, String name, String text) throws Exception {
        ZipEntry entry = new ZipEntry(name); entry.setTime(0L); zip.putNextEntry(entry);
        zip.write(text.getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER)) {
            byte[] buf = new byte[BUFFER]; int n; while ((n = in.read(buf)) != -1) digest.update(buf, 0, n);
        }
        StringBuilder out = new StringBuilder(); for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b));
        return out.toString();
    }
}
