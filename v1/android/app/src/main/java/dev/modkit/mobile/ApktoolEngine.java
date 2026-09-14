package dev.modkit.mobile;

import android.content.Context;

import brut.androlib.ApkDecoder;
import brut.androlib.Config;
import brut.directory.ExtFile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Embedded Apktool decoder used by Full Analysis.
 *
 * Apktool is linked into the APK as a Java library. No desktop process, Termux,
 * network download or manual evidence import is required. Decode runs against
 * the selected base/split APK set and writes a private workspace under files/.
 */
public final class ApktoolEngine {
    public static final String ENGINE_ID = "apktool.android";
    public static final String APKTOOL_VERSION = "2.12.1";
    private ApktoolEngine() {}

    public static JSONObject analyze(Context context, List<File> inputs, AtomicBoolean cancelled) throws Exception {
        File root = new File(context.getFilesDir(), "apktool-workspace");
        if (!root.isDirectory() && !root.mkdirs()) throw new java.io.IOException("Cannot create Apktool workspace");
        File framework = new File(context.getFilesDir(), "apktool-framework");
        if (!framework.isDirectory() && !framework.mkdirs()) throw new java.io.IOException("Cannot create Apktool framework directory");
        // Apktool's desktop default derives a framework path from user.home. Android
        // doesn't guarantee that property, so pin all state to this app's private storage.
        String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.trim().isEmpty()) System.setProperty("user.home", context.getFilesDir().getAbsolutePath());

        JSONArray rows = new JSONArray();
        int decoded = 0;
        int cached = 0;
        int failed = 0;

        for (File input : inputs) {
            if (cancelled != null && cancelled.get()) break;
            JSONObject row = new JSONObject();
            row.put("apk", input.getName());
            try {
                String sha = sha256(input);
                String id = safe(input.getName()) + "-" + sha.substring(0, 12);
                File out = new File(root, id);
                File marker = new File(out, ".modkit-apktool.json");
                row.put("sha256", sha).put("workspace", "apktool-workspace/" + id);

                if (isCacheHit(marker, sha)) {
                    row.put("status", "CACHE_HIT").put("fileCount", countFiles(out, 250000));
                    cached++;
                    rows.put(row);
                    continue;
                }

                Config config = new Config();
                config.setFrameworkDirectory(framework.getAbsolutePath());
                config.setForced(true);
                config.setJobs(Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), 4)));
                config.setDecodeSources(Config.DecodeSources.FULL);
                config.setDecodeResources(Config.DecodeResources.FULL);
                config.setDecodeAssets(Config.DecodeAssets.FULL);
                config.setDecodeResolve(Config.DecodeResolve.KEEP);
                config.setBaksmaliDebugMode(true);
                config.setKeepBrokenResources(true);
                config.setAnalysisMode(true);

                new ApkDecoder(new ExtFile(input), config).decode(out);
                if (cancelled != null && cancelled.get()) {
                    row.put("status", "CANCELLED_AFTER_DECODE");
                    rows.put(row);
                    break;
                }

                JSONObject cache = new JSONObject()
                        .put("schema", "modkit-apktool-workspace-1.0")
                        .put("engineId", ENGINE_ID)
                        .put("apktoolVersion", APKTOOL_VERSION)
                        .put("apk", input.getName())
                        .put("sha256", sha)
                        .put("complete", true)
                        .put("finishedAtMs", System.currentTimeMillis());
                Files.write(marker.toPath(), cache.toString(2).getBytes(StandardCharsets.UTF_8));
                row.put("status", "DECODED")
                        .put("fileCount", countFiles(out, 250000))
                        .put("manifest", new File(out, "AndroidManifest.xml").isFile())
                        .put("resources", new File(out, "res").isDirectory())
                        .put("smali", hasSmali(out));
                decoded++;
            } catch (Throwable error) {
                row.put("status", "FAILED").put("error", String.valueOf(error.getMessage()));
                failed++;
            }
            rows.put(row);
        }

        return new JSONObject()
                .put("schema", "modkit-apktool-analysis-1.0")
                .put("engineId", ENGINE_ID)
                .put("apktoolVersion", APKTOOL_VERSION)
                .put("bundled", true)
                .put("manualImportRequired", false)
                .put("executesTargetCode", false)
                .put("decoded", decoded)
                .put("cached", cached)
                .put("failed", failed)
                .put("cancelled", cancelled != null && cancelled.get())
                .put("inputs", rows);
    }

    private static boolean isCacheHit(File marker, String sha) {
        if (!marker.isFile()) return false;
        try {
            JSONObject old = new JSONObject(Io.readUtf8(marker));
            return old.optBoolean("complete") && sha.equals(old.optString("sha256"))
                    && ENGINE_ID.equals(old.optString("engineId"))
                    && APKTOOL_VERSION.equals(old.optString("apktoolVersion"));
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean hasSmali(File out) {
        File[] children = out.listFiles();
        if (children == null) return false;
        for (File child : children) if (child.isDirectory() && child.getName().startsWith("smali")) return true;
        return false;
    }

    private static int countFiles(File root, int limit) {
        if (root == null || !root.exists() || limit <= 0) return 0;
        if (root.isFile()) return 1;
        File[] children = root.listFiles();
        if (children == null) return 0;
        int count = 0;
        for (File child : children) {
            if (count >= limit) break;
            count += countFiles(child, limit - count);
        }
        return count;
    }

    private static String safe(String name) {
        String value = name.replaceAll("[^A-Za-z0-9._-]+", "_");
        if (value.length() > 72) value = value.substring(0, 72);
        return value.isEmpty() ? "apk" : value;
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (FileInputStream in = new FileInputStream(file)) {
            int n;
            while ((n = in.read(buffer)) != -1) digest.update(buffer, 0, n);
        }
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b));
        return out.toString();
    }
}
