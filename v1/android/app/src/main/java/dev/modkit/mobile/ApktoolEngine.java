package dev.modkit.mobile;

import android.content.Context;

import brut.androlib.ApkDecoder;
import brut.androlib.Config;
import brut.directory.ExtFile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
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
    private static final String CACHE_MARKER = ".modkit-apktool.json";
    private ApktoolEngine() {}

    public static JSONObject analyze(Context context, List<File> inputs, AtomicBoolean cancelled) throws Exception {
        File root = new File(context.getFilesDir(), "apktool-workspace");
        if (!root.isDirectory() && !root.mkdirs()) throw new IOException("Cannot create Apktool workspace");
        File framework = new File(context.getFilesDir(), "apktool-framework");
        if (!framework.isDirectory() && !framework.mkdirs()) throw new IOException("Cannot create Apktool framework directory");
        String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.trim().isEmpty()) System.setProperty("user.home", context.getFilesDir().getAbsolutePath());

        JSONArray rows = new JSONArray();
        int decoded = 0;
        int cached = 0;
        int failed = 0;

        for (File input : inputs) {
            if (isCancelled(cancelled)) break;
            JSONObject row = new JSONObject();
            row.put("apk", input.getName());
            try {
                String sha = sha256(input, cancelled);
                String id = safe(input.getName()) + "-" + sha.substring(0, 12);
                File out = new File(root, id);
                File marker = new File(out, CACHE_MARKER);
                row.put("sha256", sha).put("workspace", "apktool-workspace/" + id);

                if (isCacheHit(marker, out, sha, cancelled)) {
                    JSONObject fp = workspaceFingerprint(out, cancelled);
                    row.put("status", "CACHE_HIT").put("fileCount", fp.optInt("fileCount"));
                    cached++;
                    rows.put(row);
                    continue;
                }

                if (out.exists()) deleteTree(out, cancelled);
                check(cancelled);

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
                check(cancelled);

                JSONObject fp = workspaceFingerprint(out, cancelled);
                JSONObject cache = new JSONObject()
                        .put("schema", "modkit-apktool-workspace-1.1")
                        .put("engineId", ENGINE_ID)
                        .put("apktoolVersion", APKTOOL_VERSION)
                        .put("apk", input.getName())
                        .put("sha256", sha)
                        .put("workspaceSha256", fp.getString("sha256"))
                        .put("workspaceFileCount", fp.getInt("fileCount"))
                        .put("workspaceBytes", fp.getLong("bytes"))
                        .put("complete", true)
                        .put("finishedAtMs", System.currentTimeMillis());
                check(cancelled);
                Files.write(marker.toPath(), cache.toString(2).getBytes(StandardCharsets.UTF_8));
                row.put("status", "DECODED")
                        .put("fileCount", fp.getInt("fileCount"))
                        .put("manifest", new File(out, "AndroidManifest.xml").isFile())
                        .put("resources", new File(out, "res").isDirectory())
                        .put("smali", hasSmali(out));
                decoded++;
            } catch (InterruptedIOException cancelledError) {
                row.put("status", "CANCELLED");
                rows.put(row);
                break;
            } catch (Throwable error) {
                if (isCancelled(cancelled)) {
                    row.put("status", "CANCELLED");
                    rows.put(row);
                    break;
                }
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
                .put("cancelled", isCancelled(cancelled))
                .put("inputs", rows);
    }

    private static boolean isCacheHit(File marker, File workspace, String sha, AtomicBoolean cancelled) throws Exception {
        if (!marker.isFile() || !workspace.isDirectory()) return false;
        try {
            JSONObject old = new JSONObject(Io.readUtf8(marker));
            if (!old.optBoolean("complete") || !sha.equals(old.optString("sha256"))
                    || !ENGINE_ID.equals(old.optString("engineId"))
                    || !APKTOOL_VERSION.equals(old.optString("apktoolVersion"))) return false;
            String expectedSha = old.optString("workspaceSha256", "");
            int expectedCount = old.optInt("workspaceFileCount", -1);
            long expectedBytes = old.optLong("workspaceBytes", -1L);
            if (expectedSha.isEmpty() || expectedCount < 1 || expectedBytes < 0L) return false;
            JSONObject current = workspaceFingerprint(workspace, cancelled);
            return expectedSha.equals(current.optString("sha256"))
                    && expectedCount == current.optInt("fileCount", -2)
                    && expectedBytes == current.optLong("bytes", -2L);
        } catch (InterruptedIOException cancelledError) {
            throw cancelledError;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static JSONObject workspaceFingerprint(File root, AtomicBoolean cancelled) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long[] stats = new long[]{0L, 0L};
        hashTree(root, root, digest, stats, cancelled);
        if (stats[0] < 1L) throw new IOException("Apktool workspace is empty");
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b));
        return new JSONObject().put("sha256", out.toString()).put("fileCount", stats[0]).put("bytes", stats[1]);
    }

    private static void hashTree(File root, File current, MessageDigest digest, long[] stats, AtomicBoolean cancelled) throws Exception {
        check(cancelled);
        if (current.isFile()) {
            if (CACHE_MARKER.equals(current.getName())) return;
            String relative = root.toPath().relativize(current.toPath()).toString().replace(File.separatorChar, '/');
            digest.update(relative.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(Long.toString(current.length()).getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            byte[] buffer = new byte[1024 * 1024];
            try (FileInputStream in = new FileInputStream(current)) {
                int n;
                while ((n = in.read(buffer)) != -1) {
                    check(cancelled);
                    digest.update(buffer, 0, n);
                }
            }
            stats[0]++;
            stats[1] += current.length();
            return;
        }
        File[] children = current.listFiles();
        if (children == null) return;
        Arrays.sort(children, Comparator.comparing(File::getName));
        for (File child : children) hashTree(root, child, digest, stats, cancelled);
    }

    private static boolean hasSmali(File out) {
        File[] children = out.listFiles();
        if (children == null) return false;
        for (File child : children) if (child.isDirectory() && child.getName().startsWith("smali")) return true;
        return false;
    }

    private static void deleteTree(File file, AtomicBoolean cancelled) throws Exception {
        if (file == null || !file.exists()) return;
        check(cancelled);
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) for (File child : children) deleteTree(child, cancelled);
        }
        if (!file.delete() && file.exists()) throw new IOException("Cannot clear stale Apktool workspace: " + file.getName());
    }

    private static String safe(String name) {
        String value = name.replaceAll("[^A-Za-z0-9._-]+", "_");
        if (value.length() > 72) value = value.substring(0, 72);
        return value.isEmpty() ? "apk" : value;
    }

    private static String sha256(File file, AtomicBoolean cancelled) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (FileInputStream in = new FileInputStream(file)) {
            int n;
            while ((n = in.read(buffer)) != -1) {
                check(cancelled);
                digest.update(buffer, 0, n);
            }
        }
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", b));
        return out.toString();
    }

    private static boolean isCancelled(AtomicBoolean cancelled) {
        return cancelled != null && cancelled.get();
    }

    private static void check(AtomicBoolean cancelled) throws InterruptedIOException {
        if (isCancelled(cancelled)) throw new InterruptedIOException("Apktool analysis cancelled");
    }
}
