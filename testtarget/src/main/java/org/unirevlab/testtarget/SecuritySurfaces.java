package org.unirevlab.testtarget;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/**
 * Intentionally reviewable security surfaces used only by the UniRevLab regression fixture.
 * Values are synthetic and the application has no real account, purchase, or backend integration.
 */
public final class SecuritySurfaces {
    public static final String FIXTURE_HTTP_ENDPOINT = "http://127.0.0.1:8080/fixture";
    public static final String FIXTURE_LICENSE = "LAB-FIXTURE-LOCAL-LICENSE";
    public static final String FIXTURE_SIGNER_SHA256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    private SecuritySurfaces() {}

    public static boolean isPremiumUnlocked(Context context) {
        boolean unlocked = context.getSharedPreferences("license_state", Context.MODE_PRIVATE)
                .getBoolean("premium_unlocked", false);
        long trialEnd = context.getSharedPreferences("license_state", Context.MODE_PRIVATE)
                .getLong("trial_end_ms", 0L);
        return unlocked || (trialEnd > System.currentTimeMillis() && isFeatureEnabled(context, "premium_beta"));
    }

    public static boolean isFeatureEnabled(Context context, String flag) {
        return context.getSharedPreferences("feature_flags", Context.MODE_PRIVATE)
                .getBoolean(flag, false);
    }

    public static boolean grantFixtureLicense(Context context, String candidate) {
        boolean valid = FIXTURE_LICENSE.equals(candidate == null ? "" : candidate.trim());
        if (valid) {
            context.getSharedPreferences("license_state", Context.MODE_PRIVATE)
                    .edit().putBoolean("premium_unlocked", true).apply();
        }
        return valid;
    }

    public static boolean debuggerAttached() {
        return android.os.Debug.isDebuggerConnected();
    }

    public static int tracerPid() {
        try {
            for (String line : java.nio.file.Files.readAllLines(new File("/proc/self/status").toPath())) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                }
            }
        } catch (Throwable ignored) {
            // Regression fixture: absence is a valid result.
        }
        return 0;
    }

    public static boolean rootIndicatorPresent() {
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su"};
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return Build.TAGS != null && Build.TAGS.contains("test-keys");
    }

    public static boolean emulatorIndicatorPresent() {
        String fingerprint = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT.toLowerCase();
        String model = Build.MODEL == null ? "" : Build.MODEL.toLowerCase();
        return fingerprint.contains("generic") || fingerprint.contains("ranchu") ||
                model.contains("emulator") || model.contains("sdk_gphone");
    }

    public static Object reflectionSurface(String className) throws Exception {
        Class<?> cls = Class.forName(className);
        return cls.getDeclaredConstructor().newInstance();
    }

    public static ClassLoader dynamicLoaderSurface(Context context, String dexPath) {
        File optimized = context.getDir("fixture-dex", Context.MODE_PRIVATE);
        return new DexClassLoader(dexPath, optimized.getAbsolutePath(), null, context.getClassLoader());
    }

    public static Process processExecutionSurface() throws Exception {
        return new ProcessBuilder("/system/bin/sh", "-c", "echo unirevlab-testtarget").start();
    }

    public static byte[] weakDigestSurface(byte[] input) throws Exception {
        return MessageDigest.getInstance("MD5").digest(input);
    }

    public static Cipher weakCipherSurface() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public static boolean signerMatchesFixture(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null) return false;
            byte[] cert = info.signingInfo.getApkContentsSigners()[0].toByteArray();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert);
            return FIXTURE_SIGNER_SHA256.equals(toHex(digest));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean localIntegrityGate(Context context) {
        return signerMatchesFixture(context) && !debuggerAttached() && tracerPid() == 0;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }
}
