package com.neondrift.game.loader;

// Thin JNI facade over libneondrift.so — the whole menu lives in native code.
public final class ModKit {

    private static volatile boolean loaded;

    private ModKit() {}

    public static synchronized void load() {
        if (loaded) return;
        System.loadLibrary("neondrift");
        loaded = true;
    }

    public static boolean ready() { return loaded && nativeReady(); }

    public static native void nativeInit();
    public static native boolean nativeReady();
    public static native String nativeStatus();
    public static native void nativeSetFeature(String key, double value);
    public static native double nativeGetFeature(String key);
    public static native void nativePushTouch(int action, float x, float y);
}
