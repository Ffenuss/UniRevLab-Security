# Keep intentionally minimal. Add rules only when a concrete dependency requires them.

# JNI symbol is name-based; keep the bridge stable across R8/minification.
-keep class org.unirevlab.security.nativecore.NativeAnalysis { *; }
