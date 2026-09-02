package org.unirevlab.testtarget;

public final class NativeFixture {
    static {
        System.loadLibrary("unirevlab_fixture");
    }

    private NativeFixture() {}

    public static native String marker();
}
