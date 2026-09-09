package com.android.support;

import android.content.Context;

public final class Preferences {
    public static native void Changes(Context c, int feature, String name,
                                      int value, long longValue, boolean enabled,
                                      String text);
}
