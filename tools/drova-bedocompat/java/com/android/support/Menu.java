package com.android.support;

import android.content.Context;
import android.widget.TextView;

public final class Menu {
    static { System.loadLibrary("Bedo"); }
    public static native String[] GetFeatureList();
    public static native String[] SettingsList();
    public static native boolean IsGameLibLoaded();
    public static native void Init(Context c, TextView a, TextView b, TextView d);
    public static native String Icon();
    public static native String IconWebViewData();
}
