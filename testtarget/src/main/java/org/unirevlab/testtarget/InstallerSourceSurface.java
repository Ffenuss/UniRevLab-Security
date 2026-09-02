package org.unirevlab.testtarget;

import android.content.Context;
import android.os.Build;

/** Controlled fixture for PackageManager installation-source xrefs. */
public final class InstallerSourceSurface {
    private InstallerSourceSurface() {}

    @SuppressWarnings("deprecation")
    public static String installer(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                String name = context.getPackageManager()
                        .getInstallSourceInfo(context.getPackageName())
                        .getInstallingPackageName();
                return name == null ? "<unknown>" : name;
            }
            String name = context.getPackageManager().getInstallerPackageName(context.getPackageName());
            return name == null ? "<unknown>" : name;
        } catch (Throwable ignored) {
            return "<unavailable>";
        }
    }
}
