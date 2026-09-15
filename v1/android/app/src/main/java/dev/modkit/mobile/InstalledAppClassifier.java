package dev.modkit.mobile;

import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.os.Build;

import java.io.File;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Fast, background-only installed-app classification using Android metadata plus strong engine markers. */
final class InstalledAppClassifier {
    private static final int MAX_ENTRIES_PER_APK=40000;
    private InstalledAppClassifier(){}

    static boolean isGame(ResolveInfo resolve){
        if(resolve==null||resolve.activityInfo==null||resolve.activityInfo.applicationInfo==null)return false;
        ApplicationInfo ai=resolve.activityInfo.applicationInfo;
        if(Build.VERSION.SDK_INT>=26&&ai.category==ApplicationInfo.CATEGORY_GAME)return true;
        if(hasGameMarkers(ai.sourceDir))return true;
        if(ai.splitSourceDirs!=null)for(String split:ai.splitSourceDirs)if(hasGameMarkers(split))return true;
        return false;
    }

    private static boolean hasGameMarkers(String path){
        if(path==null||path.isEmpty())return false;File apk=new File(path);if(!apk.isFile())return false;
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> entries=zip.entries();int seen=0;
            while(entries.hasMoreElements()&&seen++<MAX_ENTRIES_PER_APK){
                ZipEntry e=entries.nextElement();if(e.isDirectory())continue;String n=e.getName().toLowerCase(Locale.ROOT);
                if(n.endsWith("/libunity.so")||n.endsWith("/libue4.so")||n.endsWith("/libunreal.so")||n.contains("libcocos2d")||n.endsWith("/libgodot_android.so"))return true;
                if(n.equals("assets/bin/data/globalgamemanagers")||n.startsWith("assets/bin/data/managed/")||n.startsWith("assets/bin/data/resources/"))return true;
                if(n.contains("/ue4game/")||n.startsWith("assets/ue4game/")||n.contains("unrealengine"))return true;
                if(n.startsWith("assets/res/import/")&&n.endsWith(".stex"))return true;
            }
        }catch(Exception ignored){}
        return false;
    }
}
