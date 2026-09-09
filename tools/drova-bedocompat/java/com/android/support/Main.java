package com.android.support;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.provider.Settings;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class Main {
    private static boolean shown;
    private static WindowManager wm;
    private static View bubble;
    private static View panel;

    public static void CheckOverlayPermission(final Context source) {
        final Context c = source.getApplicationContext();
        if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(c)) {
            Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + c.getPackageName()));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(i);
            new Handler(c.getMainLooper()).postDelayed(() -> CheckOverlayPermission(c), 1200);
            return;
        }
        if (!shown) create(c);
    }

    private static GradientDrawable bg(int color, float radius) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color); g.setCornerRadius(radius); g.setStroke(1, 0xff496274);
        return g;
    }

    private static StateListDrawable buttonBg() {
        StateListDrawable s = new StateListDrawable();
        s.addState(new int[]{android.R.attr.state_pressed}, bg(0xff376079, 10));
        s.addState(new int[]{}, bg(0xff1f2c35, 10));
        return s;
    }

    private static WindowManager.LayoutParams params(int width, int height, int x, int y) {
        int type = Build.VERSION.SDK_INT >= 26
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;
        WindowManager.LayoutParams p = new WindowManager.LayoutParams(width, height, type,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE, PixelFormat.TRANSLUCENT);
        p.gravity = Gravity.TOP | Gravity.START; p.x = x; p.y = y;
        return p;
    }

    private static TextView text(Context c, String value, int sp) {
        TextView v = new TextView(c); v.setText(value); v.setTextColor(Color.WHITE);
        v.setTextSize(sp); v.setGravity(Gravity.CENTER_VERTICAL); v.setPadding(18, 10, 18, 10);
        return v;
    }

    private static void create(Context c) {
        shown = true; wm = (WindowManager)c.getSystemService(Context.WINDOW_SERVICE);
        TextView icon = text(c, "D", 22); icon.setGravity(Gravity.CENTER);
        icon.setTextColor(0xffffffff); icon.setBackground(bg(0xff9b342e, 64));
        bubble = icon;
        WindowManager.LayoutParams bp = params(58, 58, 18, 170);
        drag(icon, bp, true); wm.addView(icon, bp);

        LinearLayout root = new LinearLayout(c); root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(7, 7, 7, 7); root.setBackground(bg(0xf223303a, 12));
        TextView title = text(c, "Drova — меню разработчиков", 18);
        title.setGravity(Gravity.CENTER); title.setBackground(bg(0xff30485a, 8));
        root.addView(title, new LinearLayout.LayoutParams(-1, 54));

        ScrollView scroll = new ScrollView(c); scroll.setFillViewport(true);
        LinearLayout list = new LinearLayout(c); list.setOrientation(LinearLayout.VERTICAL);
        String[] features = Menu.GetFeatureList();
        for (int index=0; index<features.length; index++) {
            String item = features[index];
            if (item.startsWith("Category_")) continue;
            final int id = index;
            String label = item.startsWith("Button_") ? item.substring(7) : item;
            Button b = new Button(c); b.setAllCaps(false); b.setText(label); b.setTextSize(16);
            b.setTextColor(Color.WHITE); b.setBackground(buttonBg());
            b.setOnClickListener(v -> {
                v.animate().scaleX(.96f).scaleY(.96f).setDuration(70)
                        .withEndAction(() -> v.animate().scaleX(1f).scaleY(1f).setDuration(90));
                Preferences.Changes(c, id, label, 0, 0, true, "");
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, 58);
            lp.setMargins(4, 4, 4, 4); list.addView(b, lp);
        }
        scroll.addView(list); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        Button close = new Button(c); close.setText("СВЕРНУТЬ"); close.setAllCaps(false);
        close.setOnClickListener(v -> setOpen(false)); root.addView(close, new LinearLayout.LayoutParams(-1, 48));
        panel = root;
        WindowManager.LayoutParams pp = params(430, 620, 85, 120);
        drag(title, pp, false); wm.addView(root, pp); root.setVisibility(View.GONE);
    }

    private static void setOpen(boolean open) {
        if (panel != null) panel.setVisibility(open ? View.VISIBLE : View.GONE);
        if (bubble != null) bubble.setVisibility(open ? View.GONE : View.VISIBLE);
    }

    private static void drag(View handle, WindowManager.LayoutParams p, boolean opens) {
        handle.setOnTouchListener(new View.OnTouchListener() {
            float downX, downY; int startX, startY; boolean moved;
            public boolean onTouch(View v, MotionEvent e) {
                switch (e.getActionMasked()) {
                    case MotionEvent.ACTION_DOWN:
                        downX=e.getRawX(); downY=e.getRawY(); startX=p.x; startY=p.y; moved=false;
                        return true;
                    case MotionEvent.ACTION_MOVE:
                        float dx=e.getRawX()-downX, dy=e.getRawY()-downY;
                        if (dx*dx+dy*dy > 100) moved=true;
                        if (moved) { p.x=startX+(int)dx; p.y=startY+(int)dy; wm.updateViewLayout(opens?bubble:panel,p); }
                        return true;
                    case MotionEvent.ACTION_UP:
                        if (!moved && opens) setOpen(true);
                        return true;
                    default: return false;
                }
            }
        });
    }
}
