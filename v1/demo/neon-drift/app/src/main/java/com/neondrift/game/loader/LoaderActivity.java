package com.neondrift.game.loader;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.MotionEvent;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Console for the generated module: pick a feature key, type a value, apply.
 * The real menu is drawn inside the game (overlay.cpp) — this exists so a build
 * without ImGui is still operable, and so offsets can be probed one by one.
 */
public final class LoaderActivity extends Activity {

    private static final String[] KEYS = new String[] {
        "infinite_ammo.Weapon.get_Ammo",
        "no_cooldown.Weapon.GetCooldown",
        "one_hit_kill.Weapon.GetDamage",
        "log_spawns.EnemySpawner.Spawn",
        "economy.GameOptions.coins",
        "economy.GameOptions.coins.lock",
        "economy.PlayerSave.gems",
        "economy.PlayerSave.gems.lock",
        "economy.PlayerSave.gold",
        "economy.PlayerSave.gold.lock",
        "movement.PlayerController.jumpsLeft.mem",
        "movement.PlayerController.moveSpeed",
        "movement.PlayerController.moveSpeed.lock",
        "progress.PlayerSave.level",
        "progress.PlayerSave.level.lock",
        "unlock_all.PlayerSave.s_debugUnlocks",
        "god_mode.PlayerController.get_IsGodMode",
        "god_mode.PlayerController.set_IsGodMode",
        "no_damage.PlayerController.TakeDamage",
        "survival.PlayerController.maxHealth.mem",
        "debug.save_now",
    };

    private EditText value;
    private TextView status;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        ModKit.load();
        ModKit.nativeInit();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        status = new TextView(this);
        status.setTextIsSelectable(true);
        root.addView(status);

        Button refresh = new Button(this);
        refresh.setText("refresh status");
        refresh.setOnClickListener(v -> status.setText(ModKit.nativeStatus()));
        root.addView(refresh);

        value = new EditText(this);
        value.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL
                | InputType.TYPE_NUMBER_FLAG_SIGNED);
        value.setText("1");
        root.addView(value);

        for (String key : KEYS) {
            Button b = new Button(this);
            b.setAllCaps(false);
            b.setText(key);
            b.setOnClickListener(v -> {
                double d = parse(value.getText().toString());
                ModKit.nativeSetFeature(key, d);
                status.setText("set " + key + " = " + d + "\n" + ModKit.nativeStatus());
            });
            b.setOnLongClickListener(v -> {
                value.setText(String.valueOf(ModKit.nativeGetFeature(key)));
                return true;
            });
            root.addView(b);
        }

        ScrollView sc = new ScrollView(this);
        sc.addView(root);
        setContentView(sc);
        status.setText(ModKit.nativeStatus());
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        // forwards to the in-game overlay when it runs on top of this console
        ModKit.nativePushTouch(ev.getActionMasked(), ev.getX(), ev.getY());
        return super.dispatchTouchEvent(ev);
    }

    private static double parse(String s) {
        try {
            return Double.parseDouble(s.trim());
        } catch (RuntimeException e) {
            return 1.0;
        }
    }
}
