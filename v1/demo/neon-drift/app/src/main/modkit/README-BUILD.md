# neondrift — generated offline mod module

Produced by `modkit` from the target's `global-metadata.dat` + `libil2cpp.so`
(7 types / 28 methods indexed, dump source: dump.cs).

| | |
|---|---|
| package | `com.neondrift.game` |
| abi | `arm64-v8a` |
| hooked module | `libil2cpp.so` |
| metadata version | 27 |
| features | 21 |
| instance-capture hooks | 3 |

## How it works

1. `modkit` reads the dumper output and turns matched members into a feature table
   (`app/src/main/cpp/features.inc`) with the exact RVAs from the dump.
2. `jni_main.cpp` is loaded inside the game process. It waits for `libil2cpp.so` to be mapped,
   takes the runtime base from `dl_iterate_phdr`, and translates every RVA at that base.
3. Three mechanisms, picked per feature by the analyzer:
   * **const_return** — the method prologue becomes `mov w0/x0, #imm; ret`
     (gold getters, damage, cooldowns). Original bytes are captured before patching,
     so the menu can switch it back off.
   * **value_set / toggle / action** — a direct native call to the managed method with
     the il2cpp ABI (`this` in x0). No patching, nothing to detect.
   * **field_write / static_write** — raw write at `this + off` or at the absolute rva of
     a static field's storage.
4. Instance members need an object. The generator installs a *capture hook* on a
   lifecycle method of the owning class (`Update`, `OnEnable`, …) and caches `this` in a
   slot; the menu shows `obj` / `no obj` next to those entries so you can see when the
   object has not been reached yet.
5. Menu rendering: hook `eglSwapBuffers` → draw ImGui with the game's GL context
   (`overlay.cpp`). With `-DMODKIT_HAS_IMGUI=OFF` the loader activity's console
   (feature key + value) is the fallback UI, which needs no permission at all.

## Build

```sh
# optional but recommended:
git clone --depth 1 https://github.com/ocornut/imgui third_party/imgui
git clone --depth 1 https://github.com/jmp03/Dobby third_party/dobby   # -DMODKIT_HAVE_DOBBY=ON

./build.sh                       # NDK only -> build/arm64-v8a/libneondrift.so
# or  ./gradlew :app:assembleRelease
```

Then load it in the game process: repack the APK with the library in `lib/arm64-v8a/`
plus an `Application` hook that calls `System.loadLibrary("neondrift")`, or start it from
the loader app (`LoaderActivity`) for the console build.

## Feature map

| group | feature | kind | target | rva | conf |
|---|---|---|---|---|---|
| Combat | Infinite Ammo | const_return | NeonDrift.Play.Weapon.get_Ammo | 0x1210 | 0.74 |
| Combat | No Cooldown | const_return | NeonDrift.Play.Weapon.GetCooldown | 0x1240 | 0.74 |
| Combat | One Hit Kill | const_return | NeonDrift.Play.Weapon.GetDamage | 0x1230 | 0.74 |
| Debug | Log Enemy Spawns | hook | NeonDrift.Play.EnemySpawner.Spawn | 0x1310 | 0.66 |
| Economy | Coins → set | value_set | NeonDrift.Save.GameOptions.set_Coins | 0x1410 | 0.95 |
| Economy | Coins lock | const_return | NeonDrift.Save.GameOptions.get_Coins | 0x1400 | 0.90 |
| Economy | Gems → set | value_set | NeonDrift.Save.PlayerSave.set_Gems | 0x1070 | 0.95 |
| Economy | Gems lock | const_return | NeonDrift.Save.PlayerSave.get_Gems | 0x1060 | 0.90 |
| Economy | Gold → set | value_set | NeonDrift.Save.PlayerSave.set_Gold | 0x1050 | 0.95 |
| Economy | Gold lock | const_return | NeonDrift.Save.PlayerSave.get_Gold | 0x1040 | 0.90 |
| Movement | Jumpsleft → write | field_write | NeonDrift.Play.PlayerController.jumpsLeft | — | 0.80 |
| Movement | Movespeed → set | value_set | NeonDrift.Play.PlayerController.set_MoveSpeed | 0x1130 | 0.95 |
| Movement | Movespeed lock | const_return | NeonDrift.Play.PlayerController.get_MoveSpeed | 0x1120 | 0.90 |
| Progress | Level → set | value_set | NeonDrift.Save.PlayerSave.set_Level | 0x1090 | 0.95 |
| Progress | Level lock | const_return | NeonDrift.Save.PlayerSave.get_Level | 0x1080 | 0.90 |
| Progress | Unlock Everything | static_write | NeonDrift.Save.PlayerSave.s_debugUnlocks | 0x5010 | 0.70 |
| Survival | God Mode | const_return | NeonDrift.Play.PlayerController.get_IsGodMode | 0x1150 | 0.80 |
| Survival | God Mode | toggle | NeonDrift.Play.PlayerController.set_IsGodMode | 0x1140 | 0.72 |
| Survival | Ignore Damage | hook | NeonDrift.Play.PlayerController.TakeDamage | 0x1110 | 0.80 |
| Survival | Maxhealth → write | field_write | NeonDrift.Play.PlayerController.maxHealth | — | 0.80 |
| Utility | Save Now | action | NeonDrift.Save.PlayerSave.Save | 0x10a0 | 0.90 |

## Analyzer notes

- rules: /home/user/il2cpp-modkit/rules/default.json
- arch: arm64, page: 0x10000
- dump.cs: 7 types, 28 methods (27 with an RVA)
- libil2cpp: aarch64, PIE, .text=0x4000, 3 symbols

## Verifying on device

```sh
adb logcat -s neondrift | head -60          # base, hooks, patch sites
adb push modkit.properties /sdcard/Android/data/com.neondrift.game/files/
```

`modkit verify` re-reads the dump and the `.so` and checks every recorded RVA still
points at a plausible function prologue — run it after **any** game update, offsets move
between builds even when the logic does not.

## Limits you should know before wiring the last 10 %

* Only `arm64` encodings are emitted (`movz/movk/ret`, 16-byte patch windows). A 32-bit
  build needs a Thumb-2 encoder; `modkit build --abi armeabi-v7a` will tell you it is
  unsupported instead of emitting garbage.
* Constructors, property accessors with side effects and `System.Void` setters on
  reference-type fields are intentionally not auto-patched — they appear in
  `features.json` with `confidence` < 0.4 and are left out of the table.
* `const_return` on a method whose prologue is PC-relative cannot be inline-hooked with
  the built-in hooker; link Dobby for those.
* Nothing here is obfuscation-proof: if the target renames its symbols, the rules json
  (not the generator) is the place to teach modkit the new names.
