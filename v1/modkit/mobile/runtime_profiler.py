"""Universal passive Android runtime/engine profiler.

The profiler is intentionally multi-label: one APK set may contain several runtimes
at once (for example React Native + Hermes + Java/Kotlin + JNI). It never executes
code and never treats absence of a specialized backend as absence of analyzable
content.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-runtime-profiler-1.0"
MAX_SAMPLE_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_PER_PROFILE = 32

_PROFILE_TITLES = {
    "android_dex": "Android Java/Kotlin / DEX",
    "native_elf": "Native ELF / NDK",
    "unity_il2cpp": "Unity / IL2CPP",
    "unity_mono": "Unity / Mono",
    "unreal": "Unreal Engine",
    "flutter": "Flutter / Dart AOT",
    "react_native_hermes": "React Native / Hermes",
    "react_native_jsc": "React Native / JavaScriptCore",
    "dotnet_android": ".NET Android / Xamarin / MAUI / MonoGame",
    "cordova": "Apache Cordova / Ionic",
    "capacitor": "Capacitor",
    "cocos": "Cocos2d-x / Cocos Creator",
    "godot": "Godot",
    "defold": "Defold",
    "qt_qml": "Qt / QML",
    "libgdx": "libGDX",
    "lua_runtime": "Lua / xLua / SLua",
    "webview_hybrid": "Hybrid WebView application",
}

class RuntimeProfileCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise RuntimeProfileCancelled("runtime profiler cancelled")


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    apk_dir = root / "installed-apks"
    if apk_dir.is_dir():
        for p in sorted(apk_dir.glob("*.apk")):
            if p not in paths:
                paths.append(p)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _sample(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with zf.open(info, "r") as source:
        return source.read(min(MAX_SAMPLE_BYTES, max(0, info.file_size)))


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    evidence: dict[str, list[str]] = {key: [] for key in _PROFILE_TITLES}
    abis: set[str] = set()
    apk_names: list[str] = []
    split_like = 0
    asset_pack_like = 0

    def mark(profile: str, value: str) -> None:
        bucket = evidence[profile]
        if value not in bucket and len(bucket) < MAX_EVIDENCE_PER_PROFILE:
            bucket.append(value)

    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_names.append(apk.name)
        low_apk = apk.name.casefold()
        if "split" in low_apk or low_apk.startswith("config.") or "config." in low_apk:
            split_like += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                infos = zf.infolist()
                names = [row.filename for row in infos]
                lows = [name.casefold() for name in names]
                if any(x.startswith("assets/") and ("assetpack" in x or "asset_pack" in x) for x in lows):
                    asset_pack_like += 1
                name_set = set(lows)

                for info, low in zip(infos, lows):
                    _check(cb)
                    if info.is_dir():
                        continue
                    base = low.rsplit("/", 1)[-1]
                    parts = low.split("/")
                    if len(parts) >= 3 and parts[0] == "lib":
                        abi = parts[1]
                        if abi in {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}:
                            abis.add(abi)
                    if base.startswith("classes") and base.endswith(".dex"):
                        mark("android_dex", f"{apk.name}:{info.filename}")
                    if low.endswith(".so"):
                        mark("native_elf", f"{apk.name}:{info.filename}")

                    if base == "libil2cpp.so" or low.endswith("global-metadata.dat"):
                        mark("unity_il2cpp", f"{apk.name}:{info.filename}")
                    if ("/managed/" in low and low.endswith(".dll")) or base in {"libmonobdwgc-2.0.so", "libmonosgen-2.0.so"}:
                        mark("unity_mono", f"{apk.name}:{info.filename}")

                    if base in {"libue4.so", "libunreal.so", "libunrealengine.so"} or low.endswith((".pak", ".ucas", ".utoc")) or "pakchunk" in low:
                        mark("unreal", f"{apk.name}:{info.filename}")

                    if base in {"libflutter.so", "libapp.so"} or "flutter_assets/" in low or base in {"vm_snapshot_data", "isolate_snapshot_data"}:
                        mark("flutter", f"{apk.name}:{info.filename}")

                    if base in {"libhermes.so", "libreactnativejni.so", "libreactnative.so"} or low.endswith((".hbc", ".hermes")):
                        mark("react_native_hermes", f"{apk.name}:{info.filename}")
                    if base in {"libjsc.so", "libjscexecutor.so"}:
                        mark("react_native_jsc", f"{apk.name}:{info.filename}")

                    if (low.startswith("assemblies/") and low.endswith(".dll")) or base in {
                        "libmonodroid.so", "libxamarin-app.so", "libcoreclr.so", "libmonosgen-2.0.so"
                    }:
                        mark("dotnet_android", f"{apk.name}:{info.filename}")

                    if low.endswith("cordova.js") and ("assets/www/" in low or "/www/" in low):
                        mark("cordova", f"{apk.name}:{info.filename}")
                        mark("webview_hybrid", f"{apk.name}:{info.filename}")
                    if "capacitor.config" in low or "assets/public/" in low:
                        mark("capacitor", f"{apk.name}:{info.filename}")
                        mark("webview_hybrid", f"{apk.name}:{info.filename}")

                    if base in {"libcocos2dcpp.so", "libcocos.so", "libcocos2d.so"} or "jsb-adapter" in low:
                        mark("cocos", f"{apk.name}:{info.filename}")
                    if low.endswith((".lua", ".luac", ".luae")) or "liblua" in base or "xlua" in low or "slua" in low:
                        mark("lua_runtime", f"{apk.name}:{info.filename}")

                    if base in {"libgodot_android.so", "libgodot.so"} or low.endswith(".pck") or "/.godot/" in low:
                        mark("godot", f"{apk.name}:{info.filename}")
                    if base == "libdmengine.so" or base in {"game.arcd", "game.arci", "game.dmanifest", "game.projectc"}:
                        mark("defold", f"{apk.name}:{info.filename}")
                    if base.startswith(("libqt5", "libqt6")) and base.endswith(".so") or "/qml/" in low:
                        mark("qt_qml", f"{apk.name}:{info.filename}")
                    if base in {"libgdx.so", "libgdx-box2d.so"}:
                        mark("libgdx", f"{apk.name}:{info.filename}")

                # Bounded DEX/string marker pass catches framework identity that filenames hide.
                marker_needles = {
                    "react_native_hermes": (b"com/facebook/react", b"HermesInternal"),
                    "react_native_jsc": (b"com/facebook/react", b"JavaScriptCore"),
                    "dotnet_android": (b"mono/android", b"Microsoft/Maui", b"xamarin"),
                    "cordova": (b"org/apache/cordova",),
                    "capacitor": (b"com/getcapacitor",),
                    "godot": (b"org/godotengine",),
                    "libgdx": (b"com/badlogic/gdx",),
                    "qt_qml": (b"org/qtproject", b"QtActivity"),
                }
                for info, low in zip(infos, lows):
                    if not (low.rsplit("/", 1)[-1].startswith("classes") and low.endswith(".dex")):
                        continue
                    _check(cb)
                    try:
                        data = _sample(zf, info)
                    except Exception:
                        continue
                    lower = data.lower()
                    for profile, needles in marker_needles.items():
                        if any(needle.lower() in lower for needle in needles):
                            mark(profile, f"{apk.name}:{info.filename}:dex-marker")
                    if b"android/webkit/webview" in lower:
                        mark("webview_hybrid", f"{apk.name}:{info.filename}:WebView")
        except RuntimeProfileCancelled:
            raise
        except Exception:
            continue

    profiles = []
    for profile_id, title in _PROFILE_TITLES.items():
        rows = evidence[profile_id]
        if not rows:
            continue
        confidence = "HIGH" if len(rows) >= 2 else "MEDIUM"
        if profile_id in {"android_dex", "native_elf"}:
            confidence = "HIGH"
        profiles.append({
            "id": "runtime:" + profile_id,
            "runtimeId": profile_id,
            "title": title,
            "kind": "RUNTIME_PROFILE",
            "category": "Engine/Runtime",
            "status": "CONFIRMED",
            "confidence": confidence,
            "evidence": rows,
            "patchReady": False,
            "automationExcluded": True,
            "ownershipKind": "ENGINE",
            "trustBoundary": "local",
        })

    if not profiles and apk_names:
        profiles.append({
            "id": "runtime:unknown",
            "runtimeId": "unknown",
            "title": "Unknown / custom Android runtime",
            "kind": "RUNTIME_PROFILE",
            "category": "Engine/Runtime",
            "status": "REVIEW",
            "confidence": "LOW",
            "evidence": apk_names[:MAX_EVIDENCE_PER_PROFILE],
            "patchReady": False,
            "automationExcluded": True,
            "ownershipKind": "ENGINE",
            "trustBoundary": "local",
        })

    out = {
        "schema": SCHEMA,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": len(apk_names),
        "apkNames": apk_names,
        "splitAware": len(apk_names) > 1 or split_like > 0,
        "splitLikeCount": split_like,
        "assetPackLikeCount": asset_pack_like,
        "abis": sorted(abis),
        "detected": [row["runtimeId"] for row in profiles],
        "profileCount": len(profiles),
        "profiles": profiles,
    }
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
