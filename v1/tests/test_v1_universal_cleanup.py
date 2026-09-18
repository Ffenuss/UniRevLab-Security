from pathlib import Path


def test_interrupted_target_cleanup_removes_all_universal_engine_reports():
    root = Path(__file__).resolve().parents[1]
    source = (root / "android/app/src/main/java/dev/modkit/mobile/App.java").read_text(encoding="utf-8")
    required = {
        "runtime-profiler.json",
        "engine-router.json",
        "deobfuscation.json",
        "native-inventory.json",
        "native-portable.json",
        "arm32-deep.json",
        "dotnet-deep.json",
        "unreal-deep.json",
        "godot-deep.json",
        "defold-deep.json",
        "qml-deep.json",
        "jsc-deep.json",
        "wasm-deep.json",
        "lua-deep.json",
        "hermes-deep.json",
        "native-deep.json",
        "cocos-deep.json",
        "flutter-deep.json",
        "deep-gameplay.json",
    }
    missing = sorted(name for name in required if f'"{name}"' not in source)
    assert not missing, f"universal evidence may survive interrupted target preparation: {missing}"
