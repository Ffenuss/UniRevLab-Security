from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from modkit.mobile import unreal_deep


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_unreal_deep_correlates_cooked_sidecars_iostore_pak_and_reflection(tmp_path: Path):
    pak = b"PAKDATA" + b"\x00" * 64 + struct.pack("<I", unreal_deep.PAK_MAGIC) + b"TAIL"
    apk = _apk(tmp_path / "unreal.apk", {
        "assets/pakchunk0-Android.pak": pak,
        "assets/global.utoc": b"UTOC",
        "assets/global.ucas": b"UCAS",
        "assets/Game/Player.uasset": (
            b"/Script/MyGame.PlayerHealth\x00BlueprintGeneratedClass\x00"
            b"Default__BP_Player_C\x00HealthComponent\x00"
        ),
        "assets/Game/Player.uexp": b"TakeDamage\x00PlayerDamage\x00",
        "assets/Game/Player.ubulk": b"bulk",
        "lib/arm64-v8a/libUE4.so": (
            b"\x7fELF\x00UObject\x00UClass\x00FName\x00ProcessEvent\x00StaticFindObject\x00"
        ),
    })

    report = unreal_deep.scan_apk_paths([apk])
    assert report["containerCount"] == 1
    assert report["ioStorePairCount"] == 1
    assert report["cookedAssetGroupCount"] == 1
    assert report["nativeLibraryCount"] == 1
    assert report["reflectionNameCount"] >= 2
    assert report["policy"]["claimsBlueprintSource"] is False
    assert report["policy"]["pakIndexFullyParsed"] is False
    assert report["policy"]["ioStoreIndexFullyParsed"] is False

    pak_row = report["containers"][0]
    assert pak_row["pakFooterMagicObserved"] is True
    assert pak_row["pakMagicCandidateOffsets"]

    kinds = {row["kind"] for row in report["findings"]}
    assert "UNREAL_COOKED_ASSET_GROUP" in kinds
    assert "UNREAL_IOSTORE_CONTAINER_PAIR" in kinds
    assert "UNREAL_NATIVE_RUNTIME" in kinds
    assert "UNREAL_REFLECTION_NAME" in kinds
    assert "UNREAL_COOKED_SEMANTIC_STRING" in kinds

    group = next(row for row in report["findings"] if row["kind"] == "UNREAL_COOKED_ASSET_GROUP")
    assert group["uasset"].endswith("Player.uasset")
    assert group["uexp"].endswith("Player.uexp")
    assert group["ubulk"].endswith("Player.ubulk")
    assert group["sidecarComplete"] is True

    io = next(row for row in report["findings"] if row["kind"] == "UNREAL_IOSTORE_CONTAINER_PAIR")
    assert io["pairComplete"] is True

    semantic = [row for row in report["findings"] if row["kind"] == "UNREAL_COOKED_SEMANTIC_STRING"]
    assert any("health" in row["semanticDomains"] for row in semantic)
    assert any("damage" in row["semanticDomains"] for row in semantic)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_unreal_incomplete_sidecars_and_iostore_stay_explicitly_incomplete(tmp_path: Path):
    apk = _apk(tmp_path / "partial.apk", {
        "assets/Game/Only.uasset": b"/Script/Game.OnlyAsset",
        "assets/chunk.utoc": b"UTOC",
    })
    report = unreal_deep.scan_apk_paths([apk])
    group = next(row for row in report["findings"] if row["kind"] == "UNREAL_COOKED_ASSET_GROUP")
    io = next(row for row in report["findings"] if row["kind"] == "UNREAL_IOSTORE_CONTAINER_PAIR")
    assert group["sidecarComplete"] is False
    assert io["pairComplete"] is False
