from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import defold_deep


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_defold_deep_correlates_archive_manifest_resources_and_native_engine(tmp_path: Path):
    apk = _apk(tmp_path / "defold.apk", {
        "assets/game.arci": (
            b"res:/main/player_health.scriptc\x00"
            b"/main/weapon_damage.goc\x00"
        ),
        "assets/game.arcd": b"compiled archive payload",
        "assets/game.dmanifest": (
            b"/main/player_health.scriptc\x00"
            b"/main/battle.collectionc\x00"
        ),
        "assets/game.projectc": b"player health damage inventory speed",
        "lib/arm64-v8a/libdmengine.so": b"\x7fELF",
    })

    report = defold_deep.scan_apk_paths([apk])
    assert report["archiveGroupCount"] == 1
    assert report["resourcePathCount"] >= 2
    assert report["nativeLibraryCount"] == 1
    assert report["policy"]["archivePayloadFullyDecoded"] is False
    assert report["policy"]["claimsOriginalLuaSource"] is False

    kinds = {row["kind"] for row in report["findings"]}
    assert "DEFOLD_NATIVE_ENGINE" in kinds
    assert "DEFOLD_ARCHIVE_GROUP" in kinds
    assert "DEFOLD_RESOURCE_PATH" in kinds
    assert "DEFOLD_COMPILED_SEMANTIC_STRING" in kinds

    group = next(row for row in report["findings"] if row["kind"] == "DEFOLD_ARCHIVE_GROUP")
    assert group["archivePairComplete"] is True
    assert group["manifestPresent"] is True
    assert group["projectPresent"] is True
    assert group["index"].endswith("game.arci")
    assert group["data"].endswith("game.arcd")

    resources = [row["resourcePath"] for row in report["findings"] if row["kind"] == "DEFOLD_RESOURCE_PATH"]
    assert any("player_health.scriptc" in value for value in resources)
    semantic = [row for row in report["findings"] if row["kind"] == "DEFOLD_COMPILED_SEMANTIC_STRING"]
    assert any("health" in row["semanticDomains"] for row in semantic)
    assert any("damage" in row["semanticDomains"] for row in semantic)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_defold_partial_archive_remains_explicitly_incomplete(tmp_path: Path):
    apk = _apk(tmp_path / "partial.apk", {
        "assets/game.arci": b"/main/player.scriptc",
    })
    report = defold_deep.scan_apk_paths([apk])
    group = next(row for row in report["findings"] if row["kind"] == "DEFOLD_ARCHIVE_GROUP")
    assert group["archivePairComplete"] is False
    assert group["manifestPresent"] is False
