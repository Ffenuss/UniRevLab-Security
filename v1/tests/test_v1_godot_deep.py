from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from modkit.mobile import godot_deep


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_godot_deep_parses_pck_header_gdscript_and_scene_graph(tmp_path: Path):
    pck = b"GDPC" + struct.pack("<IIII", 2, 4, 3, 0) + b"\x00" * 128
    scene = b"""
[gd_scene load_steps=2 format=3]

[ext_resource type="Script" path="res://player.gd" id="1_abcd"]

[sub_resource type="Resource" id="Resource_stats"]

[node name="World" type="Node2D"]

[node name="PlayerHealth" type="CharacterBody2D" parent="."]
script = ExtResource("1_abcd")

[node name="WeaponDamage" type="Node" parent="PlayerHealth"]
"""
    script = b"""
extends CharacterBody2D
class_name PlayerStats
signal health_changed

func take_damage(amount):
    return amount

func set_health(value):
    return value
"""
    apk = _apk(tmp_path / "godot.apk", {
        "assets/game.pck": pck,
        "assets/main.tscn": scene,
        "assets/player.gd": script,
    })

    report = godot_deep.scan_apk_paths([apk])
    assert report["packCount"] == 1
    assert report["sceneCount"] == 1
    assert report["scriptCount"] == 1
    assert report["policy"]["claimsOriginalSourceFromPck"] is False
    assert report["policy"]["binaryPckFileTableParsed"] is False

    pack = report["packs"][0]
    assert pack["headerConfirmed"] is True
    assert pack["header"]["packFormatVersion"] == 2
    assert pack["header"]["engineVersion"] == {"major": 4, "minor": 3, "patch": 0}

    scene_row = report["scenes"][0]
    assert len(scene_row["nodes"]) == 3
    assert scene_row["externalResources"][0]["path"] == "res://player.gd"
    assert scene_row["subResources"][0]["type"] == "Resource"

    script_row = report["scripts"][0]
    assert script_row["className"] == "PlayerStats"
    assert script_row["extends"] == "CharacterBody2D"
    assert script_row["signals"] == ["health_changed"]
    assert [row["name"] for row in script_row["functions"]] == ["take_damage", "set_health"]

    kinds = {row["kind"] for row in report["findings"]}
    assert "GODOT_PCK_CONTAINER" in kinds
    assert "GODOT_GDSCRIPT" in kinds
    assert "GODOT_TEXT_SCENE_GRAPH" in kinds
    assert "GODOT_SCRIPT_FUNCTION" in kinds
    assert "GODOT_SCENE_NODE_SEMANTIC" in kinds

    semantic = [row for row in report["findings"] if row["kind"] in {
        "GODOT_SCRIPT_FUNCTION", "GODOT_SCENE_NODE_SEMANTIC"
    }]
    assert any("damage" in row["semanticDomains"] for row in semantic)
    assert any("health" in row["semanticDomains"] for row in semantic)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_non_godot_pck_extension_is_review_not_fake_header(tmp_path: Path):
    apk = _apk(tmp_path / "fake.apk", {
        "assets/game.pck": b"NOTGODOT" + b"\x00" * 64,
    })
    report = godot_deep.scan_apk_paths([apk])
    assert report["packCount"] == 1
    pack = report["packs"][0]
    assert pack["headerConfirmed"] is False
    finding = next(row for row in report["findings"] if row["kind"] == "GODOT_PCK_CONTAINER")
    assert finding["status"] == "REVIEW"
