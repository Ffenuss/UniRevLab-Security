from pathlib import Path

from modkit.mobile.deep_gameplay import analyze, classify


def test_compact_and_camelcase_gameplay_aliases_are_recovered():
    cases = {
        "GetHP": "health",
        "SetMaxHP": "health",
        "ApplyDamageMultiplier": "damage",
        "GetRunSpeed": "speed",
        "ResetSkillCD": "cooldown",
        "AddCoins": "currency",
        "WalletBalance": "currency",
        "GrantXP": "level_xp",
        "PlayerLevel": "level_xp",
        "SetMaxMana": "mana_energy",
        "JumpHeight": "movement",
        "CameraFOV": "camera",
    }
    for name, expected in cases.items():
        domain, aliases = classify(name)
        assert domain == expected, (name, domain, aliases)
        assert aliases


def test_short_aliases_require_real_tokens_not_arbitrary_substrings():
    assert classify("ShippingManager")[0] == ""
    assert classify("LevelEditor")[0] == "level_xp"
    assert classify("GetHPValue")[0] == "health"


def test_native_symbols_missing_from_old_domain_filter_gain_exact_static_locator():
    artifacts = {
        "artifacts": [
            {
                "id": "existing-health",
                "title": "GetHealth",
                "kind": "NATIVE_FUNCTION",
                "entry": "lib/arm64-v8a/libgame.so",
                "library": "lib/arm64-v8a/libgame.so",
                "rva": 0x1000,
                "gameplayDomain": "health",
            }
        ]
    }
    native = {
        "libraries": [
            {
                "entry": "lib/arm64-v8a/libgame.so",
                "abi": "arm64-v8a",
                "functions": [
                    {"name": "GetHealth", "rva": 0x1000, "size": 24},
                    {"name": "GetHP", "rva": 0x1100, "size": 20},
                    {"name": "AddMoney", "rva": 0x1200, "size": 28},
                    {"name": "GrantXP", "rva": 0x1300, "size": 32},
                ],
            }
        ]
    }
    report = analyze(artifacts, native)
    by_title = {row["title"]: row for row in report["findings"]}
    assert "GetHealth" not in by_title  # already covered by the original deep backend
    assert by_title["GetHP"]["gameplayDomain"] == "health"
    assert by_title["GetHP"]["rva"] == 0x1100
    assert by_title["AddMoney"]["gameplayDomain"] == "currency"
    assert by_title["GrantXP"]["gameplayDomain"] == "level_xp"
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["runtimeTruth"] == "not-observed-by-static-analysis" for row in report["findings"])
    assert report["locatorCount"] == 3


def test_script_symbols_gain_searchable_locator_without_becoming_patch_ready():
    artifacts = {
        "artifacts": [
            {
                "id": "script-hp",
                "kind": "SCRIPT_SYMBOL",
                "family": "lua",
                "title": "setPlayerHP",
                "function": "setPlayerHP",
                "entry": "assets/scripts/player.lua",
                "line": 42,
                "ownershipKind": "APP_OR_GAME",
            }
        ]
    }
    report = analyze(artifacts, {})
    row = report["findings"][0]
    assert row["gameplayDomain"] == "health"
    assert row["status"] == "SCRIPT_CONTENT_SEARCH"
    assert row["entry"] == "assets/scripts/player.lua"
    assert row["function"] == "setPlayerHP"
    assert row["line"] == 42
    assert row["patchReady"] is False


def test_embedded_pipeline_registers_semantic_gameplay_report():
    root = Path(__file__).resolve().parents[1]
    text = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert "deep_gameplay.scan_workspace" in text
    assert '"deepGameplayReport": "deep-gameplay.json"' in text
    assert 'summary_key="deepGameplay"' in text
