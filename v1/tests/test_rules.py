"""Rule set loading, merging and linting."""

from __future__ import annotations

import json

import pytest

from modkit.analyze.rules import BUILTIN_DEFAULTS, dump_builtin, load, validate

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


def test_builtin_defaults_compile():
    rules = load(None)
    assert rules.groups and rules.actions
    assert rules.source == "builtin"
    assert rules.is_ignored("UnityEngine.MonoBehaviour")
    assert not rules.is_ignored("Game.Play.Player")
    assert rules.priority_score("Game.Save.PlayerData") > 0
    assert rules.priority_score("Neon.Render.Skybox") == 0.0
    assert rules.is_ignored("Neon.UI.SmallPanel")          # `\.(UI|Editor|...)\.` pattern


def test_default_json_matches_the_builtin_shape():
    user = load(ROOT / "rules" / "default.json")
    builtin = load(None)
    assert {g.id for g in builtin.groups} <= {g.id for g in user.groups}
    assert any(a.kind == "const_return" for a in user.actions)


def test_user_rules_are_merged_on_top_of_defaults(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"groups": [{"id": "custom", "label": "Custom",
                                         "class": "Player", "member": "essence"}],
                             "limits": {"max_features": 7}}))
    rules = load(p)
    assert any(g.id == "custom" for g in rules.groups)
    assert any(g.id == "economy" for g in rules.groups), "defaults must still apply"
    assert rules.limits["max_features"] == 7
    assert rules.limits["min_confidence"] == BUILTIN_DEFAULTS["limits"]["min_confidence"]
    assert rules.source == str(p)


def test_merge_defaults_false_replaces(tmp_path):
    p = tmp_path / "only.json"
    p.write_text(json.dumps({"groups": [], "ignore_classes": [], "priority_classes": []}))
    rules = load(p, merge_defaults=False)
    assert rules.groups == [] and rules.actions == []


def test_a_rule_without_patterns_matches_nothing_specific():
    """A group with only a class regex still qualifies every member of that class."""
    rules = load(None)
    loose = [r for r in rules.groups if r.member is None]
    assert all(r.cls is not None or r.member is not None for r in rules.groups + loose)


def test_validate_flags_bad_regex_and_missing_class(tmp_path):
    good = tmp_path / "g.json"
    good.write_text(json.dumps({"groups": [{"id": "x", "class": "(a)", "member": "(b)"}]}))
    assert validate(good) == []
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"groups": [{"id": "x", "class": "([unclosed"}]}))
    assert any("bad regex" in p for p in validate(bad))
    missing = tmp_path / "m.json"
    missing.write_text(json.dumps({"ignore_classes": [{"label": "no regex"}]}))
    assert any("missing 'class'" in p for p in validate(missing))
    assert validate(tmp_path / "absent.json")


def test_dump_builtin_writes_valid_json(tmp_path):
    out = dump_builtin(tmp_path / "sub" / "rules.json")
    data = json.loads(out.read_text())
    assert set(data) >= {"groups", "const_returns", "bool_toggles", "limits"}
    assert validate(out) == []


def test_rule_matches_full_and_short_names():
    rules = load(None)
    rule = next(g for g in rules.groups if g.id == "economy")
    assert rule.matches("Game.Save.PlayerData", "PlayerData", "gold")
    assert not rule.matches("Game.Save.PlayerData", "PlayerData", "vertexCount")
    assert not rule.matches("UnityEngine.Transform", "Transform", "gold")


def test_every_builtin_regex_compiles_and_is_used():
    rules = load(None)
    for rule in rules.groups + rules.actions:
        assert (rule.cls is not None) or (rule.member is not None)
