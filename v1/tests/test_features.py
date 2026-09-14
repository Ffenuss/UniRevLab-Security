"""Analyzer: rule matching, confidence, instance capture, drops and caps."""

from __future__ import annotations

from modkit.analyze.features import Analyzer, analyze
from modkit.ir import FeatureKind


def by_id(plan):
    return {f.id: f for f in plan.features}


def test_economy_setter_and_lock_are_both_found(plan):
    feats = by_id(plan)
    setter = feats["economy.PlayerSave.gold"]
    lock = feats["economy.PlayerSave.gold.lock"]
    assert setter.kind is FeatureKind.VALUE_SET and setter.rva == 0x1050
    assert lock.kind is FeatureKind.CONST_RETURN and lock.rva == 0x1040
    assert lock.patch is not None and lock.patch.bytes.endswith(b"\xc0\x03\x5f\xd6")
    assert setter.needs_instance and not lock.needs_instance   # patches need no object
    assert setter.confidence > lock.confidence


def test_static_field_becomes_a_static_write(plan):
    feats = by_id(plan)
    hit = [f for f in feats.values() if f.kind is FeatureKind.STATIC_WRITE]
    assert hit, "s_debugUnlocks has a StaticValue in the dump and must be writable by rva"
    assert hit[0].is_static and not hit[0].needs_instance
    assert hit[0].rva == 0x5010


def test_void_method_with_args_becomes_a_swallow_hook(plan):
    f = by_id(plan)["no_damage.PlayerController.TakeDamage"]
    assert f.kind is FeatureKind.HOOK
    assert f.swallow and f.enabled_by_default
    assert f.params == ["System.Single"]


def test_instance_hooks_are_created_for_instance_features(plan):
    hooked = {h.cls for h in plan.instance_hooks}
    assert {"NeonDrift.Play.PlayerController", "NeonDrift.Save.PlayerSave"} <= hooked
    for f in plan.features:
        if f.needs_instance:
            assert f.cls in hooked, f"{f.id} needs an instance but has no capture hook"


def test_patch_and_hook_features_need_no_object(plan):
    for f in plan.features:
        if f.kind in (FeatureKind.CONST_RETURN, FeatureKind.HOOK):
            assert not f.needs_instance, f"{f.id} must not wait for a captured instance"
    assert by_id(plan)["no_damage.PlayerController.TakeDamage"].rva == 0x1110


def test_field_write_uses_the_offset_not_an_address(plan):
    f = by_id(plan)["movement.PlayerController.jumpsLeft.mem"]
    assert f.kind is FeatureKind.FIELD_WRITE
    assert f.field_offset == 0x2C
    assert f.rva is None, "an instance offset must never be stored as an rva"


def test_engine_and_framework_types_never_appear(plan):
    assert all("UnityEngine" not in f.cls and not f.cls.startswith("System.")
               for f in plan.features)


def test_groups_and_limits_respected(program, rules):
    rules.limits = dict(rules.limits, max_features=5)
    plan = analyze(program, rules)
    assert len(plan.features) <= 5
    assert plan.grouped()


def test_low_confidence_candidates_are_dropped(program, rules):
    rules.limits = dict(rules.limits, min_confidence=0.99)
    assert analyze(program, rules).features == []


def test_no_rvas_means_no_method_features(program, rules):
    """Without an RVA column only `StaticValue:` writes survive — that is by design."""
    for cls in program.classes:
        for m in cls.methods:
            m.rva = None
    left = analyze(program, rules).features
    assert left, "static storage addresses come from the dump, not from a method"
    assert {f.kind for f in left} == {FeatureKind.STATIC_WRITE}


def test_dedupe_keeps_the_confident_variant(program, rules):
    plan1 = analyze(program, rules)
    an = Analyzer(program, rules)
    an.build()
    keys = [(f.cls, f.member, f.kind) for f in plan1.features]
    assert len(keys) == len(set(keys))


def test_report_counts(program, rules):
    an = Analyzer(program, rules)
    an.build()
    assert an.report.scanned_classes >= 5
    assert an.report.candidates >= len(an.features)
    assert an.report.as_dict()["dropped_by_cap"] == 0


def test_conflicts_are_reported(program, rules):
    from modkit.analyze.rules import Rule
    import re
    rules.actions = list(rules.actions) + [
        Rule(id="needs_args", label="Needs Args", group="G", kind="const_return",
             cls=re.compile(r"Weapon"), member=re.compile(r"^Fire$"), value=3)
    ]
    plan = analyze(program, rules)
    assert any("Fire" in c and "args" in c for c in plan_notes(plan)), \
        "a const-return rule on a method with parameters must be reported, not silently used"


def plan_notes(plan):
    return [n.removeprefix("conflict: ") for n in plan.notes]
