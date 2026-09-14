"""Turns a dumped `Program` + `RuleSet` into a concrete, buildable menu plan."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from modkit.arch import arm64
from modkit.ir import (ClassDef, Feature, FeatureKind, InstanceHook, Method, Patch, Plan,
                       Program, TypeKind, c_ident)
from modkit.analyze.rules import Rule, RuleSet

SETTER_HINTS = ("set_{0}", "Set{0}", "{0}Set", "Change{0}", "Add{0}", "Give{0}", "Set{0}Value")
GETTER_HINTS = ("get_{0}", "Get{0}", "{0}Get")
NUMERIC = re.compile(r"^(System\.)?(Int32|UInt32|Int64|UInt64|Single|Double|Int16|UInt16|Byte|SByte)$", re.I)
ACCESSOR_NAME = re.compile(r"^((?:get|set)_[A-Za-z0-9_]+)$")


@dataclass(slots=True)
class Report:
    scanned_classes: int = 0
    scanned_methods: int = 0
    candidates: int = 0
    dropped_low_confidence: int = 0
    dropped_by_cap: int = 0
    conflicts: list[str] | None = None

    def __post_init__(self) -> None:
        self.conflicts = self.conflicts or []

    def as_dict(self) -> dict:
        return {"scanned_classes": self.scanned_classes, "scanned_methods": self.scanned_methods,
                "candidates": self.candidates, "dropped_low_confidence": self.dropped_low_confidence,
                "dropped_by_cap": self.dropped_by_cap, "conflicts": self.conflicts[:20]}


class Analyzer:
    """Rule engine. Deliberately conservative: an unverifiable candidate is worse than none."""

    def __init__(self, program: Program, rules: RuleSet, *, arch: str = "arm64",
                 page_size: int = 0x10000):
        self.program = program
        self.rules = rules
        self.arch = arch
        self.page = page_size
        self.report = Report()
        self.features: list[Feature] = []
        self.instance_hooks: dict[str, InstanceHook] = {}
        self._by_class: dict[str, ClassDef] = {c.full_name: c for c in program.classes}

    # ------------------------------------------------------------------ entry

    def build(self) -> Plan:
        for cls in self.program.user_classes():
            if self.rules.is_ignored(cls.full_name):
                continue
            self.report.scanned_classes += 1
            self.report.scanned_methods += len(cls.methods)
            self._value_features(cls)
            self._rule_features(cls)
        self._dedupe()
        self._finalize()
        plan = Plan(program=self.program, features=self.features,
                    instance_hooks=list(self.instance_hooks.values()))
        plan.notes.append(f"rules: {self.rules.source}")
        plan.notes.append(f"arch: {self.arch}, page: 0x{self.page:x}")
        if self.report.conflicts:
            plan.notes.extend(f"conflict: {c}" for c in self.report.conflicts[:12])
        return plan

    # ------------------------------------------------------------------ numeric members

    def _value_features(self, cls: ClassDef) -> None:
        for f in cls.fields:
            if f.is_literal:
                continue
            rule = self._match_rule(self.rules.groups, cls, f.name)
            if rule is None:
                continue
            setter = self._accessor(cls, f.name, SETTER_HINTS, want_arg=True)
            getter = self._accessor(cls, f.name, GETTER_HINTS, want_arg=False)
            group = rule.label
            base_conf = 0.5 + self.rules.priority_score(cls.full_name)

            lo, hi = self._range_for(f)
            if setter is not None:
                conf = base_conf + 0.2
                self._add(Feature(
                    id=f"{rule.id}.{cls.c_slug}.{f.name}",
                    label=f"{f.name.replace('_', ' ').title()} → set",
                    group=group, kind=FeatureKind.VALUE_SET, cls=cls.full_name,
                    member=setter.name, c_type=setter.return_type, arg_type=f.type,
                    value=self._default_set_value(f), rva=setter.rva, min_value=lo,
                    max_value=hi, is_static=setter.is_static, needs_instance=not setter.is_static,
                    confidence=min(conf, 0.95),
                    notes=[f"setter {setter.signature()}"],
                ), setter)
            if getter is not None and NUMERIC.match(f.type or "") and not f.type.endswith("Boolean"):
                conf = base_conf + 0.15
                self._add(Feature(
                    id=f"{rule.id}.{cls.c_slug}.{f.name}.lock",
                    label=f"{f.name.replace('_', ' ').title()} lock",
                    group=group, kind=FeatureKind.CONST_RETURN, cls=cls.full_name,
                    member=getter.name, c_type=getter.return_type, value=self._default_lock_value(f),
                    rva=getter.rva, is_static=getter.is_static, min_value=lo,
                    max_value=max(hi, 1000.0), confidence=min(conf, 0.92),
                    notes=["prologue patched to return the constant; UI slider writes it live"],
                ), getter)
            if setter is None and getter is None:
                self._direct_field_feature(cls, f, rule, base_conf)

    def _direct_field_feature(self, cls: ClassDef, f, rule: Rule, base_conf: float) -> None:
        lo, hi = self._range_for(f)
        if f.is_static and f.static_value:
            kind, addr = FeatureKind.STATIC_WRITE, f.static_value
            note = "static storage, written by absolute rva — no instance needed"
        elif f.offset is not None and cls.kind is not TypeKind.ENUM:
            kind, addr = FeatureKind.FIELD_WRITE, None      # an instance offset is not an address
            note = f"instance field at +0x{f.offset:x}, needs captured `this`"
        else:
            return
        self._add(Feature(
            id=f"{rule.id}.{cls.c_slug}.{f.name}.mem",
            label=f"{f.name.replace('_', ' ').title()} → write",
            group=rule.label, kind=kind, cls=cls.full_name, member=f.name, c_type=f.type,
            arg_type=f.type, value=self._default_set_value(f), rva=addr, field_offset=f.offset,
            is_static=f.is_static, needs_instance=not f.is_static, min_value=lo, max_value=hi,
            confidence=min(base_conf + 0.05, 0.8), notes=[note],
        ), None)

    # ------------------------------------------------------------------ explicit rules

    def _rule_features(self, cls: ClassDef) -> None:
        for rule in self.rules.actions:
            if rule.kind == "value":
                continue
            matched = False
            for m in cls.methods:
                if not rule.matches(cls.full_name, cls.name, m.name):
                    continue
                matched = True
                self._method_feature(cls, m, rule)
            if matched:
                continue
            for f in cls.fields:
                if rule.matches(cls.full_name, cls.name, f.name):
                    self._field_feature(cls, f, rule)

    def _method_feature(self, cls: ClassDef, m: Method, rule: Rule) -> None:
        booly = m.return_type in ("System.Boolean", "bool")
        if rule.kind == "const_return" and m.return_type == "System.Void" and m.addressable:
            # no value to force, but "call does nothing" is exactly the effect wanted
            # (TakeDamage, Spend, Load, ...) -> an early-return hook instead of a patch
            if not m.is_generic:
                self._add(Feature(
                    id=f"{rule.id}.{cls.c_slug}.{m.name}", label=rule.label, group=rule.group,
                    kind=FeatureKind.HOOK, cls=cls.full_name, member=m.name, c_type="System.Void",
                    value=True, rva=m.rva, is_static=m.is_static, enabled_by_default=True,
                    confidence=0.8, notes=["early-return hook: body never runs while on"],
                ), m)
                self._mark_swallow(self.features[-1])
            return
        if rule.kind == "const_return":
            if not m.addressable:
                return
            if len(m.params) > 0 or m.is_generic:
                self.report.conflicts.append(f"{cls.full_name}.{m.name}: skipped, args/generics")
                return
            patch = self._const_patch(m.rva or 0, int(rule.value), m.return_type)
            self._add(Feature(
                id=f"{rule.id}.{cls.c_slug}.{m.name}", label=rule.label, group=rule.group,
                kind=FeatureKind.CONST_RETURN, cls=cls.full_name, member=m.name, c_type=m.return_type,
                value=rule.value, rva=m.rva, is_static=m.is_static,
                min_value=0, max_value=1e9, patch=patch,
                confidence=0.82 if booly else 0.74,
                notes=[f"{m.name} → return {rule.value}"],
            ), m)
        elif rule.kind == "toggle":
            if booly and m.addressable and not m.params:
                self._add(Feature(
                    id=f"{rule.id}.{cls.c_slug}.{m.name}", label=rule.label, group=rule.group,
                    kind=FeatureKind.CONST_RETURN, cls=cls.full_name, member=m.name,
                    c_type="System.Boolean", value=True, rva=m.rva, is_static=m.is_static,
                    patch=self._const_patch(m.rva or 0, 1, "System.Boolean"),
                    confidence=0.8, notes=[f"force {m.name}() == true"],
                ), m)
                return
            voidy = m.return_type == "System.Void"
            if rule.kind == "toggle" and voidy and m.addressable and len(m.params) == 1 \
                    and m.params[0].type in ("System.Boolean", "bool"):
                if not (ACCESSOR_NAME.match(m.name) or re.search(r"(set|Set)", m.name)):
                    return
                self._add(Feature(
                    id=f"{rule.id}.{cls.c_slug}.{m.name}", label=rule.label, group=rule.group,
                    kind=FeatureKind.TOGGLE, cls=cls.full_name, member=m.name, c_type="System.Void",
                    arg_type="System.Boolean", value=True, rva=m.rva, is_static=m.is_static,
                    needs_instance=not m.is_static, confidence=0.72,
                    notes=[f"call {m.name}(state) on toggle"],
                ), m)
        elif rule.kind == "hook":
            if not m.addressable:
                return
            if not m.is_static and not cls.is_mono and not rule.extra.get("allow_instance"):
                self.report.conflicts.append(
                    f"{cls.full_name}.{m.name}: instance hook, needs a captured this — enable allow_instance")
                return
            self._add(Feature(
                id=f"{rule.id}.{cls.c_slug}.{m.name}", label=rule.label, group=rule.group,
                kind=FeatureKind.HOOK, cls=cls.full_name, member=m.name, c_type=m.return_type,
                rva=m.rva, is_static=m.is_static, enabled_by_default=bool(rule.extra.get("enabled")),
                confidence=0.66, notes=[f"native callback on {m.name}(argc={len(m.params)})"
                                        f"{' , patch-out allowed' if rule.extra.get('patch_out') else ''}"],
            ), m)
        elif rule.kind == "explicit":
            kind = FeatureKind(rule.extra.get("kind", "action"))
            if kind is FeatureKind.ACTION and len(m.params) == 1 and m.return_type == "System.Void":
                kind = FeatureKind.VALUE_SET
            self._add(Feature(
                id=rule.id, label=rule.label, group=rule.group, kind=kind, cls=cls.full_name,
                member=m.name, c_type=m.return_type, value=rule.value, rva=m.rva,
                is_static=m.is_static, needs_instance=not m.is_static, confidence=0.9,
                notes=[m.signature()],
            ), m)

    def _field_feature(self, cls: ClassDef, f, rule: Rule) -> None:
        if not f.is_bool and rule.kind == "toggle":
            return
        setter = self._accessor(cls, f.name, SETTER_HINTS, want_arg=True)
        if setter is not None:
            self._add(Feature(
                id=f"{rule.id}.{cls.c_slug}.{f.name}", label=rule.label, group=rule.group,
                kind=FeatureKind.TOGGLE, cls=cls.full_name, member=setter.name, c_type="System.Void",
                arg_type="System.Boolean", value=True, rva=setter.rva, is_static=setter.is_static,
                needs_instance=not setter.is_static, confidence=0.75,
                notes=[f"set {f.name} via {setter.name}"],
            ), setter)
        elif f.is_static and f.static_value is not None:
            self._add(Feature(
                id=f"{rule.id}.{cls.c_slug}.{f.name}", label=rule.label, group=rule.group,
                kind=FeatureKind.STATIC_WRITE, cls=cls.full_name, member=f.name, c_type=f.type,
                arg_type=f.type, value=1, rva=f.static_value, field_offset=f.static_value,
                is_static=True, confidence=0.7, notes=["static bool flipped directly"],
            ), None)
        elif f.offset is not None:
            self._add(Feature(
                id=f"{rule.id}.{cls.c_slug}.{f.name}", label=rule.label, group=rule.group,
                kind=FeatureKind.FIELD_WRITE, cls=cls.full_name, member=f.name, c_type=f.type,
                arg_type=f.type, value=1, rva=None, field_offset=f.offset,
                needs_instance=True, confidence=0.62,
                notes=[f"byte-level write at this+0x{f.offset:x}"],
            ), None)

    # ------------------------------------------------------------------ helpers

    def _accessor(self, cls: ClassDef, field_name: str, hints: tuple[str, ...], *,
                  want_arg: bool) -> Method | None:
        root = re.sub(r"^[_kK]", "", field_name)
        cands = []
        for hint in hints:
            for name in {hint.format(root), hint.format(field_name),
                         hint.format(root[:1].upper() + root[1:])}:
                if (m := cls.get_method(name)) and m.addressable:
                    ok = (len(m.params) == 1) if want_arg else (len(m.params) == 0)
                    if ok:
                        cands.append(m)
        for m in cls.methods:
            if want_arg and m.name.lower().startswith("add") and len(m.params) == 1 and m.addressable:
                if root.lower() in m.name.lower():
                    cands.append(m)
        return cands[0] if cands else None

    def _match_rule(self, rules: Iterable[Rule], cls: ClassDef, member: str) -> Rule | None:
        for rule in rules:
            if rule.matches(cls.full_name, cls.name, member):
                return rule
        return None

    def _const_patch(self, rva: int, value: int, return_type: str) -> Patch:
        width = 8 if return_type in ("System.Int64", "System.UInt64", "System.Double") else 4
        code = arm64.const_return(int(value), width=width)
        return Patch(rva=rva, bytes=code, restore=b"\x00" * len(code),
                     note=f"return {value} ({return_type})")

    @staticmethod
    def _range_for(f) -> tuple[float, float]:
        """Drag-widget bounds; floats get a negative floor, bools stay 0..1."""
        if f.type in ("System.Boolean", "bool"):
            return 0.0, 1.0
        if f.type in ("System.Single", "float", "System.Double", "double"):
            return -1000.0, 1000.0
        if f.type in ("System.Byte", "System.SByte", "System.Int16", "System.UInt16"):
            return 0.0, 65535.0
        return 0.0, 1e9

    @staticmethod
    def _default_set_value(f) -> float:
        if f.type in ("System.Single", "float", "System.Double", "double"):
            return 10.0
        if f.type in ("System.Boolean", "bool"):
            return 1
        return 999999

    @staticmethod
    def _default_lock_value(f) -> float:
        if f.type in ("System.Single", "float"):
            return 999.0
        return 999999999 if f.type in ("System.Int32", "System.UInt32", "int") else 999999

    def _capture_instance(self, cls: ClassDef) -> InstanceHook | None:
        if cls.full_name in self.instance_hooks:
            return self.instance_hooks[cls.full_name]
        preferred = self.rules.instance_capture.get("methods", ["Update"])
        best: Method | None = None
        for name in preferred:
            if (m := cls.get_method(name)) and m.addressable and not m.is_static:
                best = m
                break
        if best is None:
            # any instance method works as a capture point; prefer ones that definitely run
            plain = [m for m in cls.methods if m.addressable and not m.is_static
                     and not m.is_prop_accessor and m.return_type == "System.Void"]
            getters = [m for m in cls.methods if m.addressable and not m.is_static
                       and m.is_prop_accessor and m.name.startswith("get_")]
            setters = [m for m in cls.methods if m.addressable and not m.is_static
                       and m.is_prop_accessor and m.name.startswith("set_")]
            for pool in (plain, getters, setters):
                if pool:
                    best = pool[0]
                    break
        if best is None:
            return None
        hook = InstanceHook(cls=cls.full_name, method=best.name, rva=best.rva or 0,
                            slot_name=f"inst_{c_ident(cls.name)}")
        self.instance_hooks[cls.full_name] = hook
        return hook

    def _mark_swallow(self, feat: Feature) -> None:
        feat.notes.append("swallow")

    def _add(self, feat: Feature, method: Method | None) -> None:
        self.report.candidates += 1
        if method is not None:
            feat.params = [p.type for p in method.params]
        if (method is not None and not method.is_static and not method.is_abstract
                and feat.kind not in (FeatureKind.CONST_RETURN, FeatureKind.HOOK)):
            # resolved to an instance-capture trampoline at codegen time
            feat.needs_instance = True
        if feat.kind in (FeatureKind.CONST_RETURN, FeatureKind.HOOK):
            # a patch site or a callback needs an address, not a live object: `this`
            # arrives in x0 when the hook runs
            feat.needs_instance = False
        self.features.append(feat)

    def _dedupe(self) -> None:
        seen: dict[str, Feature] = {}
        for f in self.features:
            key = f"{f.kind.value}:{f.cls}:{f.member}:{f.rva}"
            prev = seen.get(key)
            if prev is None or f.confidence > prev.confidence:
                seen[key] = f
        self.features = list(seen.values())

    def _finalize(self) -> None:
        min_conf = float(self.rules.limits.get("min_confidence", 0.0))
        cap = int(self.rules.limits.get("max_features", 48))
        keep: list[Feature] = []
        for f in sorted(self.features, key=lambda x: (-x.confidence, x.group, x.id)):
            if f.confidence < min_conf:
                self.report.dropped_low_confidence += 1
                continue
            keep.append(f)
        if len(keep) > cap:
            self.report.dropped_by_cap = len(keep) - cap
            keep = keep[:cap]
        self.features = sorted(keep, key=lambda x: (x.group.lower(), x.id))

        # resolve instance needs -> shared capture hooks, drop what we cannot resolve
        resolved: list[Feature] = []
        for f in self.features:
            if f.needs_instance:
                cls = self._by_class.get(f.cls)
                hook = self._capture_instance(cls) if cls else None
                if hook is None:
                    if f.kind in (FeatureKind.FIELD_WRITE, FeatureKind.TOGGLE,
                                  FeatureKind.VALUE_SET, FeatureKind.SLIDER, FeatureKind.ACTION):
                        self.report.dropped_low_confidence += 1
                        f.notes.append(f"dropped: no method of {f.cls} to hook for `this`")
                        continue
                    f.notes.append("no capture hook needed")
                else:
                    f.notes.append(f"instance from hook {hook.cls}.{hook.method} (+0x{hook.rva:x})")
            if f.kind is FeatureKind.CONST_RETURN and f.rva and f.patch is None:
                f.patch = self._const_patch(f.rva, int(f.value), f.c_type)
            if f.patch and f.rva:
                f.notes.append(f"patch site 0x{f.rva:x} ({len(f.patch.bytes)} bytes)")
            resolved.append(f)
        self.features = resolved


def analyze(program: Program, rules: RuleSet, **kw) -> Plan:
    return Analyzer(program, rules, **kw).build()
