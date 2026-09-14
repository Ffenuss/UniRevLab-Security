"""Rule files: the vocabulary that maps dumped symbols onto menu entries.

JSON (no extra deps). Every field is an optional regex, matched case-insensitively
against `Namespace.Name` / `Name` for classes and against `Name` for members.

    {
      "ignore_classes":   [ {"class": "^System\\."} ],
      "groups":           [ {"id": "economy", "label": "Economy", "class": "...", "member": "..."} ],
      "actions":          [ {"id": "...", "kind": "const_return", "member": "...", "value": 0} ],
      "instance_capture": {"methods": ["Update", "LateUpdate", ...]}
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BUILTIN_DEFAULTS: dict[str, Any] = {
    "ignore_classes": [
        {"class": r"^System\.|^Mono\.|^Microsoft\.|^Unity\."},
        {"class": r"^UnityEngine(\..*)?\.|^UnityEngine"},
        {"class": r"^(Cysharp|Google|Newtonsoft|LiteNetLib|GooglePlayGames|UnityEngine)"},
        {"class": r"(Attribute|Exception|EventArgs|__Gen|<PrivateImplementation|Editor|Test|Tests)$"},
        {"class": r"\.(UI|Editor|Debug|Internal)\."},
    ],
    "priority_classes": [
        {"class": r"(player|hero|character|save|profile|game(?:play)?|run|stats?|data|inventory|"
                  r"wallet|shop|economy|difficulty|weapon|enemy)"},
    ],
    "groups": [
        {"id": "economy", "label": "Economy",
         "class": r"(player|save|game|data|wallet|profile|economy|inventory|shop|run|stat)",
         "member": r"(^|_)(gold|coins?|money|cash|credits?|gems?|diamonds?|crystals?|tickets?|"
                    r"points?|score|xp|exp|currency|balance|keys?|wood|stone|food|oil)(_|$)"},
        {"id": "survival", "label": "Survival",
         "class": r"(player|hero|character|health|life|status)",
         "member": r"(^|_)(hp|health|lives?|hps?|maxhealth|energy|stamina|hunger|thirst|shield|armour|armor)"},
        {"id": "movement", "label": "Movement",
         "class": r"(player|controller|character|movement|vehicle|body)",
         "member": r"(movespeed|walkspeed|runs?speed|speed|jumps?|maxjumps?|sprint|flyspeed)"},
        {"id": "progress", "label": "Progress",
         "class": r"(progress|level|quest|story|save|unlocks?|achievement)",
         "member": r"(level|wave|stage|chapter|floor|depth|score|multiplier)"},
    ],
    "bool_toggles": [
        {"id": "god_mode", "label": "God Mode", "group": "Survival",
         "class": r"(player|hero|character|game)",
         "member": r"(god|invincib|immortal|indestruct|noDamage|unkillable|deathless)"},
        {"id": "infinite_energy", "label": "Infinite Energy", "group": "Survival",
         "class": r"(player|stat|energy|stamina|mana)",
         "member": r"(infinite|unlimited|noCost|noCooldown)"},
        {"id": "unlock_all", "label": "Unlock Everything", "group": "Progress",
         "class": r"(unlock|shop|save|profile|collection|progress)",
         "member": r"(unlockall|allunlocked|fullunlock|unlocked)"},
        {"id": "one_hit_kill", "label": "One Hit Kill", "group": "Combat",
         "class": r"(player|weapon|combat|attack|bullet|damage)",
         "member": r"(onehit|instakill|ohk|oneshot)"},
        {"id": "no_recoil", "label": "No Recoil", "group": "Aim",
         "class": r"(weapon|gun|shoot|recoil|aim)",
         "member": r"(recoil|spread|sway|kick)"},
    ],
    "const_returns": [
        {"id": "no_damage", "label": "Ignore Damage", "group": "Survival", "value": 0,
         "class": r"(player|hero|character|health|body)",
         "member": r"^(TakeDamage|ApplyDamage|Damage|Hurt|OnHit|OnDamageReceived|ReceiveDamage)$"},
        {"id": "damage_scale", "label": "Damage x10", "group": "Combat", "value": 10,
         "class": r"(player|weapon|combat|attack|stat)",
         "member": r"^(GetDamage|CalculateDamage|ComputeDamage|get_Damage)$"},
        {"id": "no_cooldown", "label": "No Cooldown", "group": "Combat", "value": 0,
         "class": r"(skill|ability|weapon|cooldown|player)",
         "member": r"^(GetCooldown|get_Cooldown|Cooldown|GetCooldownTime|RemainingCooldown)$"},
        {"id": "infinite_ammo", "label": "Infinite Ammo", "group": "Combat", "value": 999,
         "class": r"(weapon|ammo|magazine|gun|inventory|player)",
         "member": r"^(get_Ammo|get_Magazine|GetAmmoCount|get_CurrentAmmo|get_Bullets)$"},
    ],
    "hook_patches": [
        {"id": "log_spawn", "label": "Log Enemy Spawns", "group": "Debug",
         "class": r"(enemy|spawn|wave|director)", "member": r"^(Spawn|OnSpawn|InstantiateEnemy)$",
         "patch_out": True},
    ],
    "instance_capture": {
        "methods": ["Update", "LateUpdate", "FixedUpdate", "OnEnable", "Awake", "Start", "Tick"],
        "prefer_named": r"(player|hero|character|weapon|game|director)",
    },
    "limits": {"max_features": 48, "min_confidence": 0.34},
}


@dataclass(slots=True)
class Rule:
    id: str
    label: str
    group: str
    kind: str
    cls: re.Pattern | None = None
    member: re.Pattern | None = None
    value: float | int | bool = 1
    extra: dict = field(default_factory=dict)

    def matches(self, class_name: str, short_name: str, member: str) -> bool:
        if self.cls and not (self.cls.search(class_name) or self.cls.search(short_name)):
            return False
        if self.member and not self.member.search(member):
            return False
        return True


@dataclass(slots=True)
class RuleSet:
    ignore: list[re.Pattern]
    priority: list[re.Pattern]
    groups: list[Rule]
    actions: list[Rule]
    instance_capture: dict
    limits: dict
    source: str = "builtin"

    def is_ignored(self, full_name: str) -> bool:
        return any(p.search(full_name) for p in self.ignore)

    def priority_score(self, full_name: str) -> float:
        return 0.25 if any(p.search(full_name) for p in self.priority) else 0.0

    def should_ignore(self, full_name: str) -> bool:
        return self.is_ignored(full_name)


def _compile(spec: dict) -> tuple[re.Pattern | None, re.Pattern | None]:
    c = spec.get("class")
    m = spec.get("member")
    return (re.compile(c, re.I) if c else None, re.compile(m, re.I) if m else None)


def _rules(payload: list[dict], kind: str) -> list[Rule]:
    out: list[Rule] = []
    for i, spec in enumerate(payload or []):
        cls, mem = _compile(spec)
        rid = spec.get("id") or f"{kind}_{i}"
        out.append(Rule(id=rid, label=spec.get("label") or rid.replace("_", " ").title(),
                        group=spec.get("group", "General"), kind=kind, cls=cls, member=mem,
                        value=spec.get("value", 1), extra={k: v for k, v in spec.items()
                                                           if k not in ("id", "label", "group", "class",
                                                                      "member", "value", "kind")}))
    return out


def load(path: str | Path | None = None, *, merge_defaults: bool = True) -> RuleSet:
    data: dict[str, Any] = dict(BUILTIN_DEFAULTS)
    source = "builtin"
    if path:
        p = Path(path)
        user = json.loads(p.read_text(encoding="utf-8"))
        source = str(p)
        if merge_defaults:
            for key in ("groups", "bool_toggles", "const_returns", "hook_patches", "ignore_classes"):
                if key in user and key in data:
                    user[key] = list(user[key]) + list(data[key])
            for key in ("instance_capture", "limits"):
                if key in user:
                    user[key] = {**data[key], **user[key]}
            data = {**data, **user}
        else:
            data = user

    groups = _rules(data.get("groups", []), "value")
    toggles = _rules(data.get("bool_toggles", []), "toggle")
    consts = _rules(data.get("const_returns", []), "const_return")
    hooks = _rules(data.get("hook_patches", []), "hook")
    explicit = _rules(data.get("actions", []), "explicit")
    actions = toggles + consts + hooks + explicit

    return RuleSet(
        ignore=[re.compile(r["class"], re.I) for r in data.get("ignore_classes", []) if "class" in r],
        priority=[re.compile(r["class"], re.I) for r in data.get("priority_classes", []) if "class" in r],
        groups=groups,
        actions=actions,
        instance_capture=data.get("instance_capture", BUILTIN_DEFAULTS["instance_capture"]),
        limits=data.get("limits", BUILTIN_DEFAULTS["limits"]),
        source=source,
    )


def dump_builtin(path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(BUILTIN_DEFAULTS, indent=2), encoding="utf-8")
    return p


def validate(path: str | Path) -> list[str]:
    """Lint a rule file: returns a list of problems (empty == OK)."""
    problems: list[str] = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"unreadable: {exc}"]
    for key, value in data.items():
        if key.endswith("_classes") or key == "priority_classes":
            for i, spec in enumerate(value or []):
                if "class" not in spec:
                    problems.append(f"{key}[{i}]: missing 'class' regex")
                else:
                    try:
                        re.compile(spec["class"])
                    except re.error as exc:
                        problems.append(f"{key}[{i}]: bad regex {exc}")
        elif isinstance(value, list):
            for i, spec in enumerate(value):
                for fld in ("class", "member"):
                    if (rx := spec.get(fld)):
                        try:
                            re.compile(rx)
                        except re.error as exc:
                            problems.append(f"{key}[{i}].{fld}: bad regex {exc}")
    return problems
