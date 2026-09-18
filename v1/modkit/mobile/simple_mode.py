"""Human-oriented catalogue for ModKit Simple Mode.

All static findings remain available, but default UI priority favors app-owned and
high-signal evidence. Automatic building remains fail-closed: only an existing
validated local MenuSpec binding is selectable for build.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-simple-mode-1.3"

_FRAMEWORK_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "org.jetbrains.",
    "com.google.", "com.android.", "okhttp3.", "retrofit2.", "org.chromium.",
)
_SDK_PREFIXES = (
    "com.facebook.", "com.tiktok.", "com.linecorp.", "com.adjust.", "com.appsflyer.",
    "com.google.android.gms.", "com.google.firebase.", "com.revenuecat.", "com.stripe.",
    "com.paypal.", "com.squareup.", "io.sentry.", "com.braze.", "com.onesignal.",
)
_GAMEPLAY_WORDS = (
    "health", "hp", "damage", "dmg", "attack", "speed", "timescale", "cooldown", "cd",
    "currency", "gold", "coin", "gem", "diamond", "wallet", "level", "experience", "xp",
    "inventory", "mana", "energy", "stamina", "camera", "fov", "weather", "quest",
)


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:20]


def _str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return str(v)
    return str(v)


def _first(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _class_hint(row: dict, title: str = "") -> str:
    cls = _first(row, "class", "className", "class_name", "owner")
    if cls:
        return cls
    if "::" in title:
        return title.split("::", 1)[0]
    return title


def _ownership(row: dict, title: str = "", source: str = "") -> str:
    explicit = _first(row, "ownershipKind")
    if explicit:
        return explicit.upper().replace("-", "_")
    role = _first(row, "evidenceRole")
    cls = _class_hint(row, title).casefold()
    if cls.startswith(_FRAMEWORK_PREFIXES) or role == "framework/third-party":
        return "FRAMEWORK"
    if ".sdk." in cls or cls.startswith(_SDK_PREFIXES):
        return "BUNDLED_SDK"
    if source == "SecuritySurface":
        return "SECURITY"
    if source == "EngineDetection":
        return "ENGINE"
    if source in {"Gameplay", "Analysis", "DeepResolver", "RE", "MenuSpec"}:
        return "APP_OR_GAME"
    return "UNKNOWN"


def _contains_server(row: dict) -> bool:
    """Classify explicit server/trust findings without treating every economy word as remote.

    Currency/reward/gameplay labels are not automatically server-side. They become audit
    findings only when the evidence says server/backend/remote or when the finding is an
    authentication/payment/network/key surface.
    """
    trust = " ".join(_str(row.get(k)) for k in (
        "trustBoundary", "authority", "serverAuthority", "remoteAuthority", "localAuthority",
    )).casefold()
    if any(x in trust for x in ("server", "backend", "remote", "platform-backed")):
        return True
    if "local" in trust and not any(x in trust for x in ("not-confirmed", "unknown")):
        return False
    joined = " ".join(_str(row.get(k)) for k in (
        "domain", "category", "title", "description", "note", "kind", "surface",
    )).casefold()
    return any(x in joined for x in (
        "server", "backend", "api endpoint", "host:port", "websocket", "network stack",
        "authentication", "session", "oauth", "access token", "refresh token", "credential",
        "billing", "purchase", "payment", "entitlement", "subscription", "license",
        "crypto / key", "key storage", "tls certificate", "certificate pin",
    ))


def _describe(title: str, row: dict, category: str = "", ownership: str = "") -> str:
    explicit = _first(row, "description", "explanation", "note", "summary", "reason", "detail")
    if explicit:
        text = explicit[:1200]
    else:
        low = (title + " " + category).casefold()
        mapping = [
            (("health", "hp", "god", "immortal"), "Локальное здоровье/получение урона; точность зависит от подтверждённой точки исполнения."),
            (("damage", "dmg", "attack"), "Расчёт или множитель урона; проверьте конкретный method/field locator."),
            (("speed", "timescale", "time scale"), "Локальная скорость времени/симуляции."),
            (("cooldown", "cd"), "Таймер или коэффициент перезарядки."),
            (("camera", "fov", "zoom"), "Параметры камеры/угла обзора."),
            (("currency", "diamond", "gold", "coin", "gem", "wallet"), "Экономическая/валютная поверхность. Серверный trust определяется отдельно по evidence."),
            (("premium", "entitlement", "purchase", "billing"), "Граница доверия покупки/доступа; показывается для аудита, серверный обход не генерируется."),
            (("session", "auth", "token", "login"), "Поверхность аутентификации/сессии для defensive trust-аудита."),
            (("crypto", "key", "cipher", "encrypt"), "Криптографическая/key-handling поверхность. Статическая находка не означает утечку секретного ключа."),
            (("endpoint", "websocket", "grpc", "retrofit", "okhttp"), "Сетевая/API поверхность, найденная пассивным статическим сканированием."),
        ]
        text = "Статическая/структурная находка ModKit. Откройте доказательства для источника и степени подтверждения."
        for needles, value in mapping:
            if any(n in low for n in needles):
                text = value
                break
    if ownership == "FRAMEWORK":
        return "Фреймворк/системная библиотека, низкий приоритет. " + text
    if ownership == "BUNDLED_SDK":
        return "Bundled SDK/третья сторона. Отделяйте её от собственной игровой логики. " + text
    return text


def _card_id(source: str, title: str, row: dict) -> str:
    stable = _first(row, "id", "finding_id", "findingId", "metadataMethodId", "methodId", "rva")
    return f"{source}:{stable or _sha256_text(title + _str(row))}"


def _actionable_locator(row: dict, source: str, status_raw: str, title: str) -> tuple[str | None, dict | None]:
    if status_raw.upper() not in {
        "CONFIRMED", "VERIFIED", "READY", "PATCHABLE", "PACKAGE_OBSERVED",
        "FIELD_OBSERVED", "FOUND_STATIC", "SCRIPT_CONTENT_SEARCH",
    }:
        return None, None
    ownership = _ownership(row, title, source)
    if ownership in {"FRAMEWORK", "BUNDLED_SDK"}:
        return None, None
    rva = row.get("rva")
    if rva is not None:
        return "READY_NATIVE", {"rva": rva, "abi": row.get("abi"), "library": row.get("library") or row.get("module")}
    artifact = _first(row, "artifact", "dex", "sourceArtifact")
    clazz = _first(row, "class", "className", "class_name", "owner")
    method = _first(row, "method", "methodName", "method_name")
    signature = _first(row, "signature", "descriptor", "methodSignature")
    code_offset = row.get("codeOffset")
    dex_evidence = ".dex" in artifact.casefold() or "dex" in source.casefold()
    if dex_evidence and code_offset is not None and (clazz or "::" in title):
        if not clazz and "::" in title:
            clazz = title.split("::", 1)[0]
        if not method and "::" in title:
            method = title.split("::", 1)[1].split("(", 1)[0]
        return "READY_DEX", {"artifact": artifact, "class": clazz, "method": method, "signature": signature or title, "codeOffset": code_offset}
    entry = _first(row, "entry", "path", "file", "apkEntry", "asset")
    fn = _first(row, "function", "functionName", "symbol")
    elow = entry.casefold()
    if entry and elow.endswith((".lua", ".luac", ".luae", ".js", ".jsc")) and fn:
        return "READY_SCRIPT", {"entry": entry, "symbol": fn, "line": row.get("line") or row.get("lineNumber")}
    if entry and (elow.startswith("res/") or elow.startswith("assets/")) and row.get("offset") is not None:
        return "READY_RESOURCE", {"entry": entry, "offset": row.get("offset")}
    return None, None


_GAMEPLAY_DOMAIN_RULES = (
    ("health", ("health", "maxhealth", "max_health", "hitpoints", "hit_points", "hp", "life", "lifepoints")),
    ("damage", ("damage", "dmg", "attackdamage", "attack_damage", "attackpower", "attack_power", "defense", "armour", "armor")),
    ("speed", ("movespeed", "move_speed", "attackspeed", "attack_speed", "timescale", "time_scale", "speed")),
    ("cooldown", ("cooldown", "cool_down", "skillcd", "skill_cd", "recharge", "recast")),
    ("currency", ("diamond", "diamonds", "gem", "gems", "gold", "coin", "coins", "wallet", "balance", "premiumcurrency", "premium_currency")),
    ("level_xp", ("level", "playerlevel", "player_level", "experience", "exp", "xp")),
    ("inventory", ("inventory", "itemamount", "item_amount", "itemcount", "item_count", "stackcount", "stack_count", "reward", "drop")),
    ("camera", ("camera", "fieldofview", "field_of_view", "fov", "zoom")),
    ("movement", ("movement", "position", "teleport", "gravity", "jump", "velocity")),
    ("mana_energy", ("mana", "stamina", "energy")),
)


def _semantic_blob(card: dict) -> str:
    values = [
        card.get("title"), card.get("category"), card.get("description"),
        card.get("source"), card.get("ownership"), card.get("evidence"),
    ]
    return " ".join(_str(v) for v in values).casefold()


def _gameplay_domain(card: dict) -> str:
    blob = _semantic_blob(card)
    tokens = set(re.findall(r"[a-z0-9_]+", blob))
    compact = re.sub(r"[^a-z0-9]", "", blob)
    for domain, aliases in _GAMEPLAY_DOMAIN_RULES:
        for alias in aliases:
            low = alias.casefold()
            if low in tokens or low.replace("_", "") in compact:
                return domain
    return ""


def _has_flow_evidence(evidence: object) -> bool:
    if not isinstance(evidence, dict):
        return False
    for key in ("directInvokes", "invokes", "callers", "callees", "callReferences", "references", "xref", "xrefs"):
        value = evidence.get(key)
        if isinstance(value, (list, dict)) and len(value) > 0:
            return True
    return bool(evidence.get("flowConfirmed") or evidence.get("dataFlowConfirmed"))


def _runtime_confirmed(card: dict) -> bool:
    evidence = card.get("evidence") if isinstance(card.get("evidence"), dict) else {}
    status = str(card.get("status") or "").upper()
    return (
        "RUNTIME" in status
        or bool(evidence.get("runtimeConfirmed"))
        or bool(evidence.get("runtimeObserved"))
        or str(evidence.get("confirmation") or "").casefold() == "runtime"
    )


def _verification_stage(card: dict) -> str:
    if card.get("serverAudit"):
        return "SERVER_AUDIT"
    ownership = str(card.get("ownership") or "UNKNOWN")
    if ownership == "FRAMEWORK":
        return "FRAMEWORK_NOISE"
    if ownership == "BUNDLED_SDK":
        return "SDK_NOISE"
    if card.get("buildable"):
        return "PATCH_READY"
    if _runtime_confirmed(card):
        return "RUNTIME_CONFIRMED"
    status = str(card.get("status") or "")
    if card.get("actionable") or status.startswith("READY"):
        return "LOCATOR_CONFIRMED"
    evidence = card.get("evidence")
    if _has_flow_evidence(evidence):
        return "FLOW_CONFIRMED"
    raw = status.upper()
    if ownership in {"APP", "APP_OR_GAME"} and raw in {
        "CONFIRMED", "VERIFIED", "PACKAGE_OBSERVED", "FIELD_OBSERVED", "FOUND_STATIC",
        "SCRIPT_CONTENT_SEARCH", "SCRIPT/CONTENT_SEARCH",
    }:
        return "APP_OWNED"
    return "FOUND_STATIC"


def _readiness_reason(card: dict, stage: str) -> tuple[str, str]:
    if stage == "PATCH_READY":
        return "Есть проверенный локальный executable binding; пункт разрешён для fail-closed автосборки.", ""
    if stage == "LOCATOR_CONFIRMED":
        return "Есть точный локальный locator для перехода/ручной проверки.", "Для автосборки всё ещё нужен проверенный executable binding/MenuSpec control."
    if stage == "RUNTIME_CONFIRMED":
        return "Поведение подтверждено runtime evidence.", "Нужна точная локальная patch-point привязка и preflight перед автосборкой."
    if stage == "FLOW_CONFIRMED":
        return "Связь подтверждена call/data-flow evidence.", "Нужен точный locator или runtime confirmation."
    if stage == "APP_OWNED":
        return "Находка относится к коду/данным приложения или игры.", "Пока нет достаточного flow/locator подтверждения."
    if stage == "SERVER_AUDIT":
        return "Серверная/network/trust поверхность сохранена для defensive audit.", "Автоматический server/payment/economy bypass запрещён политикой ModKit."
    if stage in {"SDK_NOISE", "FRAMEWORK_NOISE"}:
        return "", "Низкий приоритет: SDK/framework evidence не считается игровой patch-point без сильной app-owned связи."
    return "Статически найдено.", "Нужно подтвердить принадлежность приложению, flow и точный locator."


def _quality(card: dict) -> dict:
    ownership = str(card.get("ownership") or "UNKNOWN")
    status = str(card.get("status") or "")
    source = str(card.get("source") or "")
    title = str(card.get("title") or "")
    category = str(card.get("category") or "")
    priority = 30
    if card.get("buildable"):
        priority = 100
    elif status.startswith("READY"):
        priority = 92
    elif source == "SecuritySummary":
        priority = 88
    elif source == "NativeDeep" and str(card.get("category") or "").startswith("Runtime/Architecture"):
        priority = 82
    elif source == "RuntimeProfiler":
        priority = 74
    elif source == "EngineRouter":
        priority = 70
    elif source == "Deobfuscation":
        priority = 72
    elif source == "NativeInventory":
        priority = 68
    elif source == "DotNetDeep":
        priority = 75
    elif source == "UnrealDeep":
        priority = 74
    elif source == "GodotDeep":
        priority = 74
    elif source == "NativeDeep" and "IL2CPP Runtime Lookup" in str(card.get("category") or ""):
        priority = 78
    elif card.get("serverAudit") and ownership not in {"FRAMEWORK"}:
        priority = 80
    elif status in {"CONFIRMED", "VERIFIED", "FIELD_OBSERVED"} and ownership in {"APP", "APP_OR_GAME"}:
        priority = 75
    elif status == "PACKAGE_OBSERVED":
        low = (title + " " + category).casefold()
        priority = 66 if any(x in low for x in ("diamond", "gold", "coin", "gem", "currency", "health", "damage")) else 48
    if ownership == "BUNDLED_SDK":
        priority = min(priority, 42)
    if ownership == "FRAMEWORK":
        priority = min(priority, 12)
    card["priority"] = priority
    domain = _gameplay_domain(card)
    card["gameplayDomain"] = domain
    stage = _verification_stage(card)
    card["verificationStage"] = stage
    card["confirmationRank"] = {
        "FOUND_STATIC": 10, "APP_OWNED": 20, "FLOW_CONFIRMED": 30,
        "LOCATOR_CONFIRMED": 40, "RUNTIME_CONFIRMED": 50, "PATCH_READY": 60,
        "SERVER_AUDIT": 15, "SDK_NOISE": 2, "FRAMEWORK_NOISE": 1,
    }.get(stage, 0)
    ready_reason, not_ready_reason = _readiness_reason(card, stage)
    card["readyReason"] = ready_reason
    card["notReadyReason"] = not_ready_reason
    card["patchReady"] = stage == "PATCH_READY"
    evidence = card.get("evidence") if isinstance(card.get("evidence"), dict) else {}
    trust = " ".join(_str(evidence.get(k)) for k in ("trustBoundary", "authority", "localAuthority")).casefold()
    card["offlineCandidate"] = bool(
        not card.get("serverAudit") and card.get("ownership") in {"APP", "APP_OR_GAME"}
        and ("local" in trust or bool(domain))
    )
    if stage == "PATCH_READY":
        card["priority"] = max(int(card["priority"]), 110)
    elif stage == "RUNTIME_CONFIRMED":
        card["priority"] = max(int(card["priority"]), 105)
    elif stage == "LOCATOR_CONFIRMED":
        card["priority"] = max(int(card["priority"]), 96)
    elif stage == "FLOW_CONFIRMED":
        card["priority"] = max(int(card["priority"]), 84)
    elif stage == "APP_OWNED" and domain:
        card["priority"] = max(int(card["priority"]), 76)
    if stage == "SDK_NOISE":
        card["priority"] = min(int(card["priority"]), 42)
    if stage == "FRAMEWORK_NOISE":
        card["priority"] = min(int(card["priority"]), 12)
    card["lowSignal"] = int(card["priority"]) < 50
    card["important"] = int(card["priority"]) >= 60
    return card


def _menu_card(row: dict, source: str = "MenuSpec") -> dict:
    title = _first(row, "title", "label", "name", "id") or "Unnamed control"
    category = _first(row, "category", "domain") or "General"
    binding = row.get("binding")
    rva = row.get("rva")
    probe = row.get("probe_kind") or row.get("probeKind")
    executable = bool(binding) and rva is not None and not probe and str(row.get("type", "")).casefold() != "label"
    server = _contains_server(row)
    if server:
        status = "SERVER_AUDIT"; executable = False
    elif probe:
        status = "READ_ONLY_PROBE"; executable = False
    elif executable:
        status = "READY"
    else:
        status = "REVIEW"
    ownership = _ownership(row, title, source)
    return _quality({
        "id": _card_id(source, title, row), "title": title, "category": category, "source": source,
        "status": status, "buildable": executable, "selectable": executable,
        "actionable": executable, "locator": ({"rva": rva, "binding": binding} if executable else None),
        "menuControlId": _first(row, "id") or None,
        "description": _describe(title, row, category, ownership), "serverAudit": server,
        "ownership": ownership, "evidence": row,
    })


def _generic_card(row: dict, source: str, category: str = "") -> dict | None:
    title = _first(row, "title", "label", "name", "method", "methodName", "domain", "kind", "id")
    if not title:
        return None
    category = category or _first(row, "category", "domain", "type") or "General"
    server = _contains_server(row)
    menu = row.get("menuCandidate") if isinstance(row.get("menuCandidate"), dict) else None
    elig = row.get("menuEligibility") if isinstance(row.get("menuEligibility"), dict) else None
    verification = row.get("methodVerification") if isinstance(row.get("methodVerification"), dict) else {}
    auto_prepare = bool(menu and elig and elig.get("eligible") and verification.get("executableReady"))
    status_raw = _first(row, "status", "decision", "evidence_status", "evidenceStatus")
    locator_status, locator = _actionable_locator(row, source, status_raw, title)
    actionable = bool(locator_status)
    if server:
        status = "SERVER_AUDIT"; auto_prepare = False; actionable = False; locator = None
    elif auto_prepare:
        status = "READY_FOR_PREPARE"; actionable = True
    elif locator_status:
        status = locator_status
    elif status_raw:
        status = status_raw.upper().replace(" ", "_")
    else:
        status = "REVIEW"
    ownership = _ownership(row, title, source)
    return _quality({
        "id": _card_id(source, title, row), "title": title, "category": category, "source": source,
        "status": status, "buildable": False, "selectable": False, "actionable": actionable,
        "locator": locator, "menuControlId": None,
        "description": _describe(title, row, category, ownership), "serverAudit": server,
        "ownership": ownership, "evidence": row,
    })


def _iter_rows(obj: Any, wanted: set[str]) -> Iterable[tuple[str, dict]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in wanted and isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        yield key, row
            if isinstance(value, dict):
                yield from _iter_rows(value, wanted)
    elif isinstance(obj, list):
        for value in obj:
            if isinstance(value, dict):
                yield from _iter_rows(value, wanted)


def _apk_paths(workdir: Path) -> list[Path]:
    paths: list[Path] = []
    target = _json(workdir / "installed-target.json")
    if isinstance(target, dict):
        for row in target.get("splits", []) or []:
            if isinstance(row, dict):
                p = Path(str(row.get("path") or ""))
                if p.is_file() and p not in paths:
                    paths.append(p)
    installed_dir = workdir / "installed-apks"
    if installed_dir.is_dir():
        for p in sorted(installed_dir.glob("*.apk")):
            if p not in paths:
                paths.append(p)
    game = workdir / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def detect_engines(apk_paths: Iterable[str | Path]) -> dict:
    evidence: dict[str, list[str]] = {
        "unity_il2cpp": [], "unity_mono": [], "cocos2dx_cpp": [], "cocos2dx_lua": [],
        "cocos2dx_js": [], "cocos_creator": [], "lua_runtime": [], "android_dex": [], "native": [],
    }
    seen: set[str] = set()
    for raw in apk_paths:
        path = Path(raw)
        if not path.is_file():
            continue
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
        except Exception:
            continue
        low_names = [n.casefold() for n in names]
        joined_sample = " ".join(low_names[: min(len(low_names), 5000)])
        def mark(key: str, value: str) -> None:
            token = f"{key}:{value}"
            if token not in seen:
                seen.add(token); evidence[key].append(value)
        for name, low in zip(names, low_names):
            base = low.rsplit("/", 1)[-1]
            if base.startswith("classes") and base.endswith(".dex"): mark("android_dex", name)
            if low.endswith(".so"): mark("native", name)
            if base == "libil2cpp.so" or low.endswith("global-metadata.dat"): mark("unity_il2cpp", name)
            if base in {"libunity.so", "libmain.so"}: mark("unity_mono", name)
            if base in {"libcocos2dcpp.so", "libcocos.so", "libcocos2d.so"}: mark("cocos2dx_cpp", name)
            if low.endswith((".lua", ".luac", ".luae")) or "liblua" in base or "xlua" in low or "slua" in low:
                mark("lua_runtime", name)
                if "cocos" in joined_sample or any(x.startswith(("assets/src/", "assets/res/")) for x in low_names):
                    mark("cocos2dx_lua", name)
            if low.endswith((".js", ".jsc")) and ("jsb-adapter" in low or low.startswith("assets/src/")):
                mark("cocos2dx_js", name)
            if "jsb-adapter" in low or (low.endswith((".prefab", ".scene")) and ("assets/" in low or "res/" in low)):
                mark("cocos_creator", name)
            if low.endswith((".csb", ".ccb")): mark("cocos2dx_cpp", name)
    return {"schema": "modkit-engine-detection-1.0", "detected": [k for k, v in evidence.items() if v], "evidence": evidence}


def _security_summary(obj: dict, kind: str, title: str, description: str) -> dict | None:
    groups = obj.get("groups") if isinstance(obj.get("groups"), dict) else {}
    group = groups.get(kind) if isinstance(groups, dict) else None
    if not isinstance(group, dict) or int(group.get("count", 0) or 0) <= 0:
        return None
    row = {"kind": kind, "title": title, "description": description, "trustBoundary": "server", "status": "FOUND_STATIC", "summary": group}
    card = _generic_card(row, "SecuritySummary", "Security/Connection")
    if card:
        card["ownership"] = "SECURITY"; card["important"] = True; card["lowSignal"] = False; card["priority"] = 88
    return card


def build_catalog(workdir: str | Path, output_path: str | Path | None = None) -> dict:
    root = Path(workdir)
    cards: list[dict] = []
    seen: set[str] = set()
    def add(card: dict | None) -> None:
        if not card:
            return
        key = str(card.get("menuControlId") or card.get("id") or f"{card.get('source')}|{card.get('title')}|{card.get('category')}|{card.get('status')}")
        if key in seen:
            return
        seen.add(key); cards.append(card)

    menu = _json(root / "menu-spec.json")
    if isinstance(menu, dict):
        for row in menu.get("controls", []) or []:
            if isinstance(row, dict): add(_menu_card(row))

    deep = root / "analysis-deep"
    if deep.is_dir():
        for p in sorted(deep.glob("method-*.json")):
            obj = _json(p)
            if isinstance(obj, dict): add(_generic_card(obj, "DeepResolver"))

    security = _json(root / "security-surfaces.json")
    if isinstance(security, dict):
        add(_security_summary(security, "endpoints", "Network / API Endpoints", "Найдены статические API/HTTP/WebSocket/host:port точки. Откройте детали для уникальных endpoint и точных файлов."))
        add(_security_summary(security, "crypto", "Crypto / Key Handling", "Найдены crypto/key-handling и TLS pinning markers. Это карта кода, а не доказательство утечки секретного ключа."))

    artifacts = _json(root / "artifact-families.json")
    if isinstance(artifacts, dict):
        for row in artifacts.get("artifacts", []) or []:
            if not isinstance(row, dict):
                continue
            card = _generic_card(row, "ArtifactFamily", "Runtime/Script")
            if card:
                card["ownership"] = "APP_OR_GAME"
                family = str(row.get("family") or "runtime")
                recovery = str(row.get("recoveryLevel") or "FOUND_STATIC")
                card["description"] = f"{family} · {recovery}. Артефакт найден во всех выбранных APK/split; symbols/strings участвуют в gameplay-поиске."
                add(_quality(card))

    for external_path in sorted(root.glob("external-evidence-*.json")):
        external = _json(external_path)
        if not isinstance(external, dict):
            continue
        for row in external.get("findings", []) or []:
            if not isinstance(row, dict):
                continue
            card = _generic_card(row, "ExternalEngine", str(row.get("category") or "External Evidence"))
            if card:
                card["externalCorroborating"] = True
                card["buildable"] = False
                card["selectable"] = False
                card["actionable"] = False
                card["locator"] = None
                card["status"] = "IMPORTED_EVIDENCE"
                card["description"] = str(row.get("description") or "Imported external-engine evidence; requires local confirmation before READY.")
                add(_quality(card))

    sources = [
        ("analysis.json", "Analysis"),
        ("analysis.gameplay-coverage.json", "Gameplay"),
        ("re-analysis.ui.json", "RE"),
        ("re-analysis.menu.json", "RE"),
        ("installed-scan.json", "InstalledScan"),
        ("security-surfaces.json", "SecuritySurface"),
        ("runtime-profiler.json", "RuntimeProfiler"),
        ("engine-router.json", "EngineRouter"),
        ("deobfuscation.json", "Deobfuscation"),
        ("native-inventory.json", "NativeInventory"),
        ("dotnet-deep.json", "DotNetDeep"),
        ("unreal-deep.json", "UnrealDeep"),
        ("godot-deep.json", "GodotDeep"),
        ("native-deep.json", "NativeDeep"),
        ("deep-gameplay.json", "Gameplay"),
    ]
    wanted = {"candidates", "discoveries", "cards", "findings", "profiles", "routes",
              "controlCandidates", "controls", "methods", "surfaces"}
    for name, source in sources:
        obj = _json(root / name)
        if not isinstance(obj, (dict, list)):
            continue
        for key, row in _iter_rows(obj, wanted):
            add(_generic_card(row, source, key))

    profiler = _json(root / "runtime-profiler.json")
    if isinstance(profiler, dict) and isinstance(profiler.get("profiles"), list):
        engine = {
            "schema": profiler.get("schema"),
            "detected": [str(x) for x in (profiler.get("detected") or [])],
            "evidence": {
                str(row.get("runtimeId")): list(row.get("evidence") or [])
                for row in profiler.get("profiles") if isinstance(row, dict) and row.get("runtimeId")
            },
            "abis": profiler.get("abis") or [],
            "splitAware": bool(profiler.get("splitAware")),
            "universalProfiler": True,
        }
    else:
        engine = detect_engines(_apk_paths(root))
        pretty = {
            "unity_il2cpp": "Unity / IL2CPP", "unity_mono": "Unity runtime", "cocos2dx_cpp": "Cocos2d-x C++",
            "cocos2dx_lua": "Cocos2d-x Lua", "cocos2dx_js": "Cocos2d-x JavaScript", "cocos_creator": "Cocos Creator",
            "lua_runtime": "Lua/xLua/SLua runtime", "android_dex": "Android DEX", "native": "Native ELF/.so",
        }
        for key in engine["detected"]:
            ev = engine["evidence"].get(key, [])
            add(_quality({
                "id": f"engine:{key}", "title": pretty.get(key, key), "category": "Engine/Runtime", "source": "EngineDetection",
                "status": "CONFIRMED", "buildable": False, "selectable": False, "actionable": False, "locator": None,
                "menuControlId": None, "description": "Автоматически обнаруженный runtime/движок; используется для выбора анализатора.",
                "serverAudit": False, "ownership": "ENGINE", "evidence": {"markers": ev},
            }))

    cards.sort(key=lambda c: (-int(c.get("priority", 0)), str(c.get("category", "")).casefold(), str(c.get("title", "")).casefold()))
    counts: dict[str, int] = {}
    for card in cards:
        counts[str(card.get("status") or "UNKNOWN")] = counts.get(str(card.get("status") or "UNKNOWN"), 0) + 1
    out = {
        "schema": SCHEMA, "engineDetection": engine, "cards": cards, "counts": counts,
        "total": len(cards), "buildable": sum(1 for c in cards if c.get("buildable")),
        "actionable": sum(1 for c in cards if c.get("actionable")),
        "important": sum(1 for c in cards if c.get("important")),
        "frameworkNoise": sum(1 for c in cards if c.get("ownership") == "FRAMEWORK"),
        "bundledSdk": sum(1 for c in cards if c.get("ownership") == "BUNDLED_SDK"),
        "serverAudit": sum(1 for c in cards if c.get("serverAudit")),
        "verificationCounts": {stage: sum(1 for c in cards if c.get("verificationStage") == stage)
                               for stage in sorted({str(c.get("verificationStage") or "FOUND_STATIC") for c in cards})},
        "gameplayCounts": {domain: sum(1 for c in cards if c.get("gameplayDomain") == domain)
                           for domain in sorted({str(c.get("gameplayDomain") or "") for c in cards if c.get("gameplayDomain")})},
        "policy": {
            "showAllFindings": True, "defaultView": "important", "buildOnlyValidatedLocalBindings": True,
            "serverBypassGenerated": False, "serverFindingsMode": "audit+local-simulation-only",
            "readyStatusMeansExactLocalLocator": True, "autoBuildStillRequiresValidatedExecutableBinding": True,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def filter_menu_spec(menu_json_path: str | Path, selected_ids_json: str, output_path: str | Path | None = None) -> dict:
    path = Path(menu_json_path)
    raw = _json(path)
    if not isinstance(raw, dict):
        raise ValueError("menu spec is missing or invalid")
    try:
        selected = json.loads(selected_ids_json)
    except Exception as exc:
        raise ValueError(f"invalid selection json: {exc}") from exc
    if not isinstance(selected, list):
        raise ValueError("selection must be a JSON list")
    wanted = {str(x) for x in selected}
    controls = [c for c in raw.get("controls", []) if isinstance(c, dict)]
    kept = [c for c in controls if str(c.get("id", "")) in wanted]
    # Explicitly retain the fail-closed server gate expected by dev37 regression tests.
    safe = [c for c in kept if c.get("binding") and c.get("rva") is not None and not c.get("probe_kind") and str(c.get("type", "")).casefold() != "label" and not _contains_server(c)]
    raw["controls"] = safe
    dest = Path(output_path) if output_path else path
    dest.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"schema": "modkit-simple-selection-1.1", "requested": len(wanted), "matched": len(kept), "buildable": len(safe), "controlIds": [str(c.get("id")) for c in safe]}
