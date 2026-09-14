"""Dev27 shared native evidence graph and gameplay discovery.

This module is intentionally generic.  It never contains application/package
names and never turns discovery evidence into an executable binding.  Runtime
truth remains separate from static evidence.
"""
from __future__ import annotations

import bisect
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import zipfile

_GRAPH_SCHEMA = "modkit-native-evidence-graph-1.0"
_COVERAGE_SCHEMA = "modkit-gameplay-coverage-1.0"
_MISSING = (1 << 64) - 1

# Exact token/domain vocabulary.  Generic infrastructure words such as
# ``resource`` or ``level`` are deliberately weak and require owner/state proof.
_DOMAIN_WORDS = {
    "health": {"health", "hp", "hitpoint", "hitpoints", "alive", "dead", "death", "heal", "healing", "revive", "revived", "lifestate"},
    "damage": {"damage", "dmg", "attack", "attacker", "hurt", "injury", "crit", "critical", "combat", "armor", "armour", "defense", "defence"},
    "currency": {"gold", "coin", "coins", "currency", "currencies", "gem", "gems", "diamond", "diamonds", "wallet", "spend", "cost", "purchase", "grant"},
    "progression": {"xp", "experience", "levelup", "progression", "rank", "upgrade", "unlock", "skillpoint", "skillpoints"},
    "movement": {"speed", "movespeed", "movementspeed", "movement", "velocity", "timescale"},
    "resource": {"mana", "energy", "stamina", "rage"},
    "cooldown": {"cooldown", "cooldowns", "cdtime"},
    "inventory": {"inventory", "item", "items", "stack", "quantity", "backpack"},
    "camera": {"fov", "camera", "zoom"},
    "world": {"world", "weather", "day", "night", "timescale", "gametime"},
    "debug": {"debug", "console", "developer", "devmenu", "godmode", "noclip"},
}

# ``level`` and ``balance`` are extremely ambiguous.  They are accepted only on
# gameplay-looking state owners and never by package-string evidence alone.
_WEAK_FIELD_WORDS = {
    "health": {"life"},
    "currency": {"balance", "reward"},
    "progression": {"level", "rank", "exp"},
    "movement": {"speed"},
    "inventory": {"slot", "count"},
}

_NOISE_PARTS = {
    "ifix", "luainterface", "flowcanvas", "nodecanvas", "uwa", "crashsight",
    "magica", "cloth", "render", "renderer", "rendering", "quality", "lod",
    "pathfinding", "profiler", "formatter", "codec", "sdk", "middleware",
    "analytics", "telemetry", "logger", "logging", "typewriter", "easytouch",
    "etcaxis", "etcinput", "etcdpad", "etcjoystick", "etcbase",
    "criware", "cri", "vitamana", "salsa", "rope", "curvy", "timeline", "editor",
    "fx", "effect", "animation", "anim", "ani", "typewriter", "outline", "febucci", "astar", "superscroll", "dynamicmaterial", "lua", "luamanager", "translator",
}

_GAME_OWNER_PARTS = {
    "player", "hero", "actor", "avatar", "character", "unit", "battle",
    "combat", "inventory", "wallet", "currency", "skill", "ability", "quest",
    "mapunit", "fighter", "enemy", "npc", "pet",
}


_PACKAGE_STRONG_WORDS = {
    "health": {"health", "hitpoint", "hitpoints", "alive", "heal", "revive"},
    "damage": {"damage", "hurt", "injury", "attackdamage", "attackpower"},
    "currency": {"gold", "coin", "coins", "currency", "gem", "gems", "diamond", "diamonds", "wallet"},
    "progression": {"experience", "levelup", "rankup", "skillpoint", "skillpoints"},
    "movement": {"movespeed", "movementspeed", "actionspeed", "globalspeed", "timescale"},
    "resource": {"mana", "energy", "stamina", "rage"},
    "cooldown": {"cooldown", "cdtime"},
    "inventory": {"inventory", "backpack", "stackcount"},
    "camera": {"fov", "camera", "zoom"},
    "world": {"weather", "timescale", "gametime"},
    "debug": {"debug", "console", "devmenu", "godmode", "noclip"},
}

def _package_domains(text):
    if _noise(text):
        return []
    low=" ".join(_tokens(text))
    # Networking, Play SDK and analytics strings can contain gameplay-looking
    # words without representing game state. Keep them as infrastructure only.
    if any(x in low for x in (
        "keep alive", "keepalive", "com google android play", "google label purchase",
        "currency code", "report revenue", "square create category health",
        "okhttp", "grpc", "protobuf", "billingclient", "google pay", "purchase order",
        "pay currency", "pay item", "ali log track",
    )):
        return []
    tokens=set(_tokens(text)); compact="".join(tokens)
    out=[]
    for domain, words in _PACKAGE_STRONG_WORDS.items():
        if tokens & words or compact in words:
            out.append(domain)

    # Generic Currency APIs, locale formatting and analytics are not game-wallet evidence.
    if "currency" in out:
        concrete={"gold","coin","coins","gem","gems","diamond","diamonds","wallet"}
        context={"balance","spend","spent","cost","price","reward","premium","shop","store","item","purchase"}
        sdk_noise={"revenue","analytics","event","events","symbol","exponent","locale","formatter","facebook","fb","appsflyer","adjust","tiktok","java","util","currencytosymbol"}
        has_concrete=bool(tokens & concrete)
        if (not has_concrete and not bool(tokens & context)) or (tokens & sdk_noise and not has_concrete):
            out=[d for d in out if d != "currency"]
    low=" ".join(tokens)
    if "cri mana" in low or "vitamana" in low:
        out=[d for d in out if d != "resource"]
    return sorted(out)

_FIELD_DOMAIN_WORDS = {
    "health": {"health", "hp", "hitpoint", "hitpoints", "alive"},
    "damage": {"damage", "dmg", "attackpower", "attackdamage"},
    "currency": {"gold", "coin", "coins", "currency", "gem", "gems", "diamond", "diamonds"},
    "progression": {"xp", "experience", "level", "rank"},
    "movement": {"speed", "movespeed", "movementspeed", "actionspeed", "globalspeed", "timescale"},
    "resource": {"mana", "energy", "stamina", "rage"},
    "cooldown": {"cooldown", "cd", "cdtime"},
    "inventory": {"inventory", "quantity", "stackcount"},
    "camera": {"fov", "zoom"},
    "world": {"weather", "timescale", "gametime"},
    "debug": {"debug", "godmode", "noclip"},
}


def _tokens(text):
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or ""))
    return [x.lower() for x in re.findall(r"[A-Za-z][A-Za-z0-9]*", text)]


def _noise(text):
    toks = _tokens(text)
    t = set(toks)
    if t & _NOISE_PARTS:
        return True
    compact = "".join(toks)
    # CamelCase framework names split into several tokens; recognize their
    # compact spelling without treating short fragments such as ``cri`` as substrings.
    compact_noise = {"crashsight","easytouch","flowcanvas","nodecanvas","luainterface","magicloth","magica","typewriter","febucci","superscrollview","dynamicmaterial"}
    return any(x in compact for x in compact_noise)


def _owner_gameplay(text):
    t = set(_tokens(text))
    return bool(t & _GAME_OWNER_PARTS) and not bool(t & _NOISE_PARTS)


def domains_for(text, *, owner=None, field=False):
    token_list = _tokens(text)
    tokens = set(token_list)
    owner_text = owner or ""
    owner_tokens = set(_tokens(owner_text))
    if field:
        # Runtime fields are much stronger evidence than names, but ambiguous
        # state words still require a gameplay-looking owner. This prevents
        # ETCAxis.deadValue, FPS/log levels, reward animation state and CRI Mana
        # middleware from becoming player-state evidence.
        if _noise(owner_text + " " + str(text or "")):
            return []
        owner_ok = _owner_gameplay(owner_text)
        out = set()
        compact = "".join(token_list)
        for domain, words in _FIELD_DOMAIN_WORDS.items():
            matched = bool(tokens & words) or compact in words
            if not matched:
                continue
            if domain in {"camera"}:
                allowed = owner_ok or bool(owner_tokens & {"camera", "mapcamera"})
            elif domain in {"world"}:
                allowed = owner_ok or bool(owner_tokens & {"weather", "world", "time", "environment", "sky"})
            elif domain == "cooldown":
                allowed = owner_ok or compact in {"cd", "cooldown", "cdtime"}
            elif domain == "debug":
                allowed = owner_ok
            else:
                allowed = owner_ok
            if allowed:
                out.add(domain)
        low = " ".join(_tokens(owner_text + " " + text))
        if "cri mana" in low or "mana init" in low or "mana decoder" in low:
            out.discard("resource")
        return sorted(out)

    out = set()
    compact = "".join(token_list)
    compound_words={"timescale","movespeed","movementspeed","hitpoint","hitpoints","levelup","skillpoint","skillpoints","devmenu","godmode"}
    for domain, words in _DOMAIN_WORDS.items():
        if tokens & words or any(w in compact for w in (words & compound_words)):
            out.add(domain)
    low = " ".join(_tokens(text))
    if "cri mana" in low:
        out.discard("resource")
    if any(x in low for x in ("mip level", "lod level", "log level", "quality level", "grid level", "patch level")):
        out.discard("progression")
    if any(x in low for x in ("format currency", "currency formatter", "reward animation", "reward anim")):
        out.discard("currency")
    if _noise(owner_text + " " + text):
        out.clear()
    return sorted(out)


def _method_domain_relevant(row, domain):
    """Require domain-specific method evidence; generic neighboring words stay graph-only."""
    label = (row.get("class") or "") + " " + (row.get("name") or "")
    if _noise(label):
        return False
    tokens = set(_tokens(label))
    owner_ok = bool(row.get("applicationOwned")) or _owner_gameplay(row.get("class") or "")
    strong = {
        "health": {"health", "hp", "heal", "healing", "revive", "alive"},
        "damage": {"damage", "hurt", "injury", "attackdamage", "attackpower"},
        "currency": {"gold", "coin", "coins", "currency", "gem", "gems", "diamond", "diamonds", "wallet", "spend", "purchase"},
        "progression": {"xp", "experience", "levelup", "rankup", "upgrade", "progression"},
        "movement": {"speed", "movespeed", "movementspeed", "actionspeed", "globalspeed", "timescale", "movement"},
        "resource": {"mana", "energy", "stamina", "rage"},
        "cooldown": {"cooldown", "cd", "cdtime"},
        "inventory": {"inventory", "backpack", "quantity", "stackcount"},
        "camera": {"fov", "camera", "zoom"},
        "world": {"weather", "timescale", "gametime"},
        "debug": {"debug", "console", "devmenu", "godmode", "noclip"},
    }.get(domain, set())
    compact = "".join(tokens)
    hit = bool(tokens & strong) or compact in strong
    # Exact typed-field evidence can carry semantics through an obfuscated name.
    if any(domain in (a.get("domains") or []) for a in (row.get("typedFieldAccesses") or [])):
        return True
    owner_tokens = set(_tokens(row.get("class") or ""))
    gameplay_owner = _owner_gameplay(row.get("class") or "")
    if domain in {"health", "damage", "currency", "progression", "resource", "inventory"}:
        allowed_owner = gameplay_owner
    elif domain == "movement":
        allowed_owner = gameplay_owner or bool(owner_tokens & {"motion", "time"})
    elif domain == "cooldown":
        allowed_owner = gameplay_owner or bool(owner_tokens & {"interact", "cooldown", "cd"})
    elif domain == "camera":
        allowed_owner = gameplay_owner or bool(owner_tokens & {"camera", "mapcamera"})
    elif domain == "world":
        allowed_owner = gameplay_owner or bool(owner_tokens & {"weather", "world", "time", "environment", "sky"})
    elif domain == "debug":
        allowed_owner = bool(row.get("applicationOwned"))
    else:
        allowed_owner = owner_ok
    return bool(allowed_owner and hit)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _source_identity(metadata_path, library_path, catalog_path):
    return {
        "metadataSha256": _sha256(metadata_path),
        "metadataBytes": os.path.getsize(metadata_path),
        "librarySha256": _sha256(library_path),
        "libraryBytes": os.path.getsize(library_path),
        "catalogSha256": _sha256(catalog_path),
        "catalogBytes": os.path.getsize(catalog_path),
    }


def graph_identity_matches(manifest, metadata_path, library_path, catalog_path):
    try:
        expected = (manifest or {}).get("sourceIdentity") or {}
        current = _source_identity(metadata_path, library_path, catalog_path)
        return all(expected.get(k) == v for k, v in current.items())
    except OSError:
        return False


def _catalog_compact(catalog_path, cb=None):
    """Read the file-backed catalogue once into compact native-graph structures."""
    nodes = {}
    rva_to_mid = {}
    max_mid = -1
    with open(catalog_path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f):
            if n % 4096 == 0 and cb is not None:
                from modkit.mobile.engine import check
                check(cb)
            if not line.strip():
                continue
            row = json.loads(line)
            mid = int(row.get("metadata_method_id", row.get("id", -1)))
            if mid < 0:
                continue
            max_mid = max(max_mid, mid)
            rva = row.get("rva") if row.get("address_confirmed") else None
            if isinstance(rva, int) and rva > 0:
                rva_to_mid[int(rva)] = mid
            label = row.get("label") or ((row.get("class") or "") + "::" + (row.get("name") or ""))
            cls = row.get("class") or label.split("::", 1)[0]
            nodes[mid] = {
                "metadataMethodId": mid,
                "rva": int(rva) if isinstance(rva, int) and rva > 0 else None,
                "label": label,
                "image": row.get("image"),
                "class": cls,
                "name": row.get("name") or (label.split("::", 1)[1] if "::" in label else label),
                "declaringTypeIndex": row.get("declaring_type_index"),
                "metadataSlot": row.get("metadata_slot"),
                "isStatic": bool(row.get("is_static")),
                "generic": bool(row.get("generic")),
                "abstract": bool(row.get("abstract")),
                "methodRole": row.get("method_role"),
                "parameterTypeDefinitionIndices": list(row.get("parameter_type_definition_indices") or []),
                "applicationOwned": bool(row.get("application_owned")),
                "provenance": row.get("provenance"),
                "abiShapeSupported": bool(row.get("abi_shape_supported")),
                "bindingSuggestion": row.get("binding_suggestion"),
                "bindingBlocker": row.get("binding_blocker"),
                "domains": domains_for(label, owner=cls),
            }
    return nodes, rva_to_mid, max_mid


def _field_catalog(meta, elf, registration, types, cb=None):
    by_type = {}
    rows = []
    for ti in range(meta.type_count):
        if ti % 512 == 0 and cb is not None:
            from modkit.mobile.engine import check
            check(cb)
        try:
            exact = elf.runtime_field_offsets(registration, meta, ti)
        except ValueError:
            continue
        if not exact:
            continue
        offset_map = {}
        for f in exact:
            off = f.get("runtimeOffset")
            if off is None or int(off) < 0x10:
                # Object instance fields on supported 64-bit IL2CPP layouts live
                # after the object header. Offset-zero enum/static constants are
                # not mutable per-instance gameplay state.
                continue
            shape = elf.metadata_type_shape(types, f.get("typeIndex", -1)) if types else None
            row = {
                "fieldDefinitionIndex": f["fieldDefinitionIndex"],
                "declaringTypeIndex": ti,
                "declaringType": f["declaringType"],
                "name": f["name"],
                "runtimeOffset": int(off),
                "typeIndex": f.get("typeIndex"),
                "fieldTypeDefinitionIndex": (shape or {}).get("typeDefIndex"),
                "fieldTypeCode": (shape or {}).get("typeCode"),
                "primitive": (shape or {}).get("primitive"),
                "domains": domains_for(f["name"], owner=f["declaringType"], field=True),
            }
            offset_map.setdefault(int(off), []).append(row)
            rows.append(row)
        if offset_map:
            by_type[ti] = offset_map
    return rows, by_type


def _branch_target(pc, word):
    # Unconditional B / BL, immediate 26.
    if word & 0x7C000000 == 0x14000000:
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return pc + (imm << 2)
    # B.cond immediate 19.
    if word & 0xFF000010 == 0x54000000:
        imm = (word >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return pc + (imm << 2)
    # CBZ/CBNZ immediate 19.
    if word & 0x7E000000 == 0x34000000:
        imm = (word >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return pc + (imm << 2)
    # TBZ/TBNZ immediate 14.
    if word & 0x7E000000 == 0x36000000:
        imm = (word >> 5) & 0x3FFF
        if imm & 0x2000:
            imm -= 0x4000
        return pc + (imm << 2)
    return None


def _successors(method_rva, words, i):
    word = words[i]
    pc = method_rva + i * 4
    n = len(words)
    target = _branch_target(pc, word)
    def idx_for(rv):
        d = int(rv) - int(method_rva)
        return d // 4 if d >= 0 and d % 4 == 0 and d // 4 < n else None
    # RET
    if word & 0xFFFFFC1F == 0xD65F0000:
        return []
    # B (not BL) has no fallthrough.
    if word & 0xFC000000 == 0x14000000:
        j = idx_for(target)
        return [j] if j is not None else []
    # Conditional branches have target + fallthrough.
    if (word & 0xFF000010 == 0x54000000 or
        word & 0x7E000000 in (0x34000000, 0x36000000)):
        out = []
        j = idx_for(target)
        if j is not None:
            out.append(j)
        if i + 1 < n:
            out.append(i + 1)
        return out
    return [i + 1] if i + 1 < n else []


def _merge_state(old, new):
    if old is None:
        return dict(new), True
    # Provenance is usable only when every incoming path agrees exactly.
    merged = {r: v for r, v in old.items() if r in new and new[r] == v}
    return merged, merged != old


def _transfer(word, state, field_by_type, pc, accesses):
    st = dict(state)
    # MOV Xd, Xm alias: ORR Xd, XZR, Xm.
    if word & 0xFFE0FFE0 == 0xAA0003E0:
        dst = word & 31
        src = (word >> 16) & 31
        if src in st:
            st[dst] = st[src]
        else:
            st.pop(dst, None)
    # ADD Xd, Xn, #0 is also a safe pointer copy.
    elif word & 0xFFC003E0 == 0x91000000 and ((word >> 10) & 0xFFF) == 0:
        dst, src = word & 31, (word >> 5) & 31
        if src in st:
            st[dst] = st[src]
        else:
            st.pop(dst, None)

    # Load/store unsigned immediate, including byte/halfword/int/X and scalar S/D.
    if word & 0x3B000000 == 0x39000000:
        opc = (word >> 22) & 3
        rn, rt = (word >> 5) & 31, word & 31
        size_code = (word >> 30) & 3
        off = ((word >> 10) & 0xFFF) << size_code
        width = 8 << size_code
        base = st.get(rn)
        is_load = opc == 1
        is_store = opc == 0
        if base and (is_load or is_store):
            type_index = base[0]
            exact = (field_by_type.get(type_index) or {}).get(off) or []
            for field in exact:
                accesses.append({
                    "instructionRva": int(pc), "access": "load" if is_load else "store",
                    "widthBits": width, "baseRegister": f"x{rn}",
                    "baseProvenance": base[1], "declaringTypeIndex": type_index,
                    "declaringType": field["declaringType"], "field": field["name"],
                    "fieldOffset": off, "fieldDefinitionIndex": field["fieldDefinitionIndex"],
                    "fieldTypeDefinitionIndex": field.get("fieldTypeDefinitionIndex"),
                    "domains": field.get("domains") or [], "proof": "typed-register+MetadataRegistration-fieldOffsets",
                })
            if is_load:
                # Only a 64-bit load can propagate an object pointer. Unknown
                # loads explicitly kill the old destination provenance.
                propagated = None
                if width == 64 and len(exact) == 1 and exact[0].get("fieldTypeDefinitionIndex") is not None:
                    f = exact[0]
                    propagated = (int(f["fieldTypeDefinitionIndex"]),
                                  f"field:{f['declaringType']}.{f['name']}")
                if propagated:
                    st[rt] = propagated
                else:
                    st.pop(rt, None)
        elif is_load:
            st.pop(rt, None)

    # LDP loads can restore callee-saved registers from the stack; kill both.
    if word & 0x3A000000 == 0x28000000 and ((word >> 22) & 1):
        st.pop(word & 31, None)
        st.pop((word >> 10) & 31, None)

    # Calls clobber volatile general-purpose argument registers x0-x18.
    if word & 0xFC000000 == 0x94000000 or word & 0xFFFFFC1F == 0xD63F0000:
        for reg in range(19):
            st.pop(reg, None)
    return st


def typed_field_accesses(elf, method, next_rva, field_by_type, *, max_bytes=16384):
    """CFG-aware typed object field tracking for one ARM64 managed method."""
    rva = int(method.get("rva") or 0)
    if not rva or not next_rva or int(next_rva) <= rva:
        return []
    span = min(int(next_rva) - rva, int(max_bytes)) & ~3
    if span < 4:
        return []
    try:
        off = elf.offset(rva, span, True)
    except ValueError:
        return []
    words = list(struct.unpack_from(f"<{span // 4}I", elf.b, off))
    initial = {}
    decl = method.get("declaringTypeIndex")
    if not method.get("isStatic") and isinstance(decl, int) and decl >= 0:
        initial[0] = (int(decl), "this")
    reg = 0 if method.get("isStatic") else 1
    for type_index in method.get("parameterTypeDefinitionIndices") or []:
        if reg > 7:
            break
        if isinstance(type_index, int) and type_index >= 0:
            initial[reg] = (int(type_index), f"arg{reg if method.get('isStatic') else reg-1}")
        reg += 1
    states = [None] * len(words)
    states[0] = initial
    queue = collections.deque([0])
    accesses = []
    seen_access = set()
    visits = 0
    while queue and visits < max(64, len(words) * 16):
        visits += 1
        i = queue.popleft()
        before = states[i] or {}
        pc = rva + i * 4
        local = []
        after = _transfer(words[i], before, field_by_type, pc, local)
        for item in local:
            key = (item["instructionRva"], item["access"], item["declaringTypeIndex"], item["fieldOffset"])
            if key not in seen_access:
                seen_access.add(key); accesses.append(item)
        for j in _successors(rva, words, i):
            if j is None or not 0 <= j < len(words):
                continue
            merged, changed = _merge_state(states[j], after)
            if changed:
                states[j] = merged
                queue.append(j)
    return accesses[:128]


def build_evidence_graph(metadata_path, library_path, catalog_path, graph_path, cb=None,
                         *, max_field_methods=12000, max_edges=1_500_000):
    """Build one reusable native evidence graph for the whole IL2CPP target."""
    from modkit.mobile.engine import Metadata, Elf, check
    metadata_path, library_path, catalog_path = map(str, (metadata_path, library_path, catalog_path))
    graph_path = Path(graph_path)
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    check(cb, "Evidence Graph: чтение file-backed metadata-каталога")
    nodes, rva_to_mid, max_mid = _catalog_compact(catalog_path, cb)
    starts = sorted(rva_to_mid)
    next_by_rva = {rva: starts[i + 1] for i, rva in enumerate(starts[:-1])}

    callers = collections.defaultdict(list)
    callees = collections.defaultdict(list)
    edge_counts = collections.Counter()
    edge_seen = set()
    check(cb, "Evidence Graph: один ARM64 BL/B scan")
    elf = Elf(library_path, cb)
    meta = Metadata(metadata_path)
    try:
        high_byte = re.compile(b"[\x14-\x17\x94-\x97]")
        edges = 0
        scanned = 0
        for va, off, size, flags in elf.segments:
            if not (flags & 1) or size < 4:
                continue
            raw = memoryview(elf.b)[off:off + (size & ~3)]
            try:
                for hit in high_byte.finditer(raw):
                    rel = hit.start() - 3
                    if rel < 0 or rel & 3:
                        continue
                    word = struct.unpack_from('<I', raw, rel)[0]
                    kind = None
                    if word & 0xFC000000 == 0x94000000:
                        kind = "bl"
                    elif word & 0xFC000000 == 0x14000000:
                        kind = "tail-b"
                    else:
                        continue
                    imm = word & 0x03FFFFFF
                    if imm & 0x02000000:
                        imm -= 0x04000000
                    pc = int(va) + rel
                    target_rva = pc + (imm << 2)
                    target_mid = rva_to_mid.get(target_rva)
                    if target_mid is None:
                        continue
                    ix = bisect.bisect_right(starts, pc) - 1
                    if ix < 0:
                        continue
                    source_rva = starts[ix]
                    if pc >= next_by_rva.get(source_rva, 1 << 63):
                        continue
                    source_mid = rva_to_mid[source_rva]
                    key = (source_mid, target_mid, kind)
                    edge_counts[kind] += 1
                    if key in edge_seen:
                        continue
                    edge_seen.add(key)
                    if len(callees[source_mid]) < 96:
                        callees[source_mid].append({"metadataMethodId": target_mid, "kind": kind, "callRva": pc})
                    if len(callers[target_mid]) < 96:
                        callers[target_mid].append({"metadataMethodId": source_mid, "kind": kind, "callRva": pc})
                    edges += 1
                    if edges >= int(max_edges):
                        break
                if edges >= int(max_edges):
                    break
            finally:
                raw.release()
            scanned += size & ~3
            check(cb)

        check(cb, "Evidence Graph: MetadataRegistration fieldOffsets")
        max_type_index = max(meta.parameter_type_indices(), default=0)
        types = elf.type_table(meta.type_count, max_type_index)
        registration = elf.metadata_registration(meta.type_count, max_type_index)
        field_rows, field_by_type = _field_catalog(meta, elf, registration, types, cb) if registration else ([], {})

        # Build a name-independent resolver *candidate* index once.  Deep
        # Resolver still performs the machine-code proof (stable global pointer
        # return) on demand, but it no longer has to rescan all 150k+ metadata
        # methods merely to discover the handful of methods returning the
        # candidate's exact managed type.
        resolver_by_type = collections.defaultdict(list)
        if types is not None:
            check(cb, "Evidence Graph: type-exact instance resolver index")
            for mid, node in nodes.items():
                if mid % 4096 == 0:
                    check(cb)
                if not node.get("isStatic") or not node.get("rva"):
                    continue
                try:
                    md = meta.method_definition(mid)
                except ValueError:
                    continue
                if md.get("isAbstract") or int(md.get("genericContainerIndex", -1)) >= 0:
                    continue
                rshape = elf.metadata_type_shape(types, md.get("returnTypeIndex", -1))
                kind = None
                target_type = None
                if int(md.get("parameterCount") or 0) == 0 and rshape and not rshape.get("byRef"):
                    if rshape.get("typeCode") in {0x11, 0x12} and isinstance(rshape.get("typeDefIndex"), int):
                        kind = "return_ptr"
                        target_type = int(rshape["typeDefIndex"])
                elif (int(md.get("parameterCount") or 0) == 1 and rshape
                      and rshape.get("primitive") == "bool" and not rshape.get("byRef")):
                    try:
                        param = meta.parameters_for(md.get("parameterStart", -1), 1)[0]
                        pshape = elf.metadata_type_shape(types, param.get("type_index", -1))
                    except (ValueError, IndexError):
                        pshape = None
                    if pshape and pshape.get("byRef") and isinstance(pshape.get("typeDefIndex"), int):
                        kind = "out_ptr_bool"
                        target_type = int(pshape["typeDefIndex"])
                if kind is None or target_type is None or not 0 <= target_type < meta.type_count:
                    continue
                bucket = resolver_by_type[target_type]
                if len(bucket) < 256:
                    bucket.append({
                        "metadataMethodId": int(mid), "rva": int(node["rva"]),
                        "label": node.get("label"), "image": (node.get("image") or ""),
                        "kind": kind, "targetTypeDefinitionIndex": target_type,
                    })

        # Domain seeds are independent evidence: method name/owner, exact state
        # field existence, and one-hop relations.  No game-specific strings.
        gameplay_types = {f["declaringTypeIndex"] for f in field_rows if f.get("domains")}
        field_candidates = set()
        for mid, node in nodes.items():
            if node.get("domains") or node.get("declaringTypeIndex") in gameplay_types:
                field_candidates.add(mid)
        # Preserve obfuscated bridges adjacent to gameplay seeds.
        for mid in list(field_candidates):
            field_candidates.update(x["metadataMethodId"] for x in callers.get(mid, ()))
            field_candidates.update(x["metadataMethodId"] for x in callees.get(mid, ()))
        ranked = sorted(field_candidates,
                        key=lambda mid: (not bool(nodes.get(mid, {}).get("domains")),
                                         not bool(nodes.get(mid, {}).get("applicationOwned")), mid))[:int(max_field_methods)]
        # The large file-backed catalogue is intentionally ABI-light. Materialize
        # parameter object type identities only for the bounded field-analysis
        # window so x1-x7 cross-object writes can be proven without typing all
        # 167k methods eagerly.
        for mid in ranked:
            node = nodes.get(mid)
            if not node:
                continue
            try:
                md = meta.method_definition(mid)
                node["declaringTypeIndex"] = int(md.get("declaringTypeIndex", -1))
                node["isStatic"] = bool(md.get("isStatic"))
                pdefs = []
                for param in meta.parameters_for(md.get("parameterStart", -1), md.get("parameterCount", 0)):
                    shape = elf.metadata_type_shape(types, param.get("type_index", -1)) if types else None
                    pdefs.append((shape or {}).get("typeDefIndex"))
                node["parameterTypeDefinitionIndices"] = pdefs
            except (ValueError, struct.error):
                pass

        field_access_by_mid = {}
        check(cb, f"Evidence Graph: typed object fields ({len(ranked)} методов)")
        for n, mid in enumerate(ranked):
            if n % 256 == 0:
                check(cb)
            node = nodes.get(mid)
            if not node or not node.get("rva"):
                continue
            access = typed_field_accesses(elf, node, next_by_rva.get(node["rva"]), field_by_type)
            if access:
                field_access_by_mid[mid] = access

        # Semantic bridge: an otherwise unnamed node between same-domain native
        # neighbors may participate in discovery, but never auto-binding by itself.
        bridge_domains = {}
        for mid, node in nodes.items():
            if node.get("domains"):
                continue
            left = set()
            right = set()
            for edge in callers.get(mid, ()):
                left.update(nodes.get(edge["metadataMethodId"], {}).get("domains") or [])
            for edge in callees.get(mid, ()):
                right.update(nodes.get(edge["metadataMethodId"], {}).get("domains") or [])
            common = left & right
            if common and (node.get("applicationOwned") or field_access_by_mid.get(mid)):
                bridge_domains[mid] = sorted(common)

        temp = str(graph_path) + ".tmp"
        idx_temp = str(graph_path) + ".idx.tmp"
        autopilot_path = graph_path.with_name("analysis.autopilot-index.jsonl")
        autopilot_temp = str(autopilot_path) + ".tmp"
        offsets = [_MISSING] * (max_mid + 1 if max_mid >= 0 else 0)
        byte_off = 0
        autopilot_rows = 0
        with open(temp, "wb") as out, open(autopilot_temp, "w", encoding="utf-8") as autopilot:
            for mid in sorted(nodes):
                node = nodes[mid]
                exact_fields = field_access_by_mid.get(mid) or []
                field_domains = sorted({d for x in exact_fields for d in (x.get("domains") or [])})
                semantic_domains = sorted(set(node.get("domains") or []) | set(field_domains) | set(bridge_domains.get(mid, [])))
                row = {
                    **node,
                    "callers": callers.get(mid, [])[:48],
                    "callees": callees.get(mid, [])[:48],
                    "typedFieldAccesses": exact_fields[:48],
                    "fieldDomains": field_domains,
                    "bridgeDomains": bridge_domains.get(mid, []),
                    "semanticDomains": semantic_domains,
                    "runtimeStatus": "not-observed",
                }
                encoded = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                offsets[mid] = byte_off
                out.write(encoded); byte_off += len(encoded)
                # Compact discovery queue for Autopilot.  This is ranking-only:
                # ABI/resolver/menu safety are still re-proved by Deep Resolver.
                if (node.get("applicationOwned") and semantic_domains
                        and not _noise((node.get("class") or "") + " " + (node.get("label") or ""))):
                    compact = {
                        "metadataMethodId": mid, "rva": node.get("rva"),
                        "label": node.get("label"), "class": node.get("class"), "name": node.get("name"),
                        "isStatic": node.get("isStatic"), "metadataSlot": node.get("metadataSlot"),
                        "generic": node.get("generic"), "abstract": node.get("abstract"),
                        "methodRole": node.get("methodRole"), "applicationOwned": True,
                        "domains": node.get("domains") or [], "semanticDomains": semantic_domains,
                        "typedFieldAccesses": exact_fields[:16],
                        "callerCount": len(callers.get(mid, [])), "calleeCount": len(callees.get(mid, [])),
                    }
                    autopilot.write(json.dumps(compact, ensure_ascii=False, separators=(",", ":")) + "\n")
                    autopilot_rows += 1
        with open(idx_temp, "wb") as out:
            for off in offsets:
                out.write(struct.pack(">Q", int(off)))
        os.replace(temp, graph_path)
        os.replace(idx_temp, str(graph_path) + ".idx")
        os.replace(autopilot_temp, autopilot_path)

        fields_path = graph_path.with_name("analysis.fields.jsonl")
        ftemp = str(fields_path) + ".tmp"
        with open(ftemp, "w", encoding="utf-8") as out:
            for row in field_rows:
                out.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        os.replace(ftemp, fields_path)

        resolver_path = graph_path.with_name("analysis.resolver-index.json")
        rtemp = str(resolver_path) + ".tmp"
        Path(rtemp).write_text(json.dumps({str(k): v for k, v in resolver_by_type.items()},
                                         ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        os.replace(rtemp, resolver_path)

        identity = _source_identity(metadata_path, library_path, catalog_path)
        manifest = {
            "schema": _GRAPH_SCHEMA,
            "sourceIdentity": identity,
            "nodes": len(nodes),
            "exactExecutableRva": len(rva_to_mid),
            "edges": len(edge_seen),
            "directBlEdges": int(edge_counts["bl"]),
            "tailBEdges": int(edge_counts["tail-b"]),
            "typedFieldAccesses": sum(len(x) for x in field_access_by_mid.values()),
            "exactRuntimeFields": len(field_rows),
            "bridgeMethods": len(bridge_domains),
            "fieldScanMethods": len(ranked),
            "resolverTargetTypes": len(resolver_by_type),
            "resolverCandidates": sum(len(v) for v in resolver_by_type.values()),
            "autopilotRows": autopilot_rows,
            "graphFile": graph_path.name,
            "graphIndexFile": graph_path.name + ".idx",
            "fieldsFile": fields_path.name,
            "resolverIndexFile": resolver_path.name,
            "autopilotIndexFile": autopilot_path.name,
            "typeTable": ({"count": int(types[0]), "tableOffset": int(types[1])}
                          if types is not None else None),
            "metadataRegistration": registration,
            "runtimeTruth": "not-observed-by-static-analysis",
        }
        mpath = graph_path.with_name("analysis.evidence-graph.meta.json")
        mt = str(mpath) + ".tmp"
        Path(mt).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(mt, mpath)
        return manifest
    finally:
        meta.close(); elf.close()


def graph_method(graph_path, metadata_method_id):
    graph_path = Path(graph_path)
    ix = Path(str(graph_path) + ".idx")
    mid = int(metadata_method_id)
    if mid < 0 or not graph_path.is_file() or not ix.is_file():
        return None
    with ix.open("rb") as f:
        f.seek(mid * 8); raw = f.read(8)
    if len(raw) != 8:
        return None
    off = struct.unpack(">Q", raw)[0]
    if off == _MISSING:
        return None
    with graph_path.open("rb") as f:
        f.seek(off); line = f.readline()
    if not line:
        return None
    row = json.loads(line.decode("utf-8"))
    if int(row.get("metadataMethodId", -1)) != mid:
        raise ValueError("Evidence Graph index points to another method")
    return row


def scan_apk_package_evidence(apk_path, *, max_total_bytes=48 * 1024 * 1024, max_entry_bytes=8 * 1024 * 1024, max_hits=384):
    """Bounded discovery-only scan of an APK or APK-set. Never creates bindings.

    An installed package may be represented by a base APK plus multiple split APKs.
    ModKit stores those splits in one ZIP for analysis; nested APKs are opened one
    at a time so package/content evidence is not lost merely because it lives in a
    feature/config split rather than base.apk.
    """
    path = Path(apk_path) if apk_path else None
    if not path or not path.is_file():
        return []
    hits, seen = [], set()
    per_domain = collections.Counter()
    domain_cap = max(8, max_hits // max(1, len(_DOMAIN_WORDS)))
    total = 0
    printable = re.compile(rb"[ -~]{4,192}")
    content_layer_seen=set()
    def content_layer(artifact, value):
        low=(str(artifact)+" "+str(value)).casefold()
        markers=("streamingassets", "addressable", "assetbundle", "virtualassetbundle", ".lua", "/lua", "luamanager")
        if not any(m in low for m in markers):
            return
        key=(artifact, "script/content-layer")
        if key in content_layer_seen:
            return
        content_layer_seen.add(key)
        hits.append({"artifact":artifact,"kind":"script/content-layer","value":str(value)[:192],"domains":[],"status":"script/content-search"})
    def add(artifact, kind, value):
        value = str(value or "").strip()
        if not value:
            return
        low_art=str(artifact).casefold()
        if any(x in low_art for x in ("managed/resources/system.", "uwawrapper", "unity_builtin_extra")):
            content_layer(artifact, value)
            return
        content_layer(artifact, value)
        ds = _package_domains(value)
        if not ds:
            return
        ds=[d for d in ds if per_domain[d] < domain_cap]
        if not ds:
            return
        key = (artifact, kind, value.casefold())
        if key in seen:
            return
        seen.add(key)
        for d in ds: per_domain[d]+=1
        hits.append({"artifact": artifact, "kind": kind, "value": value[:192], "domains": ds, "status": "package-observed"})

    def scan_zip(z, prefix=""):
        nonlocal total
        for info in z.infolist():
            name = f"{prefix}{info.filename}" if prefix else info.filename
            add(name, "apk-entry", name)
            low = info.filename.casefold()
            candidate = (low.endswith('.dex') or low.endswith(('.json','.txt','.xml','.lua','.bytes','.config','.catalog'))
                         or 'streamingassets/' in low or 'addressable' in low or 'assets/' in low)
            if not candidate or info.file_size <= 0 or info.file_size > max_entry_bytes or total >= max_total_bytes:
                continue
            take = min(info.file_size, max_entry_bytes, max_total_bytes-total)
            try:
                with z.open(info) as f:
                    data = f.read(take)
            except Exception:
                continue
            total += len(data)
            for m in printable.finditer(data):
                try: value = m.group().decode('utf-8', 'ignore')
                except Exception: continue
                if len(value) > 192:
                    continue
                add(name, "dex/string" if low.endswith('.dex') else "content-string", value)

    try:
        with zipfile.ZipFile(path) as outer:
            names=[x.filename for x in outer.infolist()]
            nested_infos=[x for x in outer.infolist() if x.filename.casefold().endswith('.apk')]
            plain = not nested_infos or ('AndroidManifest.xml' in names and any(x.endswith('.dex') or x.startswith('lib/') for x in names))
            if plain:
                scan_zip(outer)
            else:
                import tempfile
                for info in outer.infolist():
                    if total >= max_total_bytes:
                        break
                    if not info.filename.casefold().endswith('.apk') or info.file_size <= 0:
                        continue
                    # Nested APKs require random access. Spool one split at a time to
                    # a temp file instead of retaining a potentially huge APK in RAM.
                    fd, tmp = tempfile.mkstemp(prefix='modkit-split-', suffix='.apk')
                    os.close(fd)
                    try:
                        with outer.open(info) as src, open(tmp, 'wb') as dst:
                            while True:
                                chunk=src.read(1024*1024)
                                if not chunk: break
                                dst.write(chunk)
                        try:
                            with zipfile.ZipFile(tmp) as nested:
                                scan_zip(nested, f"{info.filename}!")
                        except zipfile.BadZipFile:
                            continue
                    finally:
                        try: os.unlink(tmp)
                        except FileNotFoundError: pass
            if len(hits) > max_hits:
                markers=[x for x in hits if x.get("kind")=="script/content-layer"][:32]
                normal=[x for x in hits if x.get("kind")!="script/content-layer"][:max(0,max_hits-len(markers))]
                hits=normal+markers
    except (OSError, zipfile.BadZipFile):
        return []
    return hits


def build_gameplay_coverage(graph_path, fields_path=None, package_evidence=None, output_path=None):
    """Summarize user-facing gameplay entities without creating bindings."""
    graph_path = Path(graph_path)
    fields_path = Path(fields_path) if fields_path else graph_path.with_name("analysis.fields.jsonl")
    domains = {k: {"methods": [], "fields": [], "bridges": [], "package": []} for k in _DOMAIN_WORDS}
    script_content_layer = any((x.get("kind") == "script/content-layer") for x in (package_evidence or []))
    if fields_path.is_file():
        with fields_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                row = json.loads(line)
                for d in row.get("domains") or []:
                    if d in domains and len(domains[d]["fields"]) < 512:
                        domains[d]["fields"].append(row)
    with graph_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            row = json.loads(line)
            infra_label=((row.get("class") or "") + " " + (row.get("name") or "")).casefold()
            if any(x in infra_label for x in ("lua", "addressable", "assetbundle", "virtualassetbundle", "streamingassets")):
                script_content_layer = True
            if _noise((row.get("class") or "") + " " + (row.get("name") or "")):
                continue
            for d in row.get("semanticDomains") or []:
                if d not in domains or not _method_domain_relevant(row, d):
                    continue
                evidence = {
                    "metadataMethodId": row.get("metadataMethodId"), "label": row.get("label"),
                    "rva": row.get("rva"), "isStatic": row.get("isStatic"),
                    "typedFieldAccesses": [x for x in (row.get("typedFieldAccesses") or []) if d in (x.get("domains") or [])][:8],
                    "callers": row.get("callers") or [], "callees": row.get("callees") or [],
                    "applicationOwned": row.get("applicationOwned"),
                }
                bucket = "bridges" if d in (row.get("bridgeDomains") or []) and d not in (row.get("domains") or []) else "methods"
                if len(domains[d][bucket]) < 512:
                    domains[d][bucket].append(evidence)
    for item in package_evidence or []:
        value = item.get("value") or item.get("label") or ""
        if _noise(value):
            continue
        for d in (item.get("domains") or _package_domains(value)):
            if d in domains and len(domains[d]["package"]) < 24:
                domains[d]["package"].append(item)

    for d, bucket in domains.items():
        accessed=set(); meaningful_writes=collections.Counter()
        for m in bucket["methods"] + bucket["bridges"]:
            label=m.get("label") or ""
            init_only=any(x in label for x in ("::.ctor", "::.cctor"))
            for a in m.get("typedFieldAccesses") or []:
                if d in (a.get("domains") or []):
                    key=(a.get("declaringType"),a.get("field"),a.get("fieldOffset"))
                    accessed.add(key)
                    if a.get("access")=="store" and not init_only:
                        meaningful_writes[key]+=1
        bucket["fields"].sort(key=lambda f: (
            -meaningful_writes[(f.get("declaringType"),f.get("name"),f.get("runtimeOffset"))],
            (f.get("declaringType"),f.get("name"),f.get("runtimeOffset")) not in accessed,
            not _owner_gameplay(f.get("declaringType") or ""),
            f.get("declaringType") or "", f.get("runtimeOffset") or 0, f.get("name") or ""))
        def method_rank(m):
            exact=[a for a in (m.get("typedFieldAccesses") or []) if d in (a.get("domains") or [])]
            stores=sum(1 for a in exact if a.get("access")=="store")
            return (-stores, -len(exact), not bool(m.get("applicationOwned")),
                    -(len(m.get("callers") or []) + len(m.get("callees") or [])), m.get("label") or "")
        bucket["methods"].sort(key=method_rank)
        bucket["bridges"].sort(key=method_rank)
        bucket["fields"] = bucket["fields"][:24]
        bucket["methods"] = bucket["methods"][:32]
        bucket["bridges"] = bucket["bridges"][:32]

    labels = {
        "health": "HP / Life-state", "damage": "Damage", "currency": "Currency",
        "progression": "Level / XP", "movement": "Speed / Movement", "resource": "Mana / Energy / Stamina",
        "cooldown": "Cooldowns", "inventory": "Inventory / resources", "camera": "FOV / Camera",
        "world": "World / Time / Weather", "debug": "Debug / Dev surfaces",
    }
    cards = []
    for d in _DOMAIN_WORDS:
        x = domains[d]
        exact_field = bool(x["fields"])
        method_field = any(
            any(d in (a.get("domains") or []) for a in (m.get("typedFieldAccesses") or []))
            for m in x["methods"]
        )
        # CONFIRMED requires an exact typed state access. Name+call-graph alone
        # remains REVIEW; this prevents damage/reward/security/UI surfaces from
        # being promoted merely because they are native and connected.
        confirmed = method_field
        if confirmed:
            status = "CONFIRMED"
        elif exact_field:
            status = "FIELD OBSERVED"
        elif x["package"]:
            status = "PACKAGE OBSERVED"
        elif x["methods"] or x["bridges"]:
            status = "REVIEW"
        elif script_content_layer and d in {"health","damage","currency","progression","resource","inventory","cooldown"}:
            status = "SCRIPT/CONTENT SEARCH"
        else:
            status = "NOT FOUND LOCAL"
        card = {"domain": d, "title": labels[d], "status": status, **x}
        if d == "health":
            card["numericHpSetterAttributed"] = any(
                any(a.get("field") and any(t in set(_tokens(a["field"])) for t in ("health", "hp", "hitpoint"))
                    for a in (m.get("typedFieldAccesses") or [])) for m in x["methods"])
        cards.append(card)
    result = {"schema": _COVERAGE_SCHEMA, "cards": cards,
              "scriptContentLayerDetected": bool(script_content_layer),
              "note": "NOT FOUND LOCAL means no local static attribution; it never means the gameplay entity does not exist.",
              "runtimeTruth": "not-observed-by-static-analysis"}
    if output_path:
        temp = str(output_path) + ".tmp"
        Path(temp).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, output_path)
    return result
