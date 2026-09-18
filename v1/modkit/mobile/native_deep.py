"""Embedded deep native analysis for Android ARM64 libraries.

The backend is intentionally static: it parses ELF files, recovers function symbols,
scans direct ARM64 BL edges, tail/thunk control flow, conservative indirect slot calls,
and ADRP+ADD data references. It never executes target code and doesn't need
Ghidra/Rizin or a manual import.
"""
from __future__ import annotations

from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Iterable
import zipfile

from modkit.elf.reader import ElfFile
from modkit.reworkspace.native import arm64_address_xrefs, direct_bl_calls

SCHEMA = "modkit-native-deep-1.1"
ENGINE_ID = "native.deep-embedded"
MAX_LIBRARIES = 64
MAX_LIBRARY_BYTES = 512 * 1024 * 1024
MAX_FUNCTION_ROWS = 1600
MAX_FINDINGS = 1200
MAX_STRING_SCAN_BYTES = 32 * 1024 * 1024
MAX_STRING_TARGETS = 160
MAX_NATIVE_MARKER_TARGETS = 320
MAX_LOOKUP_IDENTIFIER_TARGETS = 320
MAX_CONTROL_FLOW = 5000
MAX_DEX_MARKER_BYTES = 24 * 1024 * 1024
MAX_ASSET_ELF_BYTES = 128 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")

_DOMAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("health", ("health", "hitpoint", "hit_point", "godmode", "god_mode", "immortal", "life")),
    ("damage", ("damage", "dmg", "attackpower", "attack_power", "defense", "armor", "armour")),
    ("speed", ("movespeed", "move_speed", "attackspeed", "attack_speed", "timescale", "time_scale", "speed")),
    ("cooldown", ("cooldown", "cool_down", "recharge", "recast")),
    ("currency", ("currency", "diamond", "gem", "gold", "coin", "wallet", "balance")),
    ("level_xp", ("playerlevel", "player_level", "experience", "level", "xp")),
    ("inventory", ("inventory", "itemcount", "item_count", "reward", "loot", "drop")),
    ("movement", ("movement", "velocity", "gravity", "teleport", "jump")),
    ("mana_energy", ("mana", "stamina", "energy")),
    ("security", ("certificate", "pinning", "keystore", "encrypt", "decrypt", "oauth", "token", "session")),
)


_IL2CPP_LOOKUP_APIS = {
    "il2cpp_domain_get", "il2cpp_domain_get_assemblies", "il2cpp_domain_assembly_open",
    "il2cpp_assembly_get_image", "il2cpp_class_from_name", "il2cpp_class_get_field_from_name",
    "il2cpp_field_get_offset", "il2cpp_field_get_value", "il2cpp_field_set_value",
    "il2cpp_class_get_method_from_name", "il2cpp_class_get_methods", "il2cpp_method_get_name",
    "il2cpp_runtime_invoke", "il2cpp_object_new", "il2cpp_thread_attach",
}
_NATIVE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ptrace-injector", ("ptrace", "ptrace_attach", "ptrace_pokedata", "process_vm_writev",
                         "/proc/%d/maps", "/proc/%d/cmdline", "/proc/self/maps", "remote_dlopen")),
    ("dynamic-loader", ("dlopen", "dlsym", "android_dlopen_ext")),
    ("dobby-hook", ("dobbyhook", "dobbyinstrument", "dobbycodepatch", "dobbysymbolresolver")),
    ("imgui-overlay", ("dear imgui", "imgui::", "imgui_impl_opengl3", "imgui_impl_android")),
    ("egl-overlay", ("eglswapbuffers", "eglmakecurrent", "eglgetcurrentcontext", "anativewindow")),
    ("il2cpp-runtime-api", tuple(sorted(_IL2CPP_LOOKUP_APIS))),
    ("virtual-container-native", ("virtualapp", "sandhook", "nativeengine", "virtualcore")),
)
_DEX_MARKERS: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("virtual-container", (
        b"com/lody/virtual", b"com.lody.virtual", b"NativeEngine", b"VirtualCore",
        b"VirtualApp", b"dualspace", b"multispace",
    )),
    ("root-injector-orchestrator", (
        b"/data/local/tmp/", b"chmod 755", b"libsuperuser", b"su -c",
        b"InjectCezRoot", b"getInjectCommands", b"CopyFilesRoot",
    )),
)


def _marker_tags(text: str) -> list[str]:
    low = str(text or "").casefold()
    out = []
    for tag, needles in _NATIVE_MARKERS:
        if any(str(needle).casefold() in low for needle in needles):
            out.append(tag)
    return out


def _managed_identifier_candidate(text: str) -> bool:
    value = str(text or "").strip()
    if not 2 <= len(value) <= 120 or " " in value or "/" in value or "\\" in value:
        return False
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$+<>\x60-]{1,119}", value):
        return False
    low = value.casefold()
    if low in _IL2CPP_LOOKUP_APIS or low.startswith(("java.", "android.", "kotlin.", "std::")):
        return False
    if low.startswith(("get_", "set_", "m_", "is_", "has_")):
        return True
    if re.search(r"[a-z][A-Z]", value):
        return True
    return bool(_domain(value))


def _lookup_identifier_role(text: str) -> str:
    value = str(text or "")
    low = value.casefold()
    if low.startswith(("get_", "set_")):
        return "method"
    if low.startswith(("m_", "s_")):
        return "field"
    if value and value[0].isupper():
        return "type"
    return "identifier"


class NativeScanCancelled(RuntimeError):
    """Explicit cooperative cancellation; never converted into a backend error row."""


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise NativeScanCancelled("native deep scan cancelled")


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    installed = root / "installed-apks"
    if installed.is_dir():
        for path in sorted(installed.glob("*.apk")):
            if path not in paths:
                paths.append(path)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _domain(text: str) -> str:
    compact = re.sub(r"[^a-z0-9_]", "", text.casefold())
    tokens = set(re.findall(r"[a-z0-9_]+", text.casefold()))
    for name, aliases in _DOMAINS:
        for alias in aliases:
            if alias in tokens or alias.replace("_", "") in compact:
                return name
    return ""


def _abi(entry: str) -> str:
    parts = entry.split("/")
    if len(parts) >= 3 and parts[0].casefold() == "lib":
        return parts[1]
    return "unknown"


def _cache_file(cache: Path, apk: Path, info: zipfile.ZipInfo) -> Path:
    stat = apk.stat()
    identity = f"{apk.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{info.filename}|{info.CRC}|{info.file_size}"
    key = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]
    name = Path(info.filename).name.replace("/", "_") or "library.so"
    return cache / f"{key}-{name}"


def _extract(zf: zipfile.ZipFile, info: zipfile.ZipInfo, apk: Path, cache: Path,
             cb: Any | None = None) -> Path:
    _check(cb)
    cache.mkdir(parents=True, exist_ok=True)
    dest = _cache_file(cache, apk, info)
    if dest.is_file() and dest.stat().st_size == info.file_size:
        return dest
    part = dest.with_suffix(dest.suffix + ".part")
    part.unlink(missing_ok=True)
    try:
        with zf.open(info, "r") as source, part.open("wb") as out:
            while True:
                _check(cb)
                chunk = source.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                out.write(chunk)
        _check(cb)
        if part.stat().st_size != info.file_size:
            raise IOError("native extraction size mismatch")
        part.replace(dest)
        return dest
    except Exception:
        part.unlink(missing_ok=True)
        raise


def _semantic_strings(elf: ElfFile, cb: Any | None = None) -> list[dict[str, Any]]:
    """One bounded non-executable-string pass for gameplay + native architecture evidence."""
    rows: list[dict[str, Any]] = []
    scanned = 0
    seen: set[tuple[int, str]] = set()
    domain_count = marker_count = identifier_count = 0
    for sec in elf.sections:
        _check(cb)
        if sec.type != 1 or sec.is_exec or not sec.is_alloc or sec.size <= 0:
            continue
        if scanned >= MAX_STRING_SCAN_BYTES:
            break
        take = min(sec.size, MAX_STRING_SCAN_BYTES - scanned)
        raw = bytes(memoryview(elf.blob)[sec.offset:sec.offset + take])
        scanned += take
        for no, match in enumerate(PRINTABLE.finditer(raw)):
            if (no & 0xFF) == 0:
                _check(cb)
            text = match.group().decode("utf-8", "replace").strip()
            domain = _domain(text)
            markers = _marker_tags(text)
            identifier = _managed_identifier_candidate(text)
            keep_domain = bool(domain) and domain_count < MAX_STRING_TARGETS
            keep_marker = bool(markers) and marker_count < MAX_NATIVE_MARKER_TARGETS
            keep_identifier = bool(identifier) and identifier_count < MAX_LOOKUP_IDENTIFIER_TARGETS
            if not (keep_domain or keep_marker or keep_identifier):
                continue
            file_off = sec.offset + match.start()
            rva = elf.off_to_rva(file_off)
            if rva is None:
                continue
            key = (rva, text[:180])
            if key in seen:
                continue
            seen.add(key)
            if keep_domain:
                domain_count += 1
            if keep_marker:
                marker_count += 1
            if keep_identifier and not keep_marker:
                identifier_count += 1
            rows.append({
                "text": text[:300], "rva": rva, "section": sec.name,
                "domain": domain if keep_domain else "",
                "markers": markers if keep_marker else [],
                "lookupIdentifier": bool(keep_identifier and not keep_marker),
                "lookupRole": _lookup_identifier_role(text) if keep_identifier and not keep_marker else None,
            })
            if (domain_count >= MAX_STRING_TARGETS
                    and marker_count >= MAX_NATIVE_MARKER_TARGETS
                    and identifier_count >= MAX_LOOKUP_IDENTIFIER_TARGETS):
                return rows
    _check(cb)
    return rows


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm21 = _sign_extend((immhi << 2) | immlo, 21)
    return rd, (pc & ~0xFFF) + (imm21 << 12)


def _decode_add_imm(word: int) -> tuple[int, int, int] | None:
    if word & 0x7F000000 != 0x11000000:
        return None
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    imm12 = (word >> 10) & 0xFFF
    shift = 12 if ((word >> 22) & 1) else 0
    return rd, rn, imm12 << shift


def _decode_ldr_x_unsigned(word: int) -> tuple[int, int, int] | None:
    if word & 0xFFC00000 != 0xF9400000:
        return None
    rt = word & 0x1F
    rn = (word >> 5) & 0x1F
    return rt, rn, ((word >> 10) & 0xFFF) * 8


def _scan_control_flow(elf: ElfFile, functions: list[Any], *, limit: int = MAX_CONTROL_FLOW,
                       max_scan_bytes: int = 128 * 1024 * 1024,
                       cb: Any | None = None) -> list[dict[str, Any]]:
    """Recover conservative ARM64 tail/thunk and indirect-slot control flow.

    Exact target RVAs are emitted only for direct ``B`` or ADRP+ADD+BR sequences.
    ``LDR ...; LDR ...; BLR`` callsites expose registers/slot offsets but intentionally
    keep ``targetRva`` null: static slot recovery is not runtime target resolution.
    """
    if not elf.is_arm64():
        return []
    _check(cb)
    funcs = [s for s in functions if s.name and s.value > 0 and s.shndx != 0]
    funcs.sort(key=lambda s: (s.value, s.name))
    starts = [s.value for s in funcs]
    names = {s.value: s.name for s in funcs}

    def caller_for(rva: int):
        if not starts:
            return None
        i = bisect_right(starts, rva) - 1
        if i < 0:
            return None
        sym = funcs[i]
        if sym.size and rva >= sym.value + sym.size:
            return None
        if not sym.size and i + 1 < len(funcs) and rva >= funcs[i + 1].value:
            return None
        return sym

    def executable(rva: int) -> bool:
        return any(seg.is_exec and seg.vaddr <= rva < seg.vaddr + seg.filesz for seg in elf.segments)

    exec_sections = [sec for sec in elf.sections if sec.is_exec and sec.size and sec.type == 1]
    regions = ([(sec.addr, sec.offset, sec.size) for sec in exec_sections] if exec_sections else
               [(seg.vaddr, seg.offset, seg.filesz) for seg in elf.segments if seg.is_exec and seg.filesz])
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    scanned = 0
    for region_addr, region_offset, region_size in regions:
        _check(cb)
        if scanned >= max_scan_bytes:
            break
        take = min(region_size, max_scan_bytes - scanned) & ~3
        raw = memoryview(elf.blob)[region_offset:region_offset + take]
        scanned += len(raw)
        try:
            for rel in range(0, len(raw), 4):
                if (rel & 0x3FFF) == 0:
                    _check(cb)
                word = struct.unpack_from("<I", raw, rel)[0]
                pc = region_addr + rel
                caller = caller_for(pc)

                # B <known function>: exact inter-function tail edge. Local basic-block
                # branches are deliberately omitted so this isn't mistaken for a CFG.
                if word & 0xFC000000 == 0x14000000:
                    target = pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)
                    target_name = names.get(target)
                    if target_name and (caller is None or caller.value != target):
                        key = ("b", pc, target)
                        if key not in seen:
                            seen.add(key)
                            out.append({
                                "kind": "arm64-direct-b-tail",
                                "callRva": pc,
                                "fileOffset": region_offset + rel,
                                "sourceRva": caller.value if caller else None,
                                "sourceFunction": caller.name if caller else None,
                                "targetRva": target,
                                "targetFunction": target_name,
                                "targetResolution": "EXACT_STATIC",
                            })

                # ADRP Xn; ADD Xn,Xn,#imm; BR Xn: common absolute veneer/thunk.
                if word & 0xFFFFFC1F == 0xD61F0000 and rel >= 8:
                    rn = (word >> 5) & 0x1F
                    add_word = struct.unpack_from("<I", raw, rel - 4)[0]
                    adrp_word = struct.unpack_from("<I", raw, rel - 8)[0]
                    add = _decode_add_imm(add_word)
                    adrp = _decode_adrp(adrp_word, pc - 8)
                    if add and adrp and add[0] == rn and add[1] == rn and adrp[0] == rn:
                        target = adrp[1] + add[2]
                        if executable(target):
                            key = ("absbr", pc, target)
                            if key not in seen:
                                seen.add(key)
                                out.append({
                                    "kind": "arm64-adrp-add-br-thunk",
                                    "callRva": pc,
                                    "sequenceRva": pc - 8,
                                    "fileOffset": region_offset + rel - 8,
                                    "sourceRva": caller.value if caller else None,
                                    "sourceFunction": caller.name if caller else None,
                                    "targetRva": target,
                                    "targetFunction": names.get(target),
                                    "register": rn,
                                    "targetResolution": "EXACT_STATIC",
                                })

                # BLR Xn with an immediately preceding pointer load. We can recover
                # the exact table slot but not the runtime object/vtable contents.
                if word & 0xFFFFFC1F == 0xD63F0000 and rel >= 4:
                    rn = (word >> 5) & 0x1F
                    load = _decode_ldr_x_unsigned(struct.unpack_from("<I", raw, rel - 4)[0])
                    if load and load[0] == rn:
                        base_reg, slot = load[1], load[2]
                        row: dict[str, Any] = {
                            "kind": "arm64-indirect-slot-blr",
                            "callRva": pc,
                            "fileOffset": region_offset + rel,
                            "sourceRva": caller.value if caller else None,
                            "sourceFunction": caller.name if caller else None,
                            "targetRva": None,
                            "targetFunction": None,
                            "callRegister": rn,
                            "tableRegister": base_reg,
                            "slotOffset": slot,
                            "targetResolution": "STRUCTURAL_SLOT_ONLY",
                            "virtualDispatchCandidate": True,
                        }
                        if rel >= 8:
                            parent = _decode_ldr_x_unsigned(struct.unpack_from("<I", raw, rel - 8)[0])
                            if parent and parent[0] == base_reg:
                                row["receiverRegister"] = parent[1]
                                row["tableLoadOffset"] = parent[2]
                        key = ("blr", pc, rn, base_reg, slot)
                        if key not in seen:
                            seen.add(key);out.append(row)

                if len(out) >= max(1, int(limit)):
                    return out
        finally:
            raw.release()
    _check(cb)
    return out


def _architecture_profile(symbol_names: list[str], strings: list[dict[str, Any]], needed: list[str]) -> dict[str, Any]:
    marker_evidence: dict[str, list[str]] = {}
    def add(tag: str, value: str) -> None:
        bucket = marker_evidence.setdefault(tag, [])
        if value and value not in bucket and len(bucket) < 24:
            bucket.append(value)

    for name in symbol_names:
        for tag in _marker_tags(name):
            add(tag, "symbol:" + name)
    for row in strings:
        for tag in row.get("markers") or []:
            add(str(tag), "string:" + str(row.get("text") or ""))
    for lib in needed:
        for tag in _marker_tags(lib):
            add(tag, "needed:" + lib)

    features: list[dict[str, Any]] = []
    tags = set(marker_evidence)
    if "ptrace-injector" in tags and "dynamic-loader" in tags:
        features.append({"kind": "ROOT_OR_EXTERNAL_NATIVE_INJECTOR", "confidence": "HIGH",
                         "evidenceTags": ["ptrace-injector", "dynamic-loader"]})
    elif "ptrace-injector" in tags:
        features.append({"kind": "NATIVE_PROCESS_MANIPULATION", "confidence": "MEDIUM",
                         "evidenceTags": ["ptrace-injector"]})
    if "dobby-hook" in tags:
        features.append({"kind": "DOBBY_HOOK_FRAMEWORK", "confidence": "HIGH",
                         "evidenceTags": ["dobby-hook"]})
    if "imgui-overlay" in tags and "egl-overlay" in tags:
        features.append({"kind": "IMGUI_EGL_OVERLAY", "confidence": "HIGH",
                         "evidenceTags": ["imgui-overlay", "egl-overlay"]})
    elif tags & {"imgui-overlay", "egl-overlay"}:
        features.append({"kind": "NATIVE_OVERLAY_RENDERING", "confidence": "MEDIUM",
                         "evidenceTags": sorted(tags & {"imgui-overlay", "egl-overlay"})})
    if "il2cpp-runtime-api" in tags:
        features.append({"kind": "IL2CPP_RUNTIME_RESOLVER", "confidence": "HIGH",
                         "evidenceTags": ["il2cpp-runtime-api"]})
    if "virtual-container-native" in tags:
        features.append({"kind": "VIRTUAL_CONTAINER_NATIVE_RUNTIME", "confidence": "MEDIUM",
                         "evidenceTags": ["virtual-container-native"]})
    return {"markers": marker_evidence, "features": features}


def _runtime_lookup_chains(strings: list[dict[str, Any]], xrefs: list[dict[str, Any]],
                           calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_target = {int(row["rva"]): row for row in strings if isinstance(row.get("rva"), int)}
    grouped: dict[int, dict[str, Any]] = {}
    for edge in xrefs:
        source = edge.get("sourceRva")
        target = edge.get("targetRva")
        row = by_target.get(int(target)) if isinstance(target, int) else None
        if not isinstance(source, int) or row is None:
            continue
        bucket = grouped.setdefault(source, {
            "sourceRva": source, "sourceFunction": edge.get("sourceFunction"),
            "apiNames": set(), "identifiers": [], "gameplayDomains": set(), "stringXrefs": [],
            "apiCalls": [],
        })
        text = str(row.get("text") or "")
        if "il2cpp-runtime-api" in (row.get("markers") or []):
            low = text.casefold()
            for api in _IL2CPP_LOOKUP_APIS:
                if api in low:
                    bucket["apiNames"].add(api)
        if row.get("lookupIdentifier"):
            ident = {"value": text, "role": row.get("lookupRole") or "identifier",
                     "targetRva": target, "xrefRva": edge.get("xrefRva")}
            if all(x["value"] != text for x in bucket["identifiers"]) and len(bucket["identifiers"]) < 20:
                bucket["identifiers"].append(ident)
        domain = row.get("domain")
        if domain and domain != "security":
            bucket["gameplayDomains"].add(str(domain))
        if len(bucket["stringXrefs"]) < 32:
            bucket["stringXrefs"].append({
                "xrefRva": edge.get("xrefRva"), "targetRva": target, "text": text,
                "domain": domain or None, "markers": row.get("markers") or [],
            })

    for edge in calls:
        source = edge.get("sourceRva")
        target_name = str(edge.get("targetFunction") or "")
        if not isinstance(source, int) or target_name not in _IL2CPP_LOOKUP_APIS:
            continue
        bucket = grouped.setdefault(source, {
            "sourceRva": source, "sourceFunction": edge.get("sourceFunction"),
            "apiNames": set(), "identifiers": [], "gameplayDomains": set(), "stringXrefs": [],
            "apiCalls": [],
        })
        bucket["apiNames"].add(target_name)
        if len(bucket["apiCalls"]) < 16:
            bucket["apiCalls"].append({
                "callRva": edge.get("callRva"), "targetRva": edge.get("targetRva"),
                "targetFunction": target_name,
            })

    out = []
    for source in sorted(grouped):
        row = grouped[source]
        if not row["apiNames"] or not row["identifiers"]:
            continue
        api_names = sorted(row["apiNames"])
        identifiers = row["identifiers"]
        roles = sorted({str(x.get("role") or "identifier") for x in identifiers})
        confidence = "HIGH" if (
            any(api in api_names for api in ("il2cpp_class_from_name", "il2cpp_class_get_field_from_name",
                                             "il2cpp_class_get_method_from_name"))
            and len(identifiers) >= 1
        ) else "MEDIUM"
        out.append({
            "sourceRva": source, "sourceFunction": row.get("sourceFunction"),
            "apiNames": api_names, "candidateIdentifiers": identifiers,
            "candidateRoles": roles, "gameplayDomains": sorted(row["gameplayDomains"]),
            "stringXrefs": row["stringXrefs"], "apiCalls": row["apiCalls"],
            "confidence": confidence,
            "associationStatus": "same-native-function-correlated",
            "exactManagedIdentityConfirmed": False,
            "automationExcluded": True,
        })
        if len(out) >= 160:
            break
    return out


def _container_marker_profile(zf: zipfile.ZipFile, apk: Path, cb: Any | None = None) -> dict[str, Any]:
    found: dict[str, list[str]] = {}
    scanned = 0
    max_marker = max(len(x) for _tag, needles in _DEX_MARKERS for x in needles)

    def note(tag: str, marker: bytes, entry: str) -> None:
        value = marker.decode("utf-8", "replace")
        bucket = found.setdefault(tag, [])
        evidence = f"{entry}:{value}"
        if evidence not in bucket and len(bucket) < 24:
            bucket.append(evidence)

    for info in zf.infolist():
        _check(cb)
        low = info.filename.casefold()
        if info.is_dir() or not (Path(low).name.startswith("classes") and low.endswith(".dex")):
            continue
        if scanned >= MAX_DEX_MARKER_BYTES:
            break
        remaining = min(info.file_size, MAX_DEX_MARKER_BYTES - scanned)
        tail = b""
        with zf.open(info, "r") as source:
            while remaining > 0:
                _check(cb)
                chunk = source.read(min(COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                remaining -= len(chunk); scanned += len(chunk)
                data = tail + chunk
                for tag, needles in _DEX_MARKERS:
                    for marker in needles:
                        if marker.lower() in data.lower():
                            note(tag, marker, info.filename)
                tail = data[-max_marker:] if len(data) > max_marker else data
    features = []
    if len(found.get("virtual-container", [])) >= 2:
        features.append({"kind": "VIRTUAL_CONTAINER_RUNTIME", "confidence": "HIGH",
                         "evidenceTags": ["virtual-container"]})
    if len(found.get("root-injector-orchestrator", [])) >= 2:
        features.append({"kind": "ROOT_INJECTOR_ORCHESTRATOR", "confidence": "HIGH",
                         "evidenceTags": ["root-injector-orchestrator"]})
    return {"apk": apk.name, "dexBytesScanned": scanned, "markers": found, "features": features}


def _scan_library(apk: Path, entry: str, extracted: Path, cb: Any | None = None) -> dict[str, Any]:
    _check(cb)
    elf = ElfFile.open_mmap(extracted)
    try:
        info = elf.info()
        all_symbols = [s for s in elf.all_symbols(functions_only=False) if s.name]
        symbol_names = [s.name for s in all_symbols[:50000]]
        functions = [s for s in all_symbols if getattr(s, "is_function", False) and s.value > 0 and s.shndx != 0]
        functions.sort(key=lambda s: (s.value, s.name))
        function_rows = [
            {"name": s.name, "rva": s.value, "size": s.size, "global": s.is_global}
            for s in functions[:MAX_FUNCTION_ROWS]
        ]
        _check(cb)
        calls = direct_bl_calls(elf, limit=4000, max_scan_bytes=96 * 1024 * 1024, cb=cb)
        _check(cb)
        control_flow = _scan_control_flow(elf, functions, cb=cb)
        exact_extra = [row for row in control_flow if isinstance(row.get("targetRva"), int)]
        indirect = [row for row in control_flow if row.get("kind") == "arm64-indirect-slot-blr"]
        strings = _semantic_strings(elf, cb)
        targets = {int(row["rva"]) for row in strings}
        xrefs = arm64_address_xrefs(elf, targets, limit=4000, max_scan_bytes=96 * 1024 * 1024, cb=cb) if targets else []
        _check(cb)
        needed = info.get("needed") or []
        architecture = _architecture_profile(symbol_names, strings, needed)
        lookup_chains = _runtime_lookup_chains(strings, xrefs, calls)

        callers: dict[int, list[dict[str, Any]]] = {}
        callees: dict[int, list[dict[str, Any]]] = {}
        for edge in [*calls, *exact_extra]:
            src = edge.get("sourceRva")
            dst = edge.get("targetRva")
            if isinstance(src, int):
                callees.setdefault(src, []).append(edge)
            if isinstance(dst, int):
                callers.setdefault(dst, []).append(edge)
        indirect_by_source: dict[int, list[dict[str, Any]]] = {}
        for edge in indirect:
            src = edge.get("sourceRva")
            if isinstance(src, int):
                indirect_by_source.setdefault(src, []).append(edge)
        string_xrefs: dict[int, list[dict[str, Any]]] = {}
        for edge in xrefs:
            target = edge.get("targetRva")
            if isinstance(target, int):
                string_xrefs.setdefault(target, []).append(edge)

        findings: list[dict[str, Any]] = []
        effective_abi = _abi(entry)
        if effective_abi == "unknown" and str(info.get("arch") or "").casefold() in {"aarch64", "arm64"}:
            effective_abi = "arm64-v8a"

        for feature in architecture.get("features") or []:
            kind = str(feature.get("kind") or "NATIVE_ARCHITECTURE")
            findings.append({
                "id": "native-arch:" + hashlib.sha256(f"{apk.name}!{entry}!{kind}".encode()).hexdigest()[:20],
                "kind": kind, "title": kind.replace("_", " ").title(),
                "category": "Runtime/Architecture", "status": "REVIEW",
                "family": "native", "engineId": ENGINE_ID, "apk": apk.name, "entry": entry,
                "library": entry, "abi": effective_abi,
                "confidence": feature.get("confidence"), "architectureEvidence": {
                    tag: architecture.get("markers", {}).get(tag, [])
                    for tag in feature.get("evidenceTags") or []
                },
                "patchReady": False, "automationExcluded": True,
                "runtimeConfirmed": False, "evidenceRole": "native-architecture-profile",
            })

        for chain_no, chain in enumerate(lookup_chains):
            domains = chain.get("gameplayDomains") or []
            title_ids = ", ".join(x.get("value", "") for x in (chain.get("candidateIdentifiers") or [])[:3])
            findings.append({
                "id": "il2cpp-runtime-lookup:" + hashlib.sha256(
                    f"{apk.name}!{entry}!{chain.get('sourceRva')}!{chain_no}".encode()
                ).hexdigest()[:20],
                "kind": "IL2CPP_RUNTIME_LOOKUP_CHAIN",
                "title": "IL2CPP runtime lookup" + (": " + title_ids if title_ids else ""),
                "category": "Gameplay/IL2CPP Runtime Lookup" if domains else "RE/IL2CPP Runtime Lookup",
                "status": "REVIEW", "family": "native", "engineId": ENGINE_ID,
                "apk": apk.name, "entry": entry, "library": entry, "abi": effective_abi,
                "sourceRva": chain.get("sourceRva"), "sourceFunction": chain.get("sourceFunction"),
                "gameplayDomain": domains[0] if len(domains) == 1 else "",
                "gameplayDomains": domains, "runtimeLookup": chain,
                "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                "patchReady": False, "automationExcluded": True,
                "runtimeConfirmed": False, "runtimeTruth": "not-observed-by-static-analysis",
                "evidenceRole": "il2cpp-runtime-lookup-correlation",
            })
            if len(findings) >= MAX_FINDINGS:
                break

        for no, sym in enumerate(functions):
            if (no & 0xFF) == 0:
                _check(cb)
            domain = _domain(sym.name)
            if not domain:
                continue
            inbound = callers.get(sym.value, [])[:40]
            outbound = callees.get(sym.value, [])[:40]
            indirect_calls = indirect_by_source.get(sym.value, [])[:40]
            finding_id = hashlib.sha256(f"{apk.name}!{entry}!fn!{sym.value:x}!{sym.name}".encode()).hexdigest()[:20]
            findings.append({
                "id": "native-fn:" + finding_id,
                "kind": "NATIVE_FUNCTION",
                "title": sym.name,
                "category": "Gameplay/Native" if domain != "security" else "Security/Native",
                "status": "FOUND_STATIC",
                "family": "native",
                "engineId": ENGINE_ID,
                "apk": apk.name,
                "entry": entry,
                "library": entry,
                "abi": effective_abi,
                "function": sym.name,
                "rva": sym.value,
                "size": sym.size,
                "gameplayDomain": "" if domain == "security" else domain,
                "ownershipKind": "APP_OR_GAME",
                "trustBoundary": "local",
                "callers": inbound,
                "callees": outbound,
                "indirectCalls": indirect_calls,
                "patchReady": False,
                "evidenceRole": "embedded-native-function",
            })
            if len(findings) >= MAX_FINDINGS:
                break

        if len(findings) < MAX_FINDINGS:
            for no, row in enumerate(strings):
                if (no & 0x7F) == 0:
                    _check(cb)
                if not row.get("domain"):
                    continue
                refs = string_xrefs.get(int(row["rva"]), [])[:60]
                finding_id = hashlib.sha256(f"{apk.name}!{entry}!str!{row['rva']:x}!{row['text']}".encode("utf-8", "replace")).hexdigest()[:20]
                findings.append({
                    "id": "native-str:" + finding_id,
                    "kind": "NATIVE_STRING_XREF",
                    "title": row["text"][:160],
                    "category": "Gameplay/Native" if row["domain"] != "security" else "Security/Native",
                    "status": "FOUND_STATIC",
                    "family": "native",
                    "engineId": ENGINE_ID,
                    "apk": apk.name,
                    "entry": entry,
                    "library": entry,
                    "abi": effective_abi,
                    "stringRva": row["rva"],
                    "section": row["section"],
                    "gameplayDomain": "" if row["domain"] == "security" else row["domain"],
                    "ownershipKind": "APP_OR_GAME",
                    "trustBoundary": "local",
                    "xrefs": refs,
                    "patchReady": False,
                    "evidenceRole": "embedded-native-string-xref",
                })
                if len(findings) >= MAX_FINDINGS:
                    break

        _check(cb)
        return {
            "apk": apk.name,
            "entry": entry,
            "abi": effective_abi,
            "size": extracted.stat().st_size,
            "architecture": info.get("arch"),
            "pie": info.get("pie"),
            "soname": info.get("soname"),
            "needed": needed,
            "artifactKind": "shared-library" if entry.casefold().endswith(".so") else "asset-elf",
            "architectureProfile": architecture,
            "runtimeLookupChainCount": len(lookup_chains),
            "runtimeLookupChains": lookup_chains,
            "functionSymbolCount": len(functions),
            "functions": function_rows,
            "directCallCount": len(calls),
            "directCalls": calls,
            "controlFlowCount": len(control_flow),
            "controlFlow": control_flow,
            "exactTailThunkCount": len(exact_extra),
            "indirectSlotCallCount": len(indirect),
            "semanticStringCount": len(strings),
            "semanticStrings": strings,
            "addressXrefCount": len(xrefs),
            "addressXrefs": xrefs,
            "findings": findings,
            "status": "ANALYZED",
        }
    finally:
        elf.close()


def scan_apk_paths(paths: Iterable[str | Path], cache_dir: str | Path,
                   output_path: str | Path | None = None, cb: Any | None = None) -> dict[str, Any]:
    cache = Path(cache_dir)
    libraries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    apk_count = 0
    candidates: list[tuple[Path, zipfile.ZipInfo]] = []
    container_profiles: list[dict[str, Any]] = []
    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                container_profiles.append(_container_marker_profile(zf, apk, cb))
                for info in zf.infolist():
                    _check(cb)
                    low = info.filename.casefold()
                    if info.is_dir() or info.file_size <= 0:
                        continue
                    if low.endswith(".so"):
                        if info.file_size > MAX_LIBRARY_BYTES or "/arm64-v8a/" not in "/" + low:
                            continue
                        candidates.append((apk, info))
                        continue
                    if (low.startswith("assets/") and info.file_size <= MAX_ASSET_ELF_BYTES):
                        try:
                            with zf.open(info, "r") as source:
                                if source.read(4) == b"\x7fELF":
                                    candidates.append((apk, info))
                        except Exception:
                            continue
        except NativeScanCancelled:
            raise
        except Exception as exc:
            if _cancelled(cb):
                raise NativeScanCancelled("native deep scan cancelled") from exc
            errors.append({"apk": apk.name, "error": str(exc)})
    candidates.sort(key=lambda item: (
        0 if (Path(item[1].filename).name.casefold() in {"libapp.so", "libil2cpp.so", "libmain.so", "libunity.so", "libcocos2dcpp.so"}
              or any(x in Path(item[1].filename).name.casefold() for x in ("inject", "loader", "exec"))) else 1,
        item[0].name.casefold(), item[1].filename.casefold()))

    for apk, wanted in candidates[:MAX_LIBRARIES]:
        _check(cb)
        try:
            with zipfile.ZipFile(apk) as zf:
                info = zf.getinfo(wanted.filename)
                extracted = _extract(zf, info, apk, cache, cb)
            row = _scan_library(apk, info.filename, extracted, cb)
            libraries.append(row)
            findings.extend(row.get("findings") or [])
            if len(findings) >= MAX_FINDINGS:
                findings = findings[:MAX_FINDINGS]
        except NativeScanCancelled:
            raise
        except Exception as exc:
            if _cancelled(cb):
                raise NativeScanCancelled("native deep scan cancelled") from exc
            errors.append({"apk": apk.name, "entry": wanted.filename, "error": str(exc)})

    for profile in container_profiles:
        for feature in profile.get("features") or []:
            kind = str(feature.get("kind") or "APK_RUNTIME_ARCHITECTURE")
            findings.append({
                "id": "apk-arch:" + hashlib.sha256(f"{profile.get('apk')}!{kind}".encode()).hexdigest()[:20],
                "kind": kind, "title": kind.replace("_", " ").title(),
                "category": "Runtime/Architecture", "status": "REVIEW",
                "family": "apk", "engineId": ENGINE_ID, "apk": profile.get("apk"),
                "confidence": feature.get("confidence"),
                "architectureEvidence": {
                    tag: profile.get("markers", {}).get(tag, [])
                    for tag in feature.get("evidenceTags") or []
                },
                "patchReady": False, "automationExcluded": True,
                "runtimeConfirmed": False, "evidenceRole": "apk-container-architecture-profile",
            })
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            break
    findings = findings[:MAX_FINDINGS]

    _check(cb)
    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "bundled": True,
        "manualImportRequired": False,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "candidateLibraryCount": len(candidates),
        "candidateElfCount": len(candidates),
        "containerProfiles": container_profiles,
        "analyzedLibraryCount": len(libraries),
        "libraryCountTruncated": max(0, len(candidates) - MAX_LIBRARIES),
        "findingCount": len(findings),
        "libraries": libraries,
        "findings": findings,
        "errors": errors[:100],
    }
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), root / "native-deep-cache", output_path, cb)
