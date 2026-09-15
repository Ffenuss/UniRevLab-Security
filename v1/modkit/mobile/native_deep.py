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
MAX_CONTROL_FLOW = 5000
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
    rows: list[dict[str, Any]] = []
    scanned = 0
    seen: set[tuple[int, str]] = set()
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
            if not domain:
                continue
            file_off = sec.offset + match.start()
            rva = elf.off_to_rva(file_off)
            if rva is None:
                continue
            key = (rva, text[:180])
            if key in seen:
                continue
            seen.add(key)
            rows.append({"text": text[:300], "rva": rva, "section": sec.name, "domain": domain})
            if len(rows) >= MAX_STRING_TARGETS:
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


def _scan_library(apk: Path, entry: str, extracted: Path, cb: Any | None = None) -> dict[str, Any]:
    _check(cb)
    elf = ElfFile.open_mmap(extracted)
    try:
        info = elf.info()
        functions = [s for s in elf.all_symbols(functions_only=True) if s.name and s.value > 0 and s.shndx != 0]
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
        xrefs = arm64_address_xrefs(elf, targets, limit=2500, max_scan_bytes=96 * 1024 * 1024, cb=cb) if targets else []
        _check(cb)

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
                "abi": _abi(entry),
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
                    "abi": _abi(entry),
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
            "abi": _abi(entry),
            "size": extracted.stat().st_size,
            "architecture": info.get("arch"),
            "pie": info.get("pie"),
            "soname": info.get("soname"),
            "needed": info.get("needed") or [],
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
    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    low = info.filename.casefold()
                    if info.is_dir() or not low.endswith(".so") or info.file_size <= 0 or info.file_size > MAX_LIBRARY_BYTES:
                        continue
                    if "/arm64-v8a/" not in "/" + low:
                        continue
                    candidates.append((apk, info))
        except NativeScanCancelled:
            raise
        except Exception as exc:
            if _cancelled(cb):
                raise NativeScanCancelled("native deep scan cancelled") from exc
            errors.append({"apk": apk.name, "error": str(exc)})
    candidates.sort(key=lambda item: (
        0 if Path(item[1].filename).name.casefold() in {"libapp.so", "libil2cpp.so", "libmain.so", "libunity.so", "libcocos2dcpp.so"} else 1,
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
