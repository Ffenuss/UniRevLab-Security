"""Embedded deep native analysis for Android ARM64 libraries.

The backend is intentionally static: it parses ELF files, recovers function symbols,
scans direct ARM64 BL edges and conservative ADRP+ADD data references, and records
exact local RVAs where they are known. It never executes target code and doesn't need
Ghidra/Rizin or a manual import.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Iterable
import zipfile

from modkit.elf.reader import ElfFile
from modkit.reworkspace.native import arm64_address_xrefs, direct_bl_calls

SCHEMA = "modkit-native-deep-1.0"
ENGINE_ID = "native.deep-embedded"
MAX_LIBRARIES = 64
MAX_LIBRARY_BYTES = 512 * 1024 * 1024
MAX_FUNCTION_ROWS = 1600
MAX_FINDINGS = 1200
MAX_STRING_SCAN_BYTES = 32 * 1024 * 1024
MAX_STRING_TARGETS = 160
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


def _extract(zf: zipfile.ZipFile, info: zipfile.ZipInfo, apk: Path, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = _cache_file(cache, apk, info)
    if dest.is_file() and dest.stat().st_size == info.file_size:
        return dest
    part = dest.with_suffix(dest.suffix + ".part")
    part.unlink(missing_ok=True)
    with zf.open(info, "r") as source, part.open("wb") as out:
        shutil.copyfileobj(source, out, 1024 * 1024)
    if part.stat().st_size != info.file_size:
        part.unlink(missing_ok=True)
        raise IOError("native extraction size mismatch")
    part.replace(dest)
    return dest


def _semantic_strings(elf: ElfFile) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    scanned = 0
    seen: set[tuple[int, str]] = set()
    for sec in elf.sections:
        if sec.type != 1 or sec.is_exec or not sec.is_alloc or sec.size <= 0:
            continue
        if scanned >= MAX_STRING_SCAN_BYTES:
            break
        take = min(sec.size, MAX_STRING_SCAN_BYTES - scanned)
        raw = bytes(memoryview(elf.blob)[sec.offset:sec.offset + take])
        scanned += take
        for match in PRINTABLE.finditer(raw):
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
    return rows


def _scan_library(apk: Path, entry: str, extracted: Path) -> dict[str, Any]:
    elf = ElfFile.open_mmap(extracted)
    try:
        info = elf.info()
        functions = [s for s in elf.all_symbols(functions_only=True) if s.name and s.value > 0 and s.shndx != 0]
        functions.sort(key=lambda s: (s.value, s.name))
        function_rows = [
            {"name": s.name, "rva": s.value, "size": s.size, "global": s.is_global}
            for s in functions[:MAX_FUNCTION_ROWS]
        ]
        calls = direct_bl_calls(elf, limit=4000, max_scan_bytes=96 * 1024 * 1024)
        strings = _semantic_strings(elf)
        targets = {int(row["rva"]) for row in strings}
        xrefs = arm64_address_xrefs(elf, targets, limit=2500, max_scan_bytes=96 * 1024 * 1024) if targets else []

        callers: dict[int, list[dict[str, Any]]] = {}
        callees: dict[int, list[dict[str, Any]]] = {}
        for edge in calls:
            src = edge.get("sourceRva")
            dst = edge.get("targetRva")
            if isinstance(src, int):
                callees.setdefault(src, []).append(edge)
            if isinstance(dst, int):
                callers.setdefault(dst, []).append(edge)
        string_xrefs: dict[int, list[dict[str, Any]]] = {}
        for edge in xrefs:
            target = edge.get("targetRva")
            if isinstance(target, int):
                string_xrefs.setdefault(target, []).append(edge)

        findings: list[dict[str, Any]] = []
        for sym in functions:
            domain = _domain(sym.name)
            if not domain:
                continue
            inbound = callers.get(sym.value, [])[:40]
            outbound = callees.get(sym.value, [])[:40]
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
                "patchReady": False,
                "evidenceRole": "embedded-native-function",
            })
            if len(findings) >= MAX_FINDINGS:
                break

        if len(findings) < MAX_FINDINGS:
            for row in strings:
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

        return {
            "apk": apk.name,
            "entry": entry,
            "abi": _abi(entry),
            "size": extracted.stat().st_size,
            "architecture": info.get("machine"),
            "pie": info.get("pie"),
            "soname": info.get("soname"),
            "needed": info.get("needed") or [],
            "functionSymbolCount": len(functions),
            "functions": function_rows,
            "directCallCount": len(calls),
            "directCalls": calls,
            "semanticStringCount": len(strings),
            "semanticStrings": strings,
            "addressXrefCount": len(xrefs),
            "addressXrefs": xrefs,
            "findings": findings,
            "status": "ANALYZED",
        }
    finally:
        elf.close()


def scan_apk_paths(paths: Iterable[str | Path], cache_dir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    cache = Path(cache_dir)
    libraries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    apk_count = 0
    candidates: list[tuple[Path, zipfile.ZipInfo]] = []
    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    low = info.filename.casefold()
                    if info.is_dir() or not low.endswith(".so") or info.file_size <= 0 or info.file_size > MAX_LIBRARY_BYTES:
                        continue
                    if "/arm64-v8a/" not in "/" + low:
                        continue
                    candidates.append((apk, info))
        except Exception as exc:
            errors.append({"apk": apk.name, "error": str(exc)})
    candidates.sort(key=lambda item: (
        0 if Path(item[1].filename).name.casefold() in {"libapp.so", "libil2cpp.so", "libmain.so", "libunity.so", "libcocos2dcpp.so"} else 1,
        item[0].name.casefold(), item[1].filename.casefold()))

    for apk, wanted in candidates[:MAX_LIBRARIES]:
        try:
            with zipfile.ZipFile(apk) as zf:
                info = zf.getinfo(wanted.filename)
                extracted = _extract(zf, info, apk, cache)
            row = _scan_library(apk, info.filename, extracted)
            libraries.append(row)
            findings.extend(row.get("findings") or [])
            if len(findings) >= MAX_FINDINGS:
                findings = findings[:MAX_FINDINGS]
        except Exception as exc:
            errors.append({"apk": apk.name, "entry": wanted.filename, "error": str(exc)})

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "bundled": True,
        "manualImportRequired": False,
        "passive": True,
        "executesTargetCode": False,
        "apkCount": apk_count,
        "candidateLibraryCount": len(candidates),
        "analyzedLibraryCount": len(libraries),
        "libraryCountTruncated": max(0, len(candidates) - MAX_LIBRARIES),
        "findingCount": len(findings),
        "libraries": libraries,
        "findings": findings,
        "errors": errors[:100],
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), root / "native-deep-cache", output_path)
