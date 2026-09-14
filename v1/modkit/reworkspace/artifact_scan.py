"""Bounded per-artifact scanners for the generic RE pipeline.

This module owns work which is independent for each APK member.  Correlation
between artifacts intentionally remains in :mod:`modkit.reworkspace.correlate`.
Small immutable artifacts may therefore be scanned concurrently while mmap-backed
or large native objects stay synchronous to preserve the bounded-memory model.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import re
from typing import Any

from modkit.elf.reader import ElfFile
from modkit.reworkspace.dex import DexFile, DexError
from modkit.reworkspace.native import direct_bl_calls, arm64_address_xrefs
from modkit.reworkspace.trust import method_record, surfaces_for_method

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_DEX_CLASS = re.compile(rb"L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+;")

CATEGORY_TERMS = {
    "menu_overlay": ("menu", "overlay", "floating", "windowmanager", "drawmenu", "modmenu"),
    "debug_console": ("console", "debug", "developer", "devmenu", "cheat"),
    "gameplay_controls": (
        "damage", "health", "stamina", "invincible", "godmode", "money", "gold",
        "level", "weather", "noclip", "critical", "crit", "mana", "speed",
    ),
    "monetization_surface": ("purchase", "receipt", "entitlement", "premium", "fullversion", "boughtgame"),
    "hook_framework": ("dobbyhook", "mshookfunction", "a64hook", "shadowhook", "inlinehook", "hookfunction"),
    "il2cpp_surface": ("il2cpp_", "global-metadata", "coderegistration", "metadataregistration"),
    "anti_cheat_surface": ("anticheat", "cheatdetection", "tamperdetection"),
}
_COMPACT_TERMS = {
    "modmenu", "fullversion", "boughtgame", "dobbyhook", "mshookfunction", "a64hook",
    "shadowhook", "inlinehook", "hookfunction", "il2cpp_", "global-metadata",
    "coderegistration", "metadataregistration", "anticheat", "cheatdetection", "tamperdetection",
}


@dataclass(slots=True)
class Evidence:
    artifact: str
    kind: str
    value: str
    location: str = ""


@dataclass(slots=True)
class ArtifactScanResult:
    name: str
    kind: str
    inventory: dict[str, Any]
    evidence: list[Evidence]
    categories: set[str]
    classes: list[str] | None = None
    strings: set[str] | None = None
    trust_rows: list[dict[str, Any]] | None = None
    trust_errors: list[dict[str, Any]] | None = None


def ascii_strings(blob, limit: int = 200_000, chunk_size: int = 4 * 1024 * 1024):
    """Yield printable strings using bounded regex working memory."""
    count = 0
    base = 0
    carry = b""
    carry_start = 0
    n = len(blob)
    while base < n:
        end = min(n, base + max(64 * 1024, int(chunk_size)))
        part = blob[base:end]
        data = carry + part
        data_base = carry_start if carry else base
        carry = b""
        for m in _PRINTABLE.finditer(data):
            if end < n and m.end() == len(data):
                carry = m.group()[-4096:]
                carry_start = data_base + m.end() - len(carry)
                break
            yield data_base + m.start(), m.group().decode("utf-8", "replace")
            count += 1
            if count >= limit:
                return
        base = end
    if carry and count < limit:
        yield carry_start, carry.decode("utf-8", "replace")


def dex_classes(blob, limit: int = 200_000) -> set[str]:
    if not blob.startswith(b"dex\n"):
        return set()
    out = set()
    for m in _DEX_CLASS.finditer(blob):
        out.add(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


def matches(text: str) -> set[str]:
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    words = re.findall(r"[a-z0-9]+", camel.casefold())
    wordset = set(words)
    compact = "".join(words)
    hit = set()
    for category, terms in CATEGORY_TERMS.items():
        for term in terms:
            norm_words = re.findall(r"[a-z0-9]+", term.casefold())
            norm = "".join(norm_words)
            if not norm:
                continue
            if len(norm_words) == 1 and norm in wordset:
                hit.add(category)
                break
            if term in _COMPACT_TERMS and norm in compact:
                hit.add(category)
                break
    return hit


def scan_blob(name: str, blob, kind: str, *, max_strings: int = 200_000) -> tuple[list[Evidence], set[str]]:
    evidence: list[Evidence] = []
    cats: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for off, text in ascii_strings(blob, max_strings):
        for cat in matches(text):
            key = (cat, text)
            if key in seen:
                continue
            seen.add(key)
            cats.add(cat)
            evidence.append(Evidence(name, kind, text[:240], f"file+0x{off:x}"))
            if len(evidence) >= 2000:
                return evidence, cats
    return evidence, cats


def scan_elf(name: str, blob) -> tuple[dict[str, Any], list[Evidence], set[str]]:
    meta: dict[str, Any] = {"name": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    ev, cats = scan_blob(name, blob, "native-string")
    try:
        elf = ElfFile(blob)
        meta.update(elf.info())
        dynamic_symbols = [sym for sym in elf.symbols() if sym.name]
        all_symbols = [sym for sym in elf.all_symbols() if sym.name]
        imports = sorted({sym.name for sym in dynamic_symbols if sym.shndx == 0})
        exports = sorted({sym.name for sym in dynamic_symbols if sym.shndx != 0 and sym.is_global})
        functions = [sym for sym in all_symbols if sym.is_function and sym.shndx != 0]
        jni_exports = [x for x in exports if x == "JNI_OnLoad" or x.startswith("Java_")]
        interesting_apis = (
            "JNI_OnLoad", "RegisterNatives", "dlopen", "android_dlopen_ext", "dlsym",
            "mprotect", "mmap", "eglSwapBuffers", "AMotionEvent_getAction", "ptrace", "fork", "execve",
        )
        api_markers = [api for api in interesting_apis if api in imports or api in exports]
        library_refs = sorted({m.group(0).decode("ascii", "replace") for m in re.finditer(rb"lib[A-Za-z0-9_.+\-]{1,80}\.so", blob)})
        symbol_string_locations = []
        seen_symbol_strings = set()
        rx_identifier = re.compile(rb"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]{2,79}(?![A-Za-z0-9_])")
        for sec in elf.sections:
            if sec.type != 1 or not sec.is_alloc or sec.is_exec or not sec.size:
                continue
            chunk = blob[sec.offset: sec.offset + sec.size]
            for m in rx_identifier.finditer(chunk):
                value = m.group(0).decode("ascii", "replace")
                if value in seen_symbol_strings:
                    continue
                seen_symbol_strings.add(value)
                file_off = sec.offset + m.start()
                rva = elf.off_to_rva(file_off)
                if rva is None:
                    continue
                symbol_string_locations.append({"value": value, "rva": rva, "fileOffset": file_off, "section": sec.name})
                if len(symbol_string_locations) >= 4000:
                    break
            if len(symbol_string_locations) >= 4000:
                break
        symbol_string_refs = sorted(seen_symbol_strings)
        meta["symbolSummary"] = {
            "total": len(all_symbols), "dynamicTotal": len(dynamic_symbols), "functions": len(functions),
            "imports": len(imports), "exports": len(exports),
            "importsSample": imports[:80], "exportsSample": exports[:80],
            "functionSample": [
                {"name": f.name, "rva": f.value, "size": f.size, "global": f.is_global}
                for f in sorted(functions, key=lambda x: (x.value, x.name))[:160]
            ],
        }
        text_size = int(meta.get("text_size") or 0)
        if text_size and text_size <= 32 * 1024 * 1024:
            meta["directFunctionCalls"] = direct_bl_calls(elf, limit=2500, max_scan_bytes=32 * 1024 * 1024)
            string_targets = {int(x["rva"]) for x in symbol_string_locations if isinstance(x.get("rva"), int)}
            meta["stringAddressXrefs"] = arm64_address_xrefs(elf, string_targets, limit=3000, max_scan_bytes=32 * 1024 * 1024)
        else:
            meta["directFunctionCalls"] = []
            meta["stringAddressXrefs"] = []
        meta["jni"] = {
            "exports": jni_exports[:80],
            "hasJniOnLoad": "JNI_OnLoad" in exports,
            "importsRegisterNatives": "RegisterNatives" in imports,
        }
        export_rvas = {}
        retained_exports = set(exports[:800])
        for sym in dynamic_symbols:
            if sym.name in retained_exports and sym.shndx != 0 and sym.is_global and sym.name not in export_rvas:
                export_rvas[sym.name] = sym.value
                if len(export_rvas) >= len(retained_exports):
                    break
        meta["linkingSymbols"] = {"imports": imports[:800], "exports": exports[:800], "exportRvas": export_rvas}
        meta["nativeApiMarkers"] = api_markers
        meta["libraryStringRefs"] = library_refs[:120]
        meta["symbolStringRefs"] = symbol_string_refs
        meta["symbolStringLocations"] = symbol_string_locations
        for sym in all_symbols:
            for cat in matches(sym.name):
                cats.add(cat)
                ev.append(Evidence(name, "native-symbol", sym.name, f"RVA 0x{sym.value:x}"))
        for needed in elf.needed():
            ev.append(Evidence(name, "DT_NEEDED", needed))
    except Exception as exc:
        meta["parseError"] = str(exc)
    return meta, ev, cats


def scan_artifact(name: str, blob) -> ArtifactScanResult:
    """Scan exactly one artifact without consulting any sibling artifact."""
    low = name.lower()
    if low.endswith(".dex") and blob.startswith(b"dex\n"):
        classes = sorted(dex_classes(blob))
        strings = {text for _off, text in ascii_strings(blob, 100_000) if 1 <= len(text) <= 160}
        inventory = {
            "name": name, "size": len(blob), "classes": len(classes),
            "loadLibraryMarker": any(x in strings for x in ("loadLibrary", "System.loadLibrary")),
        }
        ev, cats = scan_blob(name, blob, "dex-string")
        for cls in classes:
            for cat in matches(cls):
                cats.add(cat)
                ev.append(Evidence(name, "dex-class", cls))
        trust_rows: list[dict[str, Any]] = []
        trust_errors: list[dict[str, Any]] = []
        try:
            dex = DexFile(blob)
            scanned = 0
            contextual = 0
            for method in dex.iter_defined_methods():
                scanned += 1
                if scanned > 250_000:
                    break
                for surface in surfaces_for_method(method):
                    trust_rows.append(method_record(method, name, surface))
                    if len(trust_rows) >= 2400:
                        break
                # Preserve the actual method which references interesting DEX
                # strings. A global string-table hit is discovery only; this
                # method-local xref gives the next analysis pass a real Java/Kotlin
                # context without pretending that a native RVA exists.
                if contextual < 800:
                    for value in method.strings:
                        hit = matches(value)
                        if not hit:
                            continue
                        cats.update(hit)
                        ev.append(Evidence(name, "dex-method-string-xref", value[:240],
                                           f"{method.label} @code+0x{method.code_offset:x}"))
                        contextual += 1
                        if contextual >= 800:
                            break
                if len(trust_rows) >= 2400 and contextual >= 800:
                    break
        except (DexError, ValueError, IndexError) as exc:
            trust_errors.append({"artifact": name, "error": str(exc)})
        return ArtifactScanResult(name, "dex", inventory, ev, cats, classes, strings, trust_rows, trust_errors)
    if low.endswith(".so") and blob[:4] == b"\x7fELF":
        meta, ev, cats = scan_elf(name, blob)
        return ArtifactScanResult(name, "native", meta, ev, cats)
    ev, cats = scan_blob(name, blob, "artifact-string", max_strings=50_000)
    return ArtifactScanResult(name, "other", {"name": name, "size": len(blob)}, ev, cats)
