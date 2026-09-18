"""Architecture-neutral ELF32/ELF64 structural analysis.

This backend is deliberately decoder-independent. It provides trustworthy section,
symbol, dynamic dependency and relocation evidence for ARM32, AArch64, x86 and
x86_64. Instruction CFG/data-flow is left to architecture-specific backends.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-native-portable-1.0"
ENGINE_ID = "native.portable-embedded"
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_LIBRARIES = 96
MAX_SYMBOLS = 12000
MAX_RELOCATIONS = 24000
MAX_FINDINGS = 1800
MAX_INTERESTING_REFS = 1000
MAX_STRINGS_BYTES = 16 * 1024 * 1024
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
ARCH = {EM_386: "x86", EM_ARM: "arm", EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_REL = 9
SHT_DYNSYM = 11
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHN_UNDEF = 0
DT_NULL = 0
DT_NEEDED = 1
DT_SONAME = 14

_INTERESTING_IMPORTS = (
    "dlsym", "dlopen", "android_dlopen_ext", "ptrace", "process_vm_readv",
    "process_vm_writev", "mprotect", "mmap", "munmap", "socket", "connect",
    "send", "recv", "ssl_", "jni_", "java_", "aasset", "anativewindow",
    "egl", "il2cpp_", "mono_", "lua_", "sqlite", "curl_", "open", "read",
    "write", "fopen", "fread", "fwrite",
)

_RELOC_NAMES = {
    EM_ARM: {
        2: "R_ARM_ABS32", 10: "R_ARM_THM_CALL", 21: "R_ARM_GLOB_DAT",
        22: "R_ARM_JUMP_SLOT", 23: "R_ARM_RELATIVE", 28: "R_ARM_CALL",
        29: "R_ARM_JUMP24",
    },
    EM_386: {
        1: "R_386_32", 2: "R_386_PC32", 6: "R_386_GLOB_DAT",
        7: "R_386_JMP_SLOT", 8: "R_386_RELATIVE",
    },
    EM_X86_64: {
        1: "R_X86_64_64", 2: "R_X86_64_PC32", 4: "R_X86_64_PLT32",
        6: "R_X86_64_GLOB_DAT", 7: "R_X86_64_JUMP_SLOT",
        8: "R_X86_64_RELATIVE",
    },
    EM_AARCH64: {
        257: "R_AARCH64_ABS64", 261: "R_AARCH64_PREL32",
        282: "R_AARCH64_JUMP26", 283: "R_AARCH64_CALL26",
        1025: "R_AARCH64_GLOB_DAT", 1026: "R_AARCH64_JUMP_SLOT",
        1027: "R_AARCH64_RELATIVE",
    },
}


class PortableNativeCancelled(RuntimeError):
    pass


@dataclass(slots=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def allocated(self) -> bool:
        return bool(self.flags & SHF_ALLOC)


@dataclass(slots=True)
class Symbol:
    index: int
    table_section: int
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int

    @property
    def bind(self) -> int:
        return self.info >> 4

    @property
    def sym_type(self) -> int:
        return self.info & 0xF

    @property
    def undefined(self) -> bool:
        return self.shndx == SHN_UNDEF


class ElfView:
    def __init__(self, data: bytes):
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        self.data = data
        self.bits = 32 if data[4] == 1 else 64 if data[4] == 2 else 0
        if self.bits not in {32, 64}:
            raise ValueError("unsupported ELF class")
        if data[5] != 1:
            raise ValueError("only little-endian ELF is supported")
        if self.bits == 32:
            vals = struct.unpack_from("<16sHHIIIIIHHHHHH", data, 0)
            (_ident, self.e_type, self.machine, self.e_version, self.entry,
             self.phoff, self.shoff, self.flags, self.ehsize, self.phentsize,
             self.phnum, self.shentsize, self.shnum, self.shstrndx) = vals
        else:
            vals = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
            (_ident, self.e_type, self.machine, self.e_version, self.entry,
             self.phoff, self.shoff, self.flags, self.ehsize, self.phentsize,
             self.phnum, self.shentsize, self.shnum, self.shstrndx) = vals
        self.sections = self._sections()
        self.section_by_name = {row.name: row for row in self.sections}
        self.symbol_tables: dict[int, list[Symbol]] = {}
        self.symbols = self._symbols()
        self.relocations = self._relocations()
        self.needed, self.soname = self._dynamic_names()

    def _raw_section_headers(self) -> list[tuple[int, ...]]:
        out: list[tuple[int, ...]] = []
        fmt = "<IIIIIIIIII" if self.bits == 32 else "<IIQQQQIIQQ"
        expected = struct.calcsize(fmt)
        if self.shentsize < expected or self.shoff <= 0:
            return out
        for idx in range(min(self.shnum, 8192)):
            pos = self.shoff + idx * self.shentsize
            if pos < 0 or pos + expected > len(self.data):
                break
            out.append(struct.unpack_from(fmt, self.data, pos))
        return out

    def _sections(self) -> list[Section]:
        raw = self._raw_section_headers()
        names = b""
        if 0 <= self.shstrndx < len(raw):
            row = raw[self.shstrndx]
            off, size = int(row[4]), int(row[5])
            if 0 <= off <= len(self.data) and 0 <= size <= len(self.data) - off:
                names = self.data[off:off + size]

        def cstr(index: int) -> str:
            if index < 0 or index >= len(names):
                return ""
            end = names.find(b"\0", index)
            if end < 0:
                end = len(names)
            return names[index:end].decode("utf-8", "replace")

        out: list[Section] = []
        for idx, row in enumerate(raw):
            name_idx, stype, flags, addr, off, size, link, info, _align, entsize = row
            if off < 0 or size < 0:
                continue
            out.append(Section(
                idx, cstr(int(name_idx)), int(stype), int(flags), int(addr),
                int(off), int(size), int(link), int(info), int(entsize),
            ))
        return out

    def _slice(self, sec: Section) -> bytes:
        if sec.offset < 0 or sec.size < 0 or sec.offset > len(self.data):
            return b""
        return self.data[sec.offset:min(len(self.data), sec.offset + sec.size)]

    @staticmethod
    def _cstr(table: bytes, index: int) -> str:
        if index < 0 or index >= len(table):
            return ""
        end = table.find(b"\0", index)
        if end < 0:
            end = len(table)
        return table[index:end].decode("utf-8", "replace")

    def _symbols(self) -> list[Symbol]:
        all_rows: list[Symbol] = []
        fmt = "<IIIBBH" if self.bits == 32 else "<IBBHQQ"
        default_ent = struct.calcsize(fmt)
        for sec in self.sections:
            if sec.type not in {SHT_SYMTAB, SHT_DYNSYM}:
                continue
            strtab = next((row for row in self.sections if row.index == sec.link), None)
            strings = self._slice(strtab) if strtab else b""
            raw = self._slice(sec)
            ent = sec.entsize or default_ent
            if ent < default_ent:
                continue
            table: list[Symbol] = []
            count = min(len(raw) // ent, MAX_SYMBOLS)
            for idx in range(count):
                pos = idx * ent
                if self.bits == 32:
                    name_idx, value, size, info, other, shndx = struct.unpack_from(fmt, raw, pos)
                else:
                    name_idx, info, other, shndx, value, size = struct.unpack_from(fmt, raw, pos)
                sym = Symbol(
                    idx, sec.index, self._cstr(strings, int(name_idx)), int(value),
                    int(size), int(info), int(other), int(shndx),
                )
                table.append(sym)
                all_rows.append(sym)
            self.symbol_tables[sec.index] = table
        return all_rows

    def _relocations(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for sec in self.sections:
            if sec.type not in {SHT_REL, SHT_RELA}:
                continue
            symtab = self.symbol_tables.get(sec.link, [])
            raw = self._slice(sec)
            if self.bits == 32:
                fmt = "<II" if sec.type == SHT_REL else "<IIi"
            else:
                fmt = "<QQ" if sec.type == SHT_REL else "<QQq"
            default_ent = struct.calcsize(fmt)
            ent = sec.entsize or default_ent
            if ent < default_ent:
                continue
            target_sec = next((row for row in self.sections if row.index == sec.info), None)
            count = min(len(raw) // ent, MAX_RELOCATIONS - len(out))
            for idx in range(count):
                vals = struct.unpack_from(fmt, raw, idx * ent)
                offset, info = int(vals[0]), int(vals[1])
                addend = int(vals[2]) if len(vals) == 3 else None
                if self.bits == 32:
                    sym_index, rtype = info >> 8, info & 0xFF
                else:
                    sym_index, rtype = info >> 32, info & 0xFFFFFFFF
                symbol = symtab[sym_index] if 0 <= sym_index < len(symtab) else None
                out.append({
                    "relocationSection": sec.name,
                    "targetSection": target_sec.name if target_sec else None,
                    "offset": offset,
                    "type": int(rtype),
                    "typeName": _RELOC_NAMES.get(self.machine, {}).get(int(rtype), f"reloc-{rtype}"),
                    "symbolIndex": int(sym_index),
                    "symbol": symbol.name if symbol else "",
                    "symbolUndefined": bool(symbol.undefined) if symbol else None,
                    "addend": addend,
                })
                if len(out) >= MAX_RELOCATIONS:
                    return out
        return out

    def _dynamic_names(self) -> tuple[list[str], str | None]:
        needed: list[str] = []
        soname: str | None = None
        for sec in self.sections:
            if sec.type != SHT_DYNAMIC:
                continue
            strtab = next((row for row in self.sections if row.index == sec.link), None)
            strings = self._slice(strtab) if strtab else b""
            raw = self._slice(sec)
            fmt = "<iI" if self.bits == 32 else "<qQ"
            ent = sec.entsize or struct.calcsize(fmt)
            if ent < struct.calcsize(fmt):
                continue
            for pos in range(0, len(raw) - struct.calcsize(fmt) + 1, ent):
                tag, value = struct.unpack_from(fmt, raw, pos)
                if tag == DT_NULL:
                    break
                if tag == DT_NEEDED:
                    name = self._cstr(strings, int(value))
                    if name and name not in needed:
                        needed.append(name)
                elif tag == DT_SONAME:
                    value_name = self._cstr(strings, int(value))
                    if value_name:
                        soname = value_name
        return needed, soname


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
        raise PortableNativeCancelled("portable native scan cancelled")


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


def _interesting(name: str) -> bool:
    low = name.casefold()
    return any(token in low for token in _INTERESTING_IMPORTS)


def _abi(entry: str) -> str:
    parts = entry.split("/")
    return parts[1] if len(parts) >= 3 and parts[0].casefold() == "lib" else "asset"


def _marker_strings(view: ElfView) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    budget = MAX_STRINGS_BYTES
    for sec in view.sections:
        if budget <= 0:
            break
        if sec.type != SHT_PROGBITS or sec.executable or not sec.allocated or sec.size <= 0:
            continue
        raw = view._slice(sec)[:budget]
        budget -= len(raw)
        for match in PRINTABLE.finditer(raw):
            text = match.group().decode("utf-8", "replace").strip()
            if not _interesting(text):
                continue
            out.append({
                "section": sec.name,
                "sectionOffset": match.start(),
                "rva": sec.addr + match.start(),
                "text": text[:300],
            })
            if len(out) >= 256:
                return out
    return out


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    libraries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    apk_count = 0
    scanned = 0

    for raw_path in paths:
        _check(cb)
        apk = Path(raw_path)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    if scanned >= MAX_LIBRARIES:
                        break
                    if info.is_dir() or info.file_size < 52 or info.file_size > MAX_LIBRARY_BYTES:
                        continue
                    low = info.filename.casefold()
                    if not (low.endswith(".so") or low.startswith("assets/")):
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_LIBRARY_BYTES + 1)
                    except Exception:
                        continue
                    if data[:4] != b"\x7fELF":
                        continue
                    scanned += 1
                    try:
                        view = ElfView(data)
                    except Exception as exc:
                        libraries.append({
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "status": "UNSUPPORTED_ELF_LAYOUT", "error": str(exc),
                        })
                        continue

                    imports = sorted({
                        sym.name for sym in view.symbols if sym.name and sym.undefined
                    })
                    exports = sorted({
                        sym.name for sym in view.symbols
                        if sym.name and not sym.undefined and sym.bind in {1, 2}
                    })
                    interesting_imports = [name for name in imports if _interesting(name)][:512]
                    relocation_refs = [
                        row for row in view.relocations
                        if row.get("symbol") and _interesting(str(row.get("symbol")))
                    ][:MAX_INTERESTING_REFS]
                    marker_strings = _marker_strings(view)

                    lib = {
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": info.file_size,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "abi": _abi(info.filename),
                        "bits": view.bits,
                        "machine": view.machine,
                        "arch": ARCH.get(view.machine, f"machine-{view.machine}"),
                        "elfType": view.e_type,
                        "entryPoint": view.entry,
                        "soname": view.soname,
                        "needed": view.needed,
                        "sectionCount": len(view.sections),
                        "executableSections": [
                            {"name": sec.name, "addr": sec.addr, "offset": sec.offset, "size": sec.size}
                            for sec in view.sections if sec.executable and sec.size > 0
                        ][:64],
                        "symbolCount": len(view.symbols),
                        "importCount": len(imports),
                        "exportCount": len(exports),
                        "imports": imports[:1024],
                        "exports": exports[:1024],
                        "interestingImports": interesting_imports,
                        "relocationCount": len(view.relocations),
                        "interestingRelocationRefs": relocation_refs,
                        "markerStrings": marker_strings,
                    }
                    libraries.append(lib)

                    findings.append({
                        "id": "portable-elf:" + hashlib.sha256(
                            f"{apk.name}!{info.filename}".encode()
                        ).hexdigest()[:20],
                        "kind": "PORTABLE_ELF_PROFILE",
                        "title": f"{lib['arch']} ELF: {Path(info.filename).name}",
                        "category": "Native/Portable",
                        "status": "FOUND_STATIC",
                        "engineId": ENGINE_ID,
                        **lib,
                        "patchReady": False,
                        "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME",
                        "trustBoundary": "local",
                        "evidenceRole": "portable-elf-profile",
                    })
                    for idx, ref in enumerate(relocation_refs):
                        if len(findings) >= MAX_FINDINGS:
                            break
                        findings.append({
                            "id": "portable-reloc:" + hashlib.sha256(
                                f"{apk.name}!{info.filename}!{idx}!{ref.get('offset')}!{ref.get('symbol')}".encode()
                            ).hexdigest()[:20],
                            "kind": "PORTABLE_RELOCATION_SYMBOL_REF",
                            "title": str(ref.get("symbol")),
                            "category": "Native/Relocation",
                            "status": "CORRELATED_EVIDENCE",
                            "engineId": ENGINE_ID,
                            "apk": apk.name,
                            "entry": info.filename,
                            "arch": lib["arch"],
                            "abi": lib["abi"],
                            **ref,
                            "relocationBacked": True,
                            "patchReady": False,
                            "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME",
                            "trustBoundary": "local",
                            "evidenceRole": "portable-relocation-symbol-reference",
                        })
        except PortableNativeCancelled:
            raise
        except Exception:
            continue

    arch_counts: dict[str, int] = {}
    for row in libraries:
        arch = str(row.get("arch") or "unknown")
        arch_counts[arch] = arch_counts.get(arch, 0) + 1

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "libraryCount": len(libraries),
        "archCounts": dict(sorted(arch_counts.items())),
        "findingCount": len(findings),
        "libraries": libraries,
        "findings": findings,
        "policy": {
            "instructionDecoderUsed": False,
            "cfgClaimed": False,
            "relocationRefsAreExact": True,
            "heuristicByteCallsClaimed": False,
            "patchReadyFromPortableEvidence": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    return scan_apk_paths(_workspace_apks(Path(workdir)), output_path, cb)
