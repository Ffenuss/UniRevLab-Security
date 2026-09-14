"""ELF64 reader for libil2cpp.so (no external deps).

Used for:
  * validating that the .so is arm64 / PIE and listing its DT_NEEDED,
  * rva <-> file offset <-> vaddr translation (patch application),
  * symbol + bytewise pattern search (locating il2cpp API exports,
    embedded metadata blobs, and the code-registration tables),
  * applying a patch plan to a *copy* of the .so for repackaged offline builds.
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from pathlib import Path

EHDR = "<4sBBBBB7xHHIQQQIHHHHHH"
SHDR = "<IIQQQQIIQQ"
PHDR = "<IIQQQQQQ"

EM_AARCH64, EM_ARM = 183, 40
ET_EXEC, ET_DYN = 2, 3

DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_NULL = 1, 5, 10, 14, 0


@dataclass(slots=True)
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int

    @property
    def is_alloc(self) -> bool:
        return bool(self.flags & 0x2)

    @property
    def is_exec(self) -> bool:
        return bool(self.flags & 0x4)

    @property
    def range(self) -> tuple[int, int]:
        return self.offset, self.offset + self.size


@dataclass(slots=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int

    @property
    def is_function(self) -> bool:
        return (self.info & 0xF) == 2

    @property
    def is_global(self) -> bool:
        return (self.info >> 4) == 1


@dataclass(slots=True)
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def is_exec(self) -> bool:
        return bool(self.flags & 1)


class ElfFile:
    def __init__(self, blob: bytes, path: Path | None = None):
        self.blob = blob
        self.path = path
        self._owned_map = None
        self._owned_file = None
        if blob[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if blob[4] != 2:
            raise ValueError("only ELF64 is supported (32-bit .so -> use armv7a menu path)")
        (self.ei_magic, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi,
         self.ei_abi, self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(EHDR, blob, 0)
        self.sections = self._read_sections()
        self.segments = self._read_segments()
        self._by_name = {s.name: s for s in self.sections}

    open = classmethod(lambda cls, path: cls(Path(path).read_bytes(), Path(path)))

    @classmethod
    def open_mmap(cls, path: str | Path) -> "ElfFile":
        """Read-only mmap-backed ELF for large analysis passes.

        Editing workspaces intentionally keep using :meth:`open`, which owns a
        mutable bytes snapshot.  This path is analysis-only and releases both the
        mapping and file descriptor via :meth:`close`.
        """
        p = Path(path)
        fh = p.open("rb")
        mm = None
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            obj = cls(mm, p)
            obj._owned_map = mm
            obj._owned_file = fh
            return obj
        except Exception:
            if mm is not None:
                mm.close()
            fh.close()
            raise

    def close(self) -> None:
        mm, fh = self._owned_map, self._owned_file
        self._owned_map = None
        self._owned_file = None
        if mm is not None:
            mm.close()
        if fh is not None:
            fh.close()

    # ------------------------------------------------------------------ layout

    def _read_sections(self) -> list[Section]:
        names = self._secnames_raw()
        out: list[Section] = []
        for i in range(self.e_shnum):
            (nm, st, fl, addr, off, size, link, info, align, entsize) = struct.unpack_from(
                SHDR, self.blob, self.e_shoff + i * self.e_shentsize)
            out.append(Section(self._cstr(names, nm), st, fl, addr, off, size, link, entsize))
        return out

    def _secnames_raw(self) -> bytes:
        if not self.e_shstrndx or self.e_shstrndx >= self.e_shnum:
            return b""
        off = self.e_shoff + self.e_shstrndx * self.e_shentsize
        _, _, _, addr, soffset, ssize, *_ = struct.unpack_from(SHDR, self.blob, off)
        return self.blob[soffset: soffset + ssize]

    @staticmethod
    def _cstr(table: bytes, index: int) -> str:
        end = table.find(b"\x00", index)
        return table[index:end].decode("ascii", "replace") if index < len(table) else ""

    def _read_segments(self) -> list[Segment]:
        out: list[Segment] = []
        for i in range(self.e_phnum):
            (ptype, pflags, _, poffset, pvaddr, _, pfilesz, pmemsz) = struct.unpack_from(
                PHDR, self.blob, self.e_phoff + i * self.e_phentsize)
            if ptype == 1:  # PT_LOAD
                out.append(Segment(ptype, pflags, poffset, pvaddr, pfilesz, pmemsz))
        return out

    def section(self, name: str) -> Section | None:
        return self._by_name.get(name)

    def is_arm64(self) -> bool:
        return self.e_machine == EM_AARCH64

    @property
    def is_pie(self) -> bool:
        return self.e_type == ET_DYN

    def _dynamic_strings(self, wanted_tag: int) -> list[str]:
        dyn = self.section(".dynamic")
        strtab = self.section(".dynstr")
        if not dyn or not strtab:
            return []
        raw = self.blob[dyn.offset: dyn.offset + dyn.size]
        strs = self.blob[strtab.offset: strtab.offset + strtab.size]
        out: list[str] = []
        for i in range(0, len(raw) - 15, 16):
            tag, val = struct.unpack_from("<QQ", raw, i)
            if tag == DT_NULL:
                break
            if tag == wanted_tag and val < len(strs):
                out.append(self._cstr(strs, val))
        return out

    def needed(self) -> list[str]:
        return self._dynamic_strings(DT_NEEDED)

    def soname(self) -> str | None:
        names = self._dynamic_strings(DT_SONAME)
        return names[0] if names else None

    def add_needed(self, soname: str) -> dict:
        """Conservatively add one DT_NEEDED entry without relocating the ELF.

        This is intentionally an in-place-only transformation for APK repack flows.
        It uses existing slack in ``.dynstr`` and a spare all-zero dynamic entry after
        ``DT_NULL``.  If either condition is absent the method refuses the edit rather
        than moving sections/segments or guessing linker layout.

        Returns an audit record describing the exact bytes/offsets changed.
        """
        if not soname or '/' in soname or '\\' in soname or '\x00' in soname:
            raise ValueError('dependency must be a plain ELF soname')
        encoded = soname.encode('ascii', 'strict') + b'\x00'
        if soname in self.needed():
            return {'changed': False, 'dependency': soname, 'reason': 'already-needed'}

        dyn = self.section('.dynamic')
        strtab = self.section('.dynstr')
        if not dyn or not strtab or dyn.entsize not in (0, 16):
            raise ValueError('ELF has no compatible .dynamic/.dynstr tables')

        # Only consume explicit trailing NUL slack inside the current string table.
        # This keeps DT_STRTAB/DT_STRSZ and all section/segment addresses unchanged.
        strings = self.blob[strtab.offset:strtab.offset + strtab.size]
        trailing = len(strings) - len(strings.rstrip(b'\x00'))
        if trailing < len(encoded):
            raise ValueError(f'.dynstr has only {trailing} trailing zero bytes; {len(encoded)} required')
        str_off = strtab.size - trailing
        if str_off == 0:
            raise ValueError('refusing to replace the mandatory empty dynstr entry')

        raw_dyn = self.blob[dyn.offset:dyn.offset + dyn.size]
        null_slot = None
        for rel in range(0, len(raw_dyn) - 15, 16):
            tag, val = struct.unpack_from('<QQ', raw_dyn, rel)
            if tag == DT_NULL:
                # The replacement consumes this terminator, so another zero entry
                # must remain immediately after it.
                if rel + 32 <= len(raw_dyn) and raw_dyn[rel + 16:rel + 32] == b'\x00' * 16:
                    null_slot = rel
                    break
                raise ValueError('.dynamic has no spare zero entry after DT_NULL')
        if null_slot is None:
            raise ValueError('.dynamic has no DT_NULL terminator')

        view = bytearray(self.blob)
        string_file_off = strtab.offset + str_off
        old_string = bytes(view[string_file_off:string_file_off + len(encoded)])
        view[string_file_off:string_file_off + len(encoded)] = encoded
        dynamic_file_off = dyn.offset + null_slot
        old_dynamic = bytes(view[dynamic_file_off:dynamic_file_off + 16])
        view[dynamic_file_off:dynamic_file_off + 16] = struct.pack('<QQ', DT_NEEDED, str_off)
        self.blob = bytes(view)
        return {
            'changed': True,
            'dependency': soname,
            'dynstrIndex': str_off,
            'stringFileOffset': string_file_off,
            'dynamicFileOffset': dynamic_file_off,
            'oldStringHex': old_string.hex(),
            'newStringHex': encoded.hex(),
            'oldDynamicHex': old_dynamic.hex(),
            'newDynamicHex': struct.pack('<QQ', DT_NEEDED, str_off).hex(),
        }


    def replace_needed_chain(self, dependency: str, *, allowed_victims: tuple[str, ...] =
                             ("liblog.so", "libandroid.so", "libEGL.so", "libGLESv2.so",
                              "libdl.so", "libm.so"), runtime_needed: tuple[str, ...] = ()) -> dict:
        """Replace one direct system DT_NEEDED with a shorter runtime dependency.

        This is a fallback for tightly packed ELF files which have neither dynstr
        nor dynamic-table slack.  It is only safe when the injected runtime itself
        directly depends on the displaced system library, preserving the load graph
        as ``host -> runtime -> original-system-lib``.
        """
        if not dependency or '/' in dependency or '\\' in dependency or '\x00' in dependency:
            raise ValueError('dependency must be a plain ELF soname')
        if dependency in self.needed():
            return {'changed': False, 'strategy': 'needed-chain', 'dependency': dependency,
                    'reason': 'already-needed'}
        dyn = self.section('.dynamic')
        strtab = self.section('.dynstr')
        if not dyn or not strtab:
            raise ValueError('ELF has no .dynamic/.dynstr')
        raw_dyn = self.blob[dyn.offset:dyn.offset + dyn.size]
        strs = self.blob[strtab.offset:strtab.offset + strtab.size]
        runtime_needed = set(runtime_needed)
        candidates = []
        for rel in range(0, len(raw_dyn) - 15, 16):
            tag, val = struct.unpack_from('<QQ', raw_dyn, rel)
            if tag == DT_NULL:
                break
            if tag != DT_NEEDED or val >= len(strs):
                continue
            victim = self._cstr(strs, val)
            if victim not in allowed_victims or victim not in runtime_needed:
                continue
            if len(dependency.encode('ascii')) > len(victim.encode('ascii')):
                continue
            candidates.append((rel, val, victim))
        if not candidates:
            raise ValueError('no allowlisted direct dependency can be safely chained through the runtime')
        # Prefer libraries the runtime explicitly uses for its own functionality.
        priority = {"liblog.so": 0, "libandroid.so": 1, "libEGL.so": 2,
                    "libGLESv2.so": 3, "libdl.so": 4, "libm.so": 5}
        rel, val, victim = min(candidates, key=lambda x: (priority.get(x[2], 99), x[2]))

        # Reject a shared string-table index: changing it must affect only this one
        # dependency tag, never SONAME/RPATH or a symbol name.
        string_tags = {DT_NEEDED, DT_SONAME, 15, 29, 0x7ffffffd, 0x7fffffff}
        refs = []
        for pos in range(0, len(raw_dyn) - 15, 16):
            tag, value = struct.unpack_from('<QQ', raw_dyn, pos)
            if tag == DT_NULL:
                break
            if tag in string_tags and value == val:
                refs.append((pos, tag))
        if refs != [(rel, DT_NEEDED)]:
            raise ValueError(f'{victim} dynstr index is shared by multiple dynamic tags')
        syms, _symstr = self._symtab()
        if syms is not None:
            for i in range(len(syms) // 24):
                nm = struct.unpack_from('<I', syms, i * 24)[0]
                if nm == val:
                    raise ValueError(f'{victim} dynstr index is also referenced by a symbol')

        new = dependency.encode('ascii', 'strict') + b'\x00'
        old_span = len(victim.encode('ascii')) + 1
        file_off = strtab.offset + val
        view = bytearray(self.blob)
        old = bytes(view[file_off:file_off + old_span])
        view[file_off:file_off + old_span] = new + b'\x00' * (old_span - len(new))
        self.blob = bytes(view)
        return {
            'changed': True,
            'strategy': 'needed-chain',
            'dependency': dependency,
            'displacedDependency': victim,
            'dynstrIndex': val,
            'stringFileOffset': file_off,
            'oldStringHex': old.hex(),
            'newStringHex': (new + b'\x00' * (old_span - len(new))).hex(),
        }

    # ------------------------------------------------------------------ address math

    def off_to_rva(self, off: int) -> int | None:
        for seg in self.segments:
            if seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        return None

    def rva_to_off(self, rva: int) -> int | None:
        for seg in self.segments:
            if seg.vaddr <= rva < seg.vaddr + seg.filesz:
                return seg.offset + (rva - seg.vaddr)
        return None

    def read_at_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_off(rva)
        if off is None:
            raise ValueError(f"rva 0x{rva:x} is not inside a PT_LOAD file range")
        return self.blob[off: off + size]

    def write_at_rva(self, rva: int, data: bytes) -> None:
        off = self.rva_to_off(rva)
        if off is None:
            raise ValueError(f"rva 0x{rva:x} is not backed by file data")
        view = bytearray(self.blob)
        view[off: off + len(data)] = data
        self.blob = bytes(view)

    # ------------------------------------------------------------------ symbols / search

    def _symtab(self) -> tuple[bytes, bytes] | tuple[None, None]:
        for name in (".dynsym", ".symtab"):
            sym = self.section(name)
            if sym and sym.link < len(self.sections):
                strtab = self.sections[sym.link]
                return (self.blob[sym.offset: sym.offset + sym.size],
                        self.blob[strtab.offset: strtab.offset + strtab.size])
        return None, None

    def _symbols_from_section(self, name: str) -> list[Symbol]:
        sym = self.section(name)
        if not sym or sym.link >= len(self.sections):
            return []
        strtab = self.sections[sym.link]
        syms = self.blob[sym.offset: sym.offset + sym.size]
        strs = self.blob[strtab.offset: strtab.offset + strtab.size]
        entsize = sym.entsize or 24
        if entsize < 24:
            return []
        out: list[Symbol] = []
        for off in range(0, len(syms) - 23, entsize):
            nm, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", syms, off)
            out.append(Symbol(self._cstr(strs, nm), value, size, info, shndx))
        return out

    def symbols(self, *, functions_only: bool = False) -> list[Symbol]:
        """Return the primary ELF symbol table for backwards compatibility.

        ``.dynsym`` is preferred because it is present in normal stripped Android
        libraries.  Use :meth:`all_symbols` when static/debug symbols from
        ``.symtab`` are useful for reverse-engineering provenance.
        """
        for name in (".dynsym", ".symtab"):
            out = self._symbols_from_section(name)
            if out:
                if functions_only:
                    return [s for s in out if s.is_function and s.is_global]
                return out
        return []

    def all_symbols(self, *, functions_only: bool = False) -> list[Symbol]:
        """Merge ``.dynsym`` and ``.symtab`` without duplicating identical rows."""
        out: list[Symbol] = []
        seen: set[tuple[str, int, int, int, int]] = set()
        for table in (".dynsym", ".symtab"):
            for s in self._symbols_from_section(table):
                if functions_only and not s.is_function:
                    continue
                key = (s.name, s.value, s.size, s.info, s.shndx)
                if key in seen:
                    continue
                seen.add(key)
                out.append(s)
        return out

    def find_symbol(self, name: str) -> Symbol | None:
        for s in self.symbols():
            if s.name == name:
                return s
        return None

    def search(self, pattern: bytes, limit: int | None = None) -> list[int]:
        """Returns RVAs where `pattern` (a bytes literal, no wildcards) occurs."""
        hits: list[int] = []
        for sec in self.sections:
            if not sec.size or sec.type not in (1, 7):  # SHT_PROGBITS / SHT_INIT_ARRAY
                continue
            chunk = self.blob[sec.offset: sec.offset + sec.size]
            start = 0
            while True:
                i = chunk.find(pattern, start)
                if i < 0:
                    break
                hits.append(self.off_to_rva(sec.offset + i) or 0)
                start = i + 1
                if limit and len(hits) >= limit:
                    return hits
        return hits

    def find_metadata_blob(self) -> bytes | None:
        """Locate an embedded global-metadata.dat (games that ship metadata in the .so)."""
        for rva in self.search(b"globalmetadata\x00\x00", limit=4):
            off = self.rva_to_off(rva)
            if off is None:
                continue
            # the metadata file is not compressed; take everything up to the section end
            for sec in self.sections:
                if sec.offset <= off < sec.offset + sec.size:
                    return self.blob[off: sec.offset + sec.size]
        return None

    def find_code_registration(self, metadata_ptr_rva: int) -> list[int]:
        """Heuristic: pointers to the code-registration table are stored in .data.rel.ro
        as `Il2CppCodeRegistration**`; we look for qwords pointing at a region that
        starts with plausible counts (small even numbers) followed by pointer arrays.
        Il2CppDumper does this far more thoroughly — this is only a cross-check."""
        sec = self.section(".data.rel.ro") or self.section(".data")
        if sec is None:
            return []
        raw = self.blob[sec.offset: sec.offset + sec.size]
        hits: list[int] = []
        for i in range(0, len(raw) - 15, 8):
            (ptr,) = struct.unpack_from("<Q", raw, i)
            if self.rva_to_off(ptr) is None or ptr < metadata_ptr_rva:
                continue
            try:
                head = self.read_at_rva(ptr, 8)
            except ValueError:
                continue
            a, b = struct.unpack("<II", head)
            if 1 <= a <= 0x10 and 100 <= b <= 0x2_00000:
                hits.append(self.off_to_rva(sec.offset + i) or 0)
        return hits[:32]

    # ------------------------------------------------------------------ info

    def info(self) -> dict:
        text = self.section(".text")
        return {
            "path": str(self.path) if self.path else "<memory>",
            "arch": {EM_AARCH64: "aarch64", EM_ARM: "arm"}.get(self.e_machine, f"mach-{self.e_machine}"),
            "pie": self.is_pie,
            "entry": f"0x{self.e_entry:x}",
            "text_size": text.size if text else 0,
            "needed": self.needed(),
            "soname": self.soname(),
            "sections": len(self.sections),
            "symbols": len(self.symbols()),
        }
