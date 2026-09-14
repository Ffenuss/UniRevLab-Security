"""Native reader for ``global-metadata.dat`` (fallback / cross-check path).

The authoritative source for method addresses is Il2CppDumper's ``dump.cs`` — the
runtime method-pointer tables live in ``libil2cpp.so``, not in the metadata file.
This module is used to (a) identify the exact metadata version / Unity release,
(b) recover assembly + type + method *names* when no dumper is available,
(c) pull string literals (useful for finding economy fields by their serialized keys),
(d) sanity-check a dump.cs against the binary it was produced from.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .header import (MAGIC, HeaderInfo, Region, parse_header, score_string_table,
                     UNITY_BY_METADATA)


@dataclass(slots=True)
class TypeDefView:
    """Fields of Il2CppTypeDefinition that matter for name resolution.

    Layout (v24..v31, record size 0x58):
        +0x00 nameIndex  +0x04 namespaceIndex  +0x08 byrefType  +0x0C parentType
        +0x10 elementType  +0x14 genericContainerIndex  +0x18 flags  +0x1C fieldStart
        +0x20 methodStart  ... -0x04 token
    """

    index: int
    name_index: int
    namespace_index: int
    parent: int
    flags: int
    field_start: int
    method_start: int
    token: int

    @property
    def is_sealed(self) -> bool:
        return bool(self.flags & 0x100)

    @property
    def is_abstract(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def visibility(self) -> str:
        vis = {0: "notpublic", 1: "public", 2: "private", 3: "protected",
               4: "internal", 5: "protectedinternal"}
        return vis.get((self.flags >> 1) & 7, "notpublic")


@dataclass(slots=True)
class MethodDefView:
    index: int
    name_index: int
    declaring_type: int
    return_type: int
    parameter_start: int
    token: int
    flags: int
    slot: int
    parameter_count: int

    # MethodReversed/Abstract/Virtual as used by il2cpp's MethodAttributes
    STATIC_BIT = 0x0010
    VIRTUAL_BIT = 0x0040
    ABSTRACT_BIT = 0x0400

    @property
    def is_static(self) -> bool:
        return bool(self.flags & self.STATIC_BIT)

    @property
    def is_virtual(self) -> bool:
        return bool(self.flags & self.VIRTUAL_BIT)

    @property
    def is_abstract(self) -> bool:
        return bool(self.flags & self.ABSTRACT_BIT)

    @property
    def access(self) -> str:
        """MethodAccess: 0 cc, 1 private, 2 fam+assem, 3 family, 4 fam|assem, 5 assem, 6 public."""
        acc = {0: "compilercontrolled", 1: "private", 2: "famandassem", 3: "family",
               4: "famasorassm", 5: "internal", 6: "public"}
        return acc.get(self.flags & 0x0007, "private")


class MetadataFile:
    """Random-access view over a global-metadata.dat blob."""

    def __init__(self, blob: bytes, path: Path | None = None):
        self.blob = blob
        self.path = path
        self.header: HeaderInfo = parse_header(blob)
        self._strtab: Region | None = None
        self._strings: list[str] | None = None

    # ------------------------------------------------------------------ opening

    @classmethod
    def open(cls, path: str | Path) -> "MetadataFile":
        p = Path(path)
        return cls(p.read_bytes(), p)

    @classmethod
    def from_library(cls, elf_path: str | Path) -> "MetadataFile":
        """Some builds ship the metadata *inside* libil2cpp.so (a 'global-metadata' blob)."""
        from modkit.elf.reader import ElfFile
        elf = ElfFile.open(elf_path)
        blob = elf.find_metadata_blob()
        if blob is None:
            raise ValueError(f"no embedded globalmetadata blob in {elf_path}")
        return cls(blob)

    @property
    def version(self) -> int:
        return self.header.version

    @property
    def unity(self) -> str:
        return UNITY_BY_METADATA.get(self.version, "unknown")

    def identify(self) -> dict:
        return {
            "path": str(self.path) if self.path else "<memory>",
            "size": self.header.file_size,
            "magic_ok": self.blob[:len(MAGIC)] == MAGIC,
            "version": self.version,
            "unity": self.unity,
            "schema": "named" if not self.header.inferred else "inferred",
            "regions": len(self.header.regions),
            "images": self.header.record_count("images"),
            "typedefs": self.header.record_count("typeDefinitions"),
            "methods": self.header.record_count("methods"),
            "fields": self.header.record_count("fields"),
        }

    # ------------------------------------------------------------------ strings

    def string_table(self) -> Region:
        if self._strtab is None:
            named = self.header.region("string")
            if named is not None:
                self._strtab = named
            elif self.header.inferred:
                best, best_score = None, 0.0
                for r in self.header.regions:
                    if r.size < 4096:
                        continue
                    if (s := score_string_table(self.blob, r)) > best_score:
                        best, best_score = r, s
                if best is None:
                    raise ValueError("could not infer the string table region")
                self._strtab = Region("string", best.offset, best.size)
            else:
                raise ValueError(f"metadata v{self.version} has no string region in schema")
        return self._strtab

    def strings(self) -> list[str]:
        """Decode the whole string table once (offsets in the tables index into this)."""
        if self._strings is None:
            r = self.string_table()
            chunk = self.blob[r.offset: r.end]
            self._strings = [p.decode("utf-8", "replace") for p in chunk.split(b"\x00")[:-1]]
        return self._strings

    def string_at(self, index: int) -> str:
        s = self.strings()
        return s[index] if 0 <= index < len(s) else ""

    def cstr(self, offset: int) -> str:
        end = self.blob.find(b"\x00", offset)
        return self.blob[offset:end].decode("utf-8", "replace")

    # ------------------------------------------------------------------ records

    def region_bytes(self, name: str) -> bytes:
        r = self.header.region(name)
        if r is None:
            raise KeyError(f"region {name!r} not present")
        return self.blob[r.offset: r.end]

    def type_defs(self) -> list[TypeDefView]:
        """Il2CppTypeDefinition, trimmed to the fields used for name resolution."""
        try:
            raw = self.region_bytes("typeDefinitions")
        except KeyError:
            return []
        rec = 0x58 if self.version >= 24 else 0x54
        out: list[TypeDefView] = []
        for i in range(len(raw) // rec):
            name_index, ns_index, _byref, parent = struct.unpack_from("<4i", raw, i * rec)
            flags, field_start, method_start = struct.unpack_from("<3i", raw, i * rec + 0x18)
            token = struct.unpack_from("<I", raw, i * rec + rec - 4)[0]
            out.append(TypeDefView(i, name_index, ns_index, parent, flags, field_start,
                                   method_start, token))
        return out

    def field_defs(self) -> list[tuple[int, int, int]]:
        """Il2CppFieldDefinition: (nameIndex, typeIndex, token). Types are opaque here."""
        try:
            raw = self.region_bytes("fields")
        except KeyError:
            return []
        out: list[tuple[int, int, int]] = []
        for i in range(len(raw) // 0xC):
            name_index, type_index, token = struct.unpack_from("<iiI", raw, i * 0xC)
            out.append((name_index, type_index, token))
        return out

    def method_defs(self) -> list[MethodDefView]:
        try:
            raw = self.region_bytes("methods")
        except KeyError:
            return []
        rec = 0x20
        out: list[MethodDefView] = []
        for i in range(len(raw) // rec):
            name_index, declaring, return_type, param_start, generic = struct.unpack_from("<5i", raw, i * rec)
            token, flags, iflags, slot, pcount = struct.unpack_from("<IHHHH", raw, i * rec + 20)
            out.append(MethodDefView(i, name_index, declaring, return_type, param_start,
                                     token, flags, slot, pcount))
        return out

    def images(self) -> Iterator[str]:
        """Managed assembly names — the `// Image N: Foo.dll` markers in dump.cs."""
        try:
            raw = self.region_bytes("images")
        except KeyError:
            return
        rec = 0x10
        for i in range(len(raw) // rec):
            name_index = struct.unpack_from("<i", raw, i * rec)[0]
            yield self.string_at(name_index)

    def string_literals(self, limit: int = 4096) -> list[str]:
        """Recover Il2CppStringLiteral entries (UTF-16 payload) — great for save keys."""
        try:
            lits = self.region_bytes("stringLiteral")
            data = self.region_bytes("stringLiteralData")
        except KeyError:
            return []
        out: list[str] = []
        for i in range(min(len(lits) // 8, limit)):
            length, data_index = struct.unpack_from("<Ii", lits, i * 8)
            if length <= 0 or length > 4096 or data_index + length * 2 > len(data):
                continue
            raw = data[data_index: data_index + length * 2]
            try:
                out.append(raw.decode("utf-16-le"))
            except UnicodeDecodeError:
                continue
        return out

    # ------------------------------------------------------------------ IR

    def build_program(self, so_name: str = "libil2cpp.so") -> "Program":
        """Names-only IR: no RVAs (they live in the binary, not in the metadata file).

        Type/field/method ranges follow Il2CppDumper's convention: a type owns the
        records from its own start index up to the next type's start index.
        """
        from modkit.ir import ClassDef, Field, Method, Param, Program, TypeKind

        tds = self.type_defs()
        mds = self.method_defs()
        fds = self.field_defs()
        images = [i for i in self.images()] or [None]

        def type_name(index: int) -> str:
            if 0 <= index < len(tds):
                t = tds[index]
                ns = self.string_at(t.namespace_index)
                nm = self.string_at(t.name_index)
                return f"{ns}.{nm}" if ns else nm
            return ""

        classes: list[ClassDef] = []
        for i, td in enumerate(tds):
            m_end = tds[i + 1].method_start if i + 1 < len(tds) else len(mds)
            f_end = tds[i + 1].field_start if i + 1 < len(fds) and i + 1 < len(tds) else len(fds)
            ns = self.string_at(td.namespace_index)
            name = self.string_at(td.name_index) or f"anon_{i}"
            cls = ClassDef(name=name, namespace=ns, base=type_name(td.parent),
                           kind=TypeKind.CLASS, image=images[0] or "Assembly-CSharp.dll")
            for mi in range(td.method_start, min(m_end, len(mds))):
                md = mds[mi]
                if md.declaring_type != i:
                    continue
                cls.methods.append(Method(
                    name=self.string_at(md.name_index) or f"method_{mi}",
                    return_type="System.Void",
                    params=[Param(name=f"arg{n}", type="System.Object")
                            for n in range(md.parameter_count)],
                    token=md.token,
                    is_static=bool(md.flags & 0x10),
                    is_public=md.access == "public",
                    is_virtual=bool(md.flags & 0x40),
                    declaring=cls.full_name,
                ))
            for fi in range(td.field_start, min(f_end, len(fds))):
                name_index, type_index, _tok = fds[fi]
                cls.fields.append(Field(name=self.string_at(name_index) or f"field_{fi}",
                                        type=type_name(type_index) or "System.Object"))
            classes.append(cls)

        prog = Program(classes=classes, metadata_version=self.version, so_name=so_name,
                       source=f"global-metadata.dat v{self.version}")
        return prog

    # ------------------------------------------------------------------ checks

    def cross_check(self, dump_stats: dict) -> list[str]:
        """Compare dump.cs counts against the metadata tables; returns human notes."""
        notes: list[str] = []
        if (mv := self.version) and (dv := dump_stats.get("metadata_version")) not in (None, mv):
            notes.append(f"metadata v{mv} but dump.cs claims v{dv} — they are from different builds")
        if (td := self.header.record_count("typeDefinitions")) and td:
            got = dump_stats.get("classes", 0)
            if got and abs(got - td) / max(td, 1) > 0.25:
                notes.append(f"dump.cs has {got} types, metadata declares ~{td} — partial or stale dump")
        if (md := self.header.record_count("methods")) and md:
            got = dump_stats.get("methods", 0)
            if got and abs(got - md) / max(md, 1) > 0.25:
                notes.append(f"dump.cs has {got} methods, metadata declares ~{md}")
        return notes
