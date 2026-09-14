"""Small dependency-free DEX method/reference reader for static RE correlation.

The reader is intentionally narrow: it indexes class/method/prototype tables and
extracts const-string plus invoke references from method code. It never executes
bytecode and keeps malformed/truncated input bounded.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import struct


class DexError(ValueError):
    pass


def _uleb(blob: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if off >= len(blob):
            raise DexError("truncated ULEB128")
        b = blob[off]
        off += 1
        value |= (b & 0x7f) << shift
        if not (b & 0x80):
            return value, off
        shift += 7
    raise DexError("oversized ULEB128")


def _descriptor(desc: str) -> str:
    arrays = 0
    while desc.startswith("["):
        arrays += 1
        desc = desc[1:]
    names = {
        "V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
        "I": "int", "J": "long", "F": "float", "D": "double",
    }
    out = names.get(desc)
    if out is None and desc.startswith("L") and desc.endswith(";"):
        out = desc[1:-1].replace("/", ".")
    if out is None:
        out = desc
    return out + "[]" * arrays


@dataclass(slots=True)
class DexMethodRef:
    index: int
    cls: str
    name: str
    return_type: str
    parameters: list[str]

    @property
    def label(self) -> str:
        return f"{self.cls}::{self.name}({', '.join(self.parameters)}) -> {self.return_type}"


@dataclass(slots=True)
class DexDefinedMethod:
    index: int
    cls: str
    name: str
    return_type: str
    parameters: list[str]
    access_flags: int
    code_offset: int
    strings: list[str]
    invokes: list[DexMethodRef]

    @property
    def label(self) -> str:
        return f"{self.cls}::{self.name}({', '.join(self.parameters)}) -> {self.return_type}"

    def json(self) -> dict:
        out = asdict(self)
        out["label"] = self.label
        out["invokes"] = [{**asdict(x), "label": x.label} for x in self.invokes]
        return out


class DexFile:
    def __init__(self, blob: bytes):
        if len(blob) < 112 or not blob.startswith(b"dex\n"):
            raise DexError("not a DEX file")
        self.blob = blob
        self._strings = None
        self._types = None
        self._protos = None
        self._methods = None
        self._method_cache = {}
        self._defined = None
        for off, stride, name in (
            (56, 4, "strings"), (64, 4, "types"), (72, 12, "protos"),
            (88, 8, "methods"), (96, 32, "classes"),
        ):
            count, table_off = self._pair(off)
            if count > 5_000_000 or table_off < 0 or table_off + count * stride > len(blob):
                raise DexError(f"invalid {name} table")
            setattr(self, f"{name[:-1] if name.endswith('s') else name}_ids_size", count)
            setattr(self, f"{name[:-1] if name.endswith('s') else name}_ids_off", table_off)
        # Stable names used by the original dev11 source.
        self.string_ids_size, self.string_ids_off = self._pair(56)
        self.type_ids_size, self.type_ids_off = self._pair(64)
        self.proto_ids_size, self.proto_ids_off = self._pair(72)
        self.method_ids_size, self.method_ids_off = self._pair(88)
        self.class_defs_size, self.class_defs_off = self._pair(96)

    def _u16(self, off: int) -> int:
        if off < 0 or off + 2 > len(self.blob):
            raise DexError("truncated u16")
        return struct.unpack_from("<H", self.blob, off)[0]

    def _u32(self, off: int) -> int:
        if off < 0 or off + 4 > len(self.blob):
            raise DexError("truncated u32")
        return struct.unpack_from("<I", self.blob, off)[0]

    def _pair(self, off: int) -> tuple[int, int]:
        return self._u32(off), self._u32(off + 4)

    @property
    def strings(self) -> list[str]:
        if self._strings is not None:
            return self._strings
        out = []
        for i in range(self.string_ids_size):
            p = self._u32(self.string_ids_off + i * 4)
            _n, p = _uleb(self.blob, p)
            end = self.blob.find(b"\0", p, min(len(self.blob), p + 1_048_576))
            if end < 0:
                raise DexError("unterminated string_data_item")
            out.append(self.blob[p:end].decode("utf-8", "replace"))
        self._strings = out
        return out

    @property
    def types(self) -> list[str]:
        if self._types is not None:
            return self._types
        out = []
        for i in range(self.type_ids_size):
            si = self._u32(self.type_ids_off + i * 4)
            if si >= len(self.strings):
                raise DexError("type string index out of range")
            out.append(_descriptor(self.strings[si]))
        self._types = out
        return out

    @property
    def protos(self) -> list[tuple[str, list[str]]]:
        if self._protos is not None:
            return self._protos
        out = []
        for i in range(self.proto_ids_size):
            p = self.proto_ids_off + i * 12
            ret_i = self._u32(p + 4)
            params_off = self._u32(p + 8)
            if ret_i >= len(self.types):
                raise DexError("return type index out of range")
            params = []
            if params_off:
                n = self._u32(params_off)
                if n > 65535 or params_off + 4 + n * 2 > len(self.blob):
                    raise DexError("invalid type_list")
                for j in range(n):
                    ti = self._u16(params_off + 4 + j * 2)
                    if ti >= len(self.types):
                        raise DexError("parameter type index out of range")
                    params.append(self.types[ti])
            out.append((self.types[ret_i], params))
        self._protos = out
        return out

    def method_ref(self, i: int) -> DexMethodRef:
        """Decode one method_id lazily.

        Dev11 materialized the complete method table on the first defined/invoke
        lookup.  Large Unity multidex files can contain well over 100k method_ids,
        which creates a burst of Python objects unrelated to the bounded trust
        surface scan.  Dev16 keeps only a small working cache while preserving the
        public ``methods`` property for callers which explicitly request it.
        """
        if i < 0 or i >= self.method_ids_size:
            raise DexError("method id out of range")
        cached = self._method_cache.get(i)
        if cached is not None:
            return cached
        p = self.method_ids_off + i * 8
        ci, pi, ni = self._u16(p), self._u16(p + 2), self._u32(p + 4)
        if ci >= len(self.types) or pi >= len(self.protos) or ni >= len(self.strings):
            raise DexError("method id out of range")
        ret, args = self.protos[pi]
        row = DexMethodRef(i, self.types[ci], self.strings[ni], ret, list(args))
        # Bounded working set: enough to reuse hot invoke targets without turning
        # a 150k-entry DEX into 150k dataclass/list allocations.
        if len(self._method_cache) >= 8192:
            self._method_cache.clear()
        self._method_cache[i] = row
        return row

    @property
    def methods(self) -> list[DexMethodRef]:
        if self._methods is not None:
            return self._methods
        self._methods = [self.method_ref(i) for i in range(self.method_ids_size)]
        return self._methods

    def _payload_width(self, insns: bytes, unit: int, high: int, total_units: int) -> int:
        byte = unit * 2
        try:
            if high == 1:  # packed-switch-payload
                size = struct.unpack_from("<H", insns, byte + 2)[0]
                return min(total_units - unit, 4 + size * 2)
            if high == 2:  # sparse-switch-payload
                size = struct.unpack_from("<H", insns, byte + 2)[0]
                return min(total_units - unit, 2 + size * 4)
            if high == 3:  # fill-array-data-payload
                width = struct.unpack_from("<H", insns, byte + 2)[0]
                size = struct.unpack_from("<I", insns, byte + 4)[0]
                data_units = (width * size + 1) // 2
                return min(total_units - unit, 4 + data_units)
        except struct.error:
            return 1
        return 1

    @staticmethod
    def _width(op: int) -> int:
        if op in (2, 5, 8, 19, 21, 22, 25, 26, 28, 31, 32, 34, 35, 41):
            return 2
        if 45 <= op <= 61 or 68 <= op <= 109 or 144 <= op <= 175 or 208 <= op <= 226:
            return 2
        if op in (3, 6, 9, 20, 23, 27, 36, 37, 38, 42, 43, 44):
            return 3
        if 110 <= op <= 114 or 116 <= op <= 120:
            return 3
        if op in (252, 253):
            return 3
        if op == 24:
            return 5
        if op in (250, 251):
            return 4
        if op in (254, 255):
            return 2
        return 1

    def _refs(self, code_off: int) -> tuple[list[str], list[DexMethodRef]]:
        if not code_off:
            return [], []
        if code_off < 0 or code_off + 16 > len(self.blob):
            raise DexError("truncated code_item")
        units = self._u32(code_off + 12)
        start = code_off + 16
        end = start + units * 2
        if units > 20_000_000 or end > len(self.blob):
            raise DexError("invalid code_item size")
        insns = self.blob[start:end]
        strings, invokes, seen_s, seen_m = [], [], set(), set()
        u = 0
        while u < units:
            word = struct.unpack_from("<H", insns, u * 2)[0]
            op, high = word & 0xff, word >> 8
            if op == 0 and high in (1, 2, 3):
                u += max(1, self._payload_width(insns, u, high, units)); continue
            idx = None
            if op in (26, 27):  # const-string / jumbo
                if op == 26 and u + 1 < units:
                    idx = struct.unpack_from("<H", insns, (u + 1) * 2)[0]
                elif op == 27 and u + 2 < units:
                    idx = struct.unpack_from("<I", insns, (u + 1) * 2)[0]
                if idx is not None and idx < len(self.strings) and idx not in seen_s:
                    seen_s.add(idx); strings.append(self.strings[idx])
            elif 110 <= op <= 114 or 116 <= op <= 120 or op in (250, 251):
                if u + 1 < units:
                    idx = struct.unpack_from("<H", insns, (u + 1) * 2)[0]
                    if idx < self.method_ids_size and idx not in seen_m:
                        seen_m.add(idx); invokes.append(self.method_ref(idx))
            u += max(1, self._width(op))
        return strings, invokes

    def iter_defined_methods(self):
        """Yield defined methods without retaining every decoded code item."""
        for i in range(self.class_defs_size):
            p = self.class_defs_off + i * 32
            class_idx = self._u32(p)
            data_off = self._u32(p + 24)
            if class_idx >= len(self.types):
                raise DexError("class index out of range")
            if not data_off:
                continue
            p = data_off
            sf, p = _uleb(self.blob, p); inf, p = _uleb(self.blob, p)
            direct, p = _uleb(self.blob, p); virtual, p = _uleb(self.blob, p)
            # Skip encoded fields.
            for _ in range(sf + inf):
                _diff, p = _uleb(self.blob, p); _access, p = _uleb(self.blob, p)
            # DEX class_data encodes direct_methods and virtual_methods as two
            # independent method_idx_diff lists. The running method index MUST restart
            # at zero for the virtual list. Treating both lists as one sequence assigns
            # virtual code_items to unrelated method_ids and contaminates directInvokes.
            for method_count in (direct, virtual):
                method_idx = 0
                for _ in range(method_count):
                    diff, p = _uleb(self.blob, p)
                    access, p = _uleb(self.blob, p)
                    code, p = _uleb(self.blob, p)
                    method_idx += diff
                    if method_idx >= self.method_ids_size:
                        raise DexError("encoded method index out of range")
                    mr = self.method_ref(method_idx)
                    strings, invokes = self._refs(code)
                    yield DexDefinedMethod(method_idx, mr.cls, mr.name, mr.return_type,
                                           list(mr.parameters), access, code, strings, invokes)

    @property
    def defined_methods(self) -> list[DexDefinedMethod]:
        if self._defined is None:
            self._defined = list(self.iter_defined_methods())
        return self._defined

    def find(self, query: str, limit: int = 200) -> list[DexDefinedMethod]:
        q = query.casefold().strip()
        out = []
        source = self.defined_methods if self._defined is not None else self.iter_defined_methods()
        for m in source:
            hay = " ".join([m.label, *m.strings, *(x.label for x in m.invokes)]).casefold()
            if q in hay:
                out.append(m)
                if len(out) >= limit:
                    break
        return out


def inspect_dex(blob: bytes, query: str = "", limit: int = 200) -> dict:
    d = DexFile(blob)
    rows = d.find(query, limit=limit) if query else d.defined_methods[:limit]
    return {
        "strings": len(d.strings), "types": len(d.types), "methods": len(d.methods),
        "definedMethods": len(d.defined_methods), "matches": [x.json() for x in rows],
    }
