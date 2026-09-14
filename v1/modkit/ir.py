"""Intermediate representation shared by the parsers, the analyzer and the codegen."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Iterable, Iterator


SAFE_IDENT = re.compile(r"[^0-9A-Za-z_]")


def c_ident(name: str, prefix: str = "") -> str:
    """Turn a C# symbol into something usable as a C/C++ identifier."""
    out = name
    for a, b in ((".", "_"), ("::", "_"), ("<", "_"), (">", ""), ("`", "_"), ("[", "_"), ("]", ""),
                 (",", "_"), (" ", ""), ("(", "_"), (")", ""), ("+", "_"), ("-", "_"), ("$", "_")):
        out = out.replace(a, b)
    out = SAFE_IDENT.sub("_", out)
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        out = "anon"
    if out[0].isdigit():
        out = "_" + out
    return f"{prefix}{out}" if prefix else out


class TypeKind(str, Enum):
    CLASS = "class"
    STRUCT = "struct"
    INTERFACE = "interface"
    ENUM = "enum"
    DELEGATE = "delegate"
    ARRAY = "array"


class FeatureKind(str, Enum):
    TOGGLE = "toggle"          # bool field / setter flipped on-off
    SLIDER = "slider"          # numeric setter with min/max
    VALUE_SET = "value_set"    # one-shot setter call (button)
    CONST_RETURN = "const_return"  # patch method prologue -> `mov reg, imm; ret`
    FIELD_WRITE = "field_write"    # write into an instance field by offset
    STATIC_WRITE = "static_write"  # write into a static field by absolute RVA
    HOOK = "hook"              # install a native callback (patch-in / patch-out)
    ACTION = "action"          # fire a parameterless method


# --------------------------------------------------------------------------- model


@dataclass(slots=True)
class Param:
    name: str
    type: str


@dataclass(slots=True)
class Field:
    name: str
    type: str
    offset: int | None = None
    is_static: bool = False
    is_literal: bool = False
    is_private: bool = False
    static_value: int | None = None  # `StaticValue: 0x...` in newer dumps (absolute rva of storage)
    default: str | None = None

    @property
    def is_numeric(self) -> bool:
        return self.type in NUMERIC_IL2CPP

    @property
    def is_bool(self) -> bool:
        return self.type in ("System.Boolean", "bool")


NUMERIC_IL2CPP = {
    "System.SByte": 1, "System.Byte": 1,
    "System.Int16": 2, "System.UInt16": 2,
    "System.Int32": 4, "System.UInt32": 4, "System.Boolean": 1, "System.Char": 2,
    "System.Int64": 6, "System.UInt64": 6,
    "System.Single": 4, "System.Double": 8,
    "int": 4, "uint": 4, "long": 8, "ulong": 8, "short": 2, "ushort": 2,
    "byte": 1, "sbyte": 1, "float": 4, "double": 8, "bool": 1, "char": 2,
}

INT_C_TYPE = {
    "System.SByte": "int8_t", "System.Byte": "uint8_t",
    "System.Int16": "int16_t", "System.UInt16": "uint16_t",
    "System.Int32": "int32_t", "System.UInt32": "uint32_t",
    "System.Boolean": "bool", "System.Char": "uint16_t",
    "System.Int64": "int64_t", "System.UInt64": "uint64_t",
    "System.Single": "float", "System.Double": "double",
}
for _k, _v in (("int", "int32_t"), ("uint", "uint32_t"), ("long", "int64_t"), ("ulong", "uint64_t"),
               ("short", "int16_t"), ("ushort", "uint16_t"), ("byte", "uint8_t"), ("sbyte", "int8_t"),
               ("float", "float"), ("double", "double"), ("bool", "bool"), ("char", "uint16_t")):
    INT_C_TYPE.setdefault(_k, _v)


@dataclass(slots=True)
class Method:
    name: str
    return_type: str = "System.Void"
    params: list[Param] = field(default_factory=list)
    rva: int | None = None
    offset: int | None = None
    va: int | None = None
    token: int | None = None
    is_static: bool = False
    is_public: bool = True
    is_virtual: bool = False
    is_abstract: bool = False
    is_generic: bool = False
    is_prop_accessor: bool = False
    declaring: str = ""

    @property
    def addressable(self) -> bool:
        return self.rva not in (None, 0) and not self.is_abstract and not self.is_generic

    @property
    def c_name(self) -> str:
        return c_ident(self.name)

    def signature(self) -> str:
        ps = ", ".join(f"{p.type} {p.name}" for p in self.params)
        mods = "static " if self.is_static else ""
        return f"{mods}{self.return_type} {self.declaring}.{self.name}({ps})"

    def arg_c_types(self) -> list[str]:
        return [INT_C_TYPE.get(p.type, "void*") for p in self.params]


@dataclass(slots=True)
class ClassDef:
    name: str                                   # "PlayerData"
    namespace: str = ""                         # "Game.Save"
    image: str = "Assembly-CSharp.dll"          # which managed assembly
    base: str = ""                              # "UnityEngine.MonoBehaviour"
    kind: TypeKind = TypeKind.CLASS
    type_size: int | None = None
    fields: list[Field] = field(default_factory=list)
    methods: list[Method] = field(default_factory=list)
    enum_values: dict[str, int] = field(default_factory=dict)
    doc_line: int = 0

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name

    @property
    def is_mono(self) -> bool:
        return "MonoBehaviour" in self.base or self.base.endswith("Component")

    def get_field(self, name: str) -> Field | None:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def get_method(self, name: str, *, static_only: bool | None = None) -> Method | None:
        best: Method | None = None
        for m in self.methods:
            if m.name != name:
                continue
            if static_only is not None and m.is_static != static_only:
                continue
            if m.addressable:
                return m
            best = best or m
        return best

    def iter_methods(self) -> Iterator[Method]:
        yield from self.methods

    @property
    def c_slug(self) -> str:
        return c_ident(self.name)


@dataclass(slots=True)
class Program:
    """All managed types discovered from dump.cs / metadata."""

    classes: list[ClassDef] = field(default_factory=list)
    metadata_version: int | None = None
    metadata_image: str | None = None
    so_name: str = "libil2cpp.so"
    source: str = "dump.cs"
    _by_full: dict = field(default_factory=dict, repr=False)
    _by_short: dict = field(default_factory=dict, repr=False)

    def _ensure_index(self) -> None:
        if len(self._by_full) == len(self.classes):
            return
        self._by_full = {}
        self._by_short = {}
        for c in self.classes:
            self._by_full.setdefault(c.full_name, c)
            self._by_short.setdefault(c.name, []).append(c)

    def __post_init__(self) -> None:
        self._ensure_index()

    @property
    def images(self) -> list[str]:
        seen: dict[str, None] = {}
        for c in self.classes:
            seen.setdefault(c.image, None)
        return list(seen)

    def lookup(self, full_name: str) -> ClassDef | None:
        self._ensure_index()
        c = self._by_full.get(full_name)
        if c:
            return c
        # tolerate `PlayerData`, `Game.Save/PlayerData`, `Game.Save.PlayerData`
        alt = full_name.replace("/", ".")
        if (c := self._by_full.get(alt)):
            return c
        short = alt.split(".")[-1]
        cands = self._by_short.get(short) or []
        if len(cands) == 1:
            return cands[0]
        for c in cands:
            if alt.startswith(c.namespace + "."):
                return c
        return cands[0] if cands else None

    def find(self, class_regex: str, method_regex: str | None = None) -> list[tuple[ClassDef, Method | None]]:
        """Yield (class, method) pairs matching the given regexes; method may be None."""
        cre, mre = re.compile(class_regex, re.I), re.compile(method_regex, re.I) if method_regex else None
        out: list[tuple[ClassDef, Method | None]] = []
        for c in self.classes:
            if not (cre.search(c.full_name) or cre.search(c.name)):
                continue
            if mre is None:
                out.append((c, None))
                continue
            for m in c.methods:
                if mre.search(m.name) or mre.search(f"{m.return_type} {m.name}"):
                    out.append((c, m))
        return out

    def user_classes(self) -> Iterable[ClassDef]:
        skip = re.compile(r"^(System\.|UnityEngine\.|UnityEngine|Mono\.|JetBrains\.|Cysharp\.|Google\.|"
                          r"Newtonsoft\.|LiteNetLib|GooglePlayGames|UnityXR|UnityObjects)", re.I)
        for c in self.classes:
            if skip.match(c.full_name):
                continue
            if c.kind in (TypeKind.CLASS, TypeKind.STRUCT) and "Attribute" not in c.name:
                yield c

    def summary(self) -> dict:
        return {
            "classes": len(self.classes),
            "methods": sum(len(c.methods) for c in self.classes),
            "addressed_methods": sum(1 for c in self.classes for m in c.methods if m.addressable),
            "fields": sum(len(c.fields) for c in self.classes),
            "images": self.images,
            "metadata_version": self.metadata_version,
            "source": self.source,
        }


# --------------------------------------------------------------------------- features


@dataclass(slots=True)
class Patch:
    """A byte patch applied to libil2cpp.so at load time."""

    rva: int
    bytes: bytes
    restore: bytes
    note: str = ""

    def to_json(self) -> dict:
        d = asdict(self)
        d["bytes"] = self.bytes.hex()
        d["restore"] = self.restore.hex()
        d["rva"] = f"0x{self.rva:x}"
        return d


@dataclass(slots=True)
class Feature:
    id: str
    label: str
    group: str = "General"
    kind: FeatureKind = FeatureKind.ACTION
    cls: str = ""                       # declaring managed type (full name)
    member: str = ""                    # method or field name
    c_type: str = "void"                # return type of the call / field type
    arg_type: str | None = None         # single argument type (setter / field write)
    value: float | int | bool = 1
    min_value: float = 0
    max_value: float = 1
    rva: int | None = None              # method rva (relative to libil2cpp base)
    field_offset: int | None = None
    is_static: bool = False
    needs_instance: bool = False        # requires `this` discovered by an instance-capture hook
    patch: Patch | None = None
    confidence: float = 0.5
    params: list[str] = field(default_factory=list)   # managed parameter types, in order
    notes: list[str] = field(default_factory=list)
    enabled_by_default: bool = False

    @property
    def key(self) -> str:
        return f"{self.cls}::{self.member}"

    @property
    def swallow(self) -> bool:
        """Hook feature: while enabled, the original body must not run."""
        return "swallow" in self.notes

    @property
    def arg_c_types(self) -> list[str]:
        from modkit.ir import INT_C_TYPE
        return [INT_C_TYPE.get(p, "void*") for p in self.params]

    def to_json(self) -> dict:
        d = {k: v for k, v in asdict(self).items() if k not in ("patch", "kind")}
        d["kind"] = self.kind.value
        d["rva"] = f"0x{self.rva:x}" if self.rva else None
        d["field_offset"] = f"0x{self.field_offset:x}" if self.field_offset else None
        d["patch"] = self.patch.to_json() if self.patch else None
        d["swallow"] = self.swallow
        return d


@dataclass(slots=True)
class InstanceHook:
    """Hook that captures the `this` pointer of a class so features can act on it."""

    cls: str
    method: str
    rva: int
    slot_name: str

    def to_json(self) -> dict:
        d = asdict(self)
        d["rva"] = f"0x{self.rva:x}"
        return d


@dataclass(slots=True)
class Plan:
    """Everything the codegen needs, serialisable for diffing/caching."""

    program: Program
    features: list[Feature] = field(default_factory=list)
    instance_hooks: list[InstanceHook] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    target_package: str | None = None

    def grouped(self) -> dict[str, list[Feature]]:
        out: dict[str, list[Feature]] = {}
        for f in self.features:
            out.setdefault(f.group, []).append(f)
        return out

    def to_json(self, **extra) -> str:
        payload = {
            "generator": "modkit",
            "summary": self.program.summary(),
            "features": [f.to_json() for f in self.features],
            "instance_hooks": [h.to_json() for h in self.instance_hooks],
            "notes": self.notes,
            **extra,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)
