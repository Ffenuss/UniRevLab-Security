"""Parser for Il2CppDumper's `dump.cs`.

That file is the single most reliable artifact a menu build can start from: it carries
the managed type layout, field offsets, method signatures *and* the RVA of every method
in libil2cpp.so. This parser is deliberately forgiving — dumps from different
Il2CppDumper versions annotate things slightly differently.

Grammar (per line, inside a `{}` block):

    // Image 0: Assembly-CSharp.dll // 0
    // Namespace: Game.Save
    [Serializable]
    public sealed class PlayerData : MonoBehaviour // TypeSize: 0x20
    {
        // Fields
        public Int32 gold; // 0x10
        private static Boolean s_god; // StaticValue: 0x2A4C10, Offset: 0x0

        // Methods
        public Void AddGold(Int32 amount) { } // RVA: 0x1A2B40 Offset: 0x1A2B40 VA: 0x7401A2B40
        public Int32 get_Gold() { } // RVA: 0x1A2C00 ...
        @ 0x18
        public override Void Update() { } // RVA: ...
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from modkit.ir import ClassDef, Field, Method, Param, Program, TypeKind


CLASS_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|private|protected|internal|static|sealed|abstract|readonly|extern|"
    r"unsafe|new)\s+)*?)(?P<kind>class|struct|interface|enum|delegate)\s+"
    r"(?P<name>[A-Za-z0-9_`<>\[\]]+(?:`[0-9]+)?)"
    r"(?:\s*:\s*(?P<base>[A-Za-z0-9_.<>\[\],\s]+?))?\s*"
    r"(?://\s*TypeSize:\s*(?P<size>0x[0-9a-fA-F]+))?\s*$"
)
FIELD_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|private|protected|internal|static|readonly|const|volatile|new)\s+)+)?"
    r"(?P<type>[A-Za-z0-9_.<>\[\],\s?]+?)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:(?P<init>=\s*[^;/]+?)?)\s*;\s*"
    r"(?://\s*(?P<comment>.*))?$"
)
METHOD_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|private|protected|internal|static|virtual|override|abstract|extern|"
    r"unsafe|async|new|sealed)\s+)+)?"
    r"(?P<ret>[A-Za-z0-9_.<>\[\],?]+(?:\s*<[^()]*>)?)"   # allows `Dictionary<string, int>`
    r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\((?P<args>[^)]*)\)\s*(?:\{\s*\})?\s*(?://\s*(?P<comment>.*))?$"
)
IMAGE_RE = re.compile(r"^//\s*Image\s+\d+:\s*(?P<image>[^\s/]+)")
NS_RE = re.compile(r"^//\s*Namespace:\s*(?P<ns>.*)$")
META_VERSION_RE = re.compile(r"^//\s*(?:Metadata Version|global-metadata\.dat version):\s*(?P<v>\d+)")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


@dataclass(slots=True)
class DumpStats:
    classes: int = 0
    methods: int = 0
    fields: int = 0
    addressed_methods: int = 0
    metadata_version: int | None = None
    images: list[str] | None = None
    unpaired_braces: int = 0


class DumpParser:
    def __init__(self) -> None:
        self.stats = DumpStats()

    def parse_file(self, path: str | Path, *, so_name: str = "libil2cpp.so") -> Program:
        return self.parse(Path(path).read_text(encoding="utf-8", errors="replace"), so_name=so_name)

    def parse(self, text: str, *, so_name: str = "libil2cpp.so") -> Program:
        prog = Program(so_name=so_name, source="dump.cs")
        stack: list[ClassDef | None] = []
        current: ClassDef | None = None
        namespace = ""
        image = "Assembly-CSharp.dll"
        pending: list[str] = []

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            stripped = line.strip()

            if not stripped:
                continue
            if (m := IMAGE_RE.match(stripped)):
                image = m.group("image")
                continue
            if (m := META_VERSION_RE.match(stripped)):
                self.stats.metadata_version = prog.metadata_version = int(m.group("v"))
                continue
            if (m := NS_RE.match(stripped)):
                namespace = m.group("ns").strip()
                continue
            if stripped.startswith("//"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                pending.append(stripped)
                continue

            if stripped == "{":
                stack.append(current)
                continue
            if stripped == "}":
                if stack:
                    current = stack.pop()
                    if not stack:
                        current = None            # class body finished
                else:
                    self.stats.unpaired_braces += 1  # stray close: a truncated dump
                continue

            if (cls := self._try_class(stripped, lineno, namespace, image)):
                if current is not None:
                    # nested type: keep the qualified name
                    cls.name = f"{current.name}+{cls.name}"
                    cls.image = current.image
                prog.classes.append(cls)
                self.stats.classes += 1
                current = cls
                pending = []
                continue

            if current is None:
                continue

            if (fld := self._try_field(stripped, current)):
                current.fields.append(fld)
                self.stats.fields += 1
                continue
            if (meth := self._try_method(stripped, current, pending)):
                current.methods.append(meth)
                self.stats.methods += 1
                if meth.rva:
                    self.stats.addressed_methods += 1
                pending = []
                continue
            if (enum := self._try_enum_member(stripped, current)):
                current.enum_values[enum[0]] = enum[1]
                continue

        self.stats.images = prog.images
        return prog

    # ------------------------------------------------------------------ members

    def _try_class(self, line: str, lineno: int, ns: str, image: str) -> ClassDef | None:
        m = CLASS_RE.match(line)
        if not m:
            return None
        mods = m.group("mods") or ""
        raw_name = m.group("name").strip()
        # `Foo<T>` / ``1 / nested `A/B`
        name = re.sub(r"<.*", "", raw_name).replace("/", "+")
        kind = {"class": TypeKind.CLASS, "struct": TypeKind.STRUCT, "interface": TypeKind.INTERFACE,
                "enum": TypeKind.ENUM, "delegate": TypeKind.DELEGATE}[m.group("kind")]
        base = (m.group("base") or "").strip()
        size = m.group("size")
        cls = ClassDef(name=name, namespace=ns, image=image, base=base, kind=kind,
                       type_size=int(size, 16) if size else None, doc_line=lineno)
        if "abstract" in mods:
            cls.base = cls.base or ""
        return cls

    def _try_field(self, line: str, cls: ClassDef) -> Field | None:
        if "{" in line or "(" in line:
            return None
        m = FIELD_RE.match(line)
        if not m:
            return None
        mods = (m.group("mods") or "").split()
        comment = m.group("comment") or ""
        offset = None
        static_value = None
        # dump.cs annotates fields as `// 0x10`, `// Offset: 0x10` or, for statics,
        # `// Offset: 0x0, StaticValue: 0x2A4C10` (the storage rva inside the .so).
        if (mm := re.search(r"StaticValue:\s*(0x[0-9a-fA-F]+)", comment)):
            static_value = int(mm.group(1), 16)
        if (mm := re.search(r"Offset:\s*(0x[0-9a-fA-F]+)", comment)):
            offset = int(mm.group(1), 16)
        elif (mm := re.match(r"^(0x[0-9a-fA-F]+)\s*$", comment.strip())):
            offset = int(mm.group(1), 16)
        ftype = (m.group("type") or "").strip()
        return Field(
            name=m.group("name"),
            type=ftype,
            offset=offset,
            is_static="static" in mods,
            is_literal="const" in mods or "literal" in mods,
            is_private="private" in mods or "internal" in mods,
            static_value=static_value,
            default=(m.group("init") or "").strip().lstrip("=").strip() or None,
        )

    def _try_method(self, line: str, cls: ClassDef, pending: list[str]) -> Method | None:
        if line.endswith(";") or line.startswith("//"):
            return None
        m = METHOD_RE.match(line)
        if not m:
            return None
        mods = (m.group("mods") or "").split()
        comment = m.group("comment") or ""
        rva = offset = va = token = None
        for key in ("RVA", "Offset", "VA", "token"):
            mm = re.search(rf"{key}:\s*(0x[0-9a-fA-F]+)", comment)
            if mm:
                v = int(mm.group(1), 16)
                if key == "RVA":
                    rva = v
                elif key == "Offset":
                    offset = v
                elif key == "VA":
                    va = v
                else:
                    token = v
        if rva is None and offset is not None:
            rva = offset
        name = m.group("name")
        params = self._params(m.group("args") or "")
        is_prop = bool(re.fullmatch(r"(get|set)_[A-Za-z_][A-Za-z0-9_]*", name))
        meth = Method(
            name=name,
            return_type=(m.group("ret") or "System.Void").strip(),
            params=params,
            rva=rva, offset=offset, va=va, token=token,
            is_static="static" in mods,
            is_public="public" in mods or not any(x in mods for x in ("private", "protected", "internal")),
            is_virtual="virtual" in mods or "override" in mods,
            is_abstract="abstract" in mods,
            is_generic="<" in name or any("genparam" in p.lower() for p in pending),
            is_prop_accessor=is_prop,
            declaring=cls.full_name,
        )
        return meth

    @staticmethod
    def _params(text: str) -> list[Param]:
        out: list[Param] = []
        text = text.strip()
        if not text:
            return out
        for chunk in re.split(r",(?![^<]*>)", text):
            chunk = re.sub(r"^(?:ref|out|in|params)\s+", "", chunk.strip())
            chunk = chunk.split("=", 1)[0].strip()
            if not chunk:
                continue
            parts = chunk.rsplit(" ", 1)
            if len(parts) == 2 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parts[1]):
                out.append(Param(name=parts[1], type=parts[0].strip()))
            else:
                out.append(Param(name=f"arg{len(out)}", type=chunk))
        return out

    @staticmethod
    def _try_enum_member(line: str, cls: ClassDef) -> tuple[str, int] | None:
        if cls.kind is not TypeKind.ENUM:
            return None
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)", line)
        return (m.group(1), int(m.group(2))) if m else None


def parse_dump(path: str | Path, **kw) -> Program:
    return DumpParser().parse_file(path, **kw)


def parse_dump_text(text: str, **kw) -> Program:
    return DumpParser().parse(text, **kw)
