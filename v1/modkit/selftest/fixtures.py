"""Synthetic target used by `modkit selftest` and the unit tests.

Everything here is fabricated: a small Unity-style Il2Cpp game ("NeonDrift") as a
`global-metadata.dat`, a matching `dump.cs` and an ELF64 `libil2cpp.so` whose `.text`
really contains a stub at every advertised RVA. It exists so the whole pipeline
(parse → analyze → generate → verify → apply) can be exercised without a device.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from modkit.metadata.header import MAGIC, SANITY, SCHEMAS

TEXT_VADDR = 0x200
TEXT_SIZE = 0x4000
DATA_VADDR = 0x5000
DATA_SIZE = 0x200


@dataclass(slots=True)
class FxMethod:
    name: str
    ret: str = "System.Void"
    params: tuple[tuple[str, str], ...] = ()
    rva: int = 0
    is_static: bool = False
    is_public: bool = True


@dataclass(slots=True)
class FxField:
    name: str
    type: str
    offset: int = 0
    is_static: bool = False
    static_rva: int = 0
    is_private: bool = False


@dataclass(slots=True)
class FxClass:
    name: str
    namespace: str = ""
    base: str = "UnityEngine.MonoBehaviour"
    image: str = "Assembly-CSharp.dll"
    type_size: int = 0x20
    fields: list[FxField] = field(default_factory=list)
    methods: list[FxMethod] = field(default_factory=list)


def neon_drift() -> list[FxClass]:
    return [
        FxClass("PlayerSave", "NeonDrift.Save", "UnityEngine.ScriptableObject", type_size=0x28,
                fields=[FxField("gold", "System.Int32", 0x10), FxField("gems", "System.Int32", 0x14),
                        FxField("level", "System.Int32", 0x18),
                        FxField("s_debugUnlocks", "System.Boolean", 0, is_static=True,
                                static_rva=DATA_VADDR + 0x10)],
                methods=[FxMethod(".ctor", "System.Void"),
                         FxMethod("get_Gold", "System.Int32", (), 0x1040),
                         FxMethod("set_Gold", "System.Void", (("value", "System.Int32"),), 0x1050),
                         FxMethod("get_Gems", "System.Int32", (), 0x1060),
                         FxMethod("set_Gems", "System.Void", (("value", "System.Int32"),), 0x1070),
                         FxMethod("get_Level", "System.Int32", (), 0x1080),
                         FxMethod("set_Level", "System.Void", (("value", "System.Int32"),), 0x1090),
                         FxMethod("Save", "System.Void", (), 0x10A0)]),
        FxClass("PlayerController", "NeonDrift.Play", "UnityEngine.MonoBehaviour",
                fields=[FxField("moveSpeed", "System.Single", 0x20),
                        FxField("currentHealth", "System.Single", 0x24),
                        FxField("maxHealth", "System.Single", 0x28),
                        FxField("jumpsLeft", "System.Int32", 0x2C),
                        FxField("isGodMode", "System.Boolean", 0x30)],
                methods=[FxMethod("Update", "System.Void", (), 0x1100),
                         FxMethod("TakeDamage", "System.Void", (("amount", "System.Single"),), 0x1110),
                         FxMethod("get_MoveSpeed", "System.Single", (), 0x1120),
                         FxMethod("set_MoveSpeed", "System.Void", (("value", "System.Single"),), 0x1130),
                         FxMethod("set_IsGodMode", "System.Void", (("value", "System.Boolean"),), 0x1140),
                         FxMethod("get_IsGodMode", "System.Boolean", (), 0x1150),
                         FxMethod("Jump", "System.Void", (), 0x1160)]),
        FxClass("Weapon", "NeonDrift.Play", "UnityEngine.MonoBehaviour",
                fields=[FxField("ammo", "System.Int32", 0x18), FxField("magSize", "System.Int32", 0x1C),
                        FxField("recoil", "System.Single", 0x20), FxField("cooldown", "System.Single", 0x24)],
                methods=[FxMethod("Update", "System.Void", (), 0x1200),
                         FxMethod("get_Ammo", "System.Int32", (), 0x1210),
                         FxMethod("set_Ammo", "System.Void", (("value", "System.Int32"),), 0x1220),
                         FxMethod("GetDamage", "System.Single", (), 0x1230),
                         FxMethod("GetCooldown", "System.Single", (), 0x1240),
                         FxMethod("Fire", "System.Boolean", (("mode", "System.Int32"),), 0x1250)]),
        FxClass("EnemySpawner", "NeonDrift.Play", "UnityEngine.MonoBehaviour",
                fields=[FxField("waveIndex", "System.Int32", 0x18)],
                methods=[FxMethod("Update", "System.Void", (), 0x1300),
                         FxMethod("Spawn", "System.Void", (("kind", "System.Int32"),), 0x1310),
                         FxMethod("SkipLevel", "System.Void", (), 0x1320)]),
        FxClass("GameOptions", "NeonDrift.Save", "UnityEngine.Object",
                fields=[FxField("unlockedAllTracks", "System.Boolean", 0x18),
                        FxField("coins", "System.Int32", 0x1C)],
                methods=[FxMethod("get_Coins", "System.Int32", (), 0x1400),
                         FxMethod("set_Coins", "System.Void", (("value", "System.Int32"),), 0x1410),
                         FxMethod("UnlockAllTracks", "System.Void", (), 0x1420)]),
        # engine noise: must never produce features
        FxClass("MonoBehaviour", "UnityEngine", "UnityEngine.Component", image="UnityEngine.dll",
                methods=[FxMethod("Update", "System.Void"), FxMethod(".ctor", "System.Void")]),
        FxClass("StringBuilder", "System.Text", "System.Object", image="mscorlib.dll",
                fields=[FxField("m_ChunkChars", "System.Char[]", 0x18)],
                methods=[FxMethod("Append", "System.Text.StringBuilder", (("s", "System.String"),), 0x1500)]),
    ]


# --------------------------------------------------------------------------- dump.cs


def dump_text(classes: list[FxClass] | None = None) -> str:
    classes = classes or neon_drift()
    images: list[str] = []
    for c in classes:
        if c.image not in images:
            images.append(c.image)
    img_index = {name: i for i, name in enumerate(images)}

    out: list[str] = [f"// Image {i}: {name} // {i}" for i, name in enumerate(images)] + [""]
    for c in classes:
        out.append(f"// Image {img_index[c.image]}: {c.image} // {img_index[c.image]}")
        out.append(f"// Namespace: {c.namespace}")
        out.append(f"public class {c.name} : {c.base} // TypeSize: 0x{c.type_size:x}")
        out.append("{")
        if c.fields:
            out.append("\t// Fields")
            for f in c.fields:
                mods = ["private", "static"] if f.is_static else (["private"] if f.is_private
                                                                  else ["public"])
                ann = (f"StaticValue: 0x{f.static_rva:x}, Offset: 0x{f.offset:x}" if f.is_static
                       else f"0x{f.offset:x}")
                out.append(f"\t{' '.join(mods)} {f.type} {f.name}; // {ann}")
            out.append("")
        if c.methods:
            out.append("\t// Methods")
            for m in c.methods:
                mods = "public static" if m.is_static else ("public" if m.is_public else "private")
                args = ", ".join(f"{t} {n}" for n, t in m.params)
                line = f"\t{mods} {m.ret} {m.name}({args}) {{ }}"
                if m.rva:
                    line += (f" // RVA: 0x{m.rva:x} Offset: 0x{m.rva:x} "
                             f"VA: 0x{0x700000000 + m.rva:x}")
                out.append(line)
            out.append("")
        out.append("}")
        out.append("")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- metadata


def metadata_blob(classes: list[FxClass] | None = None, version: int = 27) -> bytes:
    """Structurally valid global-metadata.dat using the v27 region schema."""
    classes = classes or neon_drift()
    strings = [""]
    for c in classes:
        for tok in (c.name, c.namespace, c.image):
            if tok and tok not in strings:
                strings.append(tok)
    for m in [m for c in classes for m in c.methods]:
        if m.name and m.name not in strings:
            strings.append(m.name)
    for f in [f for c in classes for f in c.fields]:
        if f.name and f.name not in strings:
            strings.append(f.name)
    strtab = ("\x00".join(strings) + "\x00").encode("utf-8", "surrogatepass")

    def sidx(name: str) -> int:
        return strings.index(name) if name in strings else 0

    lit_rec, lit_data = bytearray(), bytearray()
    for text in ("save/v1", "neon"):
        raw = text.encode("utf-16-le")
        lit_rec += struct.pack("<Ii", len(text), len(lit_data))
        lit_data += raw
    while len(lit_data) % 4:
        lit_data += b"\x00"

    meth_rec = bytearray()
    for i, c in enumerate(classes):
        for j, m in enumerate(c.methods):
            flags = ((0x0010 if m.is_static else 0) | (0x0006 if m.is_public else 0x0001))
            meth_rec += struct.pack("<5iIHHHH", sidx(m.name), i, -1, 0, -1,
                                    0x06000000 | (i << 8) | j, flags, 0, 0xFFFF, len(m.params))
    while len(meth_rec) % 8:
        meth_rec += b"\x00"

    field_rec = bytearray()
    for i, c in enumerate(classes):
        for f in c.fields:
            field_rec += struct.pack("<iiI", sidx(f.name), -1, 0x04000000 | i)
    while len(field_rec) % 8:
        field_rec += b"\x00"

    type_rec = bytearray()
    mstart = fstart = 0
    for i, c in enumerate(classes):
        rec = bytearray(0x58)
        struct.pack_into("<4i", rec, 0, sidx(c.name), sidx(c.namespace), -1, -1)
        struct.pack_into("<3i", rec, 0x18, 0x0002, fstart, mstart)   # flags, fieldStart, methodStart
        struct.pack_into("<I", rec, 0x54, 0x02000000 | (i + 1))      # token tail
        type_rec += rec
        mstart += len(c.methods)
        fstart += len(c.fields)

    img_rec = bytearray()
    typedef_start = 0
    for i, image in enumerate({c.image for c in classes}):
        count = sum(1 for c in classes if c.image == image)
        img_rec += struct.pack("<4i", sidx(image), i, typedef_start, count)
        typedef_start += count
    asm_rec = struct.pack("<ii", sidx(classes[0].image), 0) + bytes(0x28 - 8)

    regions: dict[str, bytes] = {
        "stringLiteral": bytes(lit_rec), "stringLiteralData": bytes(lit_data), "string": strtab,
        "methods": bytes(meth_rec), "fields": bytes(field_rec),
        "typeDefinitions": bytes(type_rec), "images": bytes(img_rec), "assemblies": asm_rec,
    }
    schema = SCHEMAS[version]
    words = 2 + sum(1 if n.endswith("Count") else 2 for n in schema)
    payload_start = len(MAGIC) + 4 * words

    offsets: dict[str, int] = {}
    cursor = payload_start
    for name in schema:
        if name not in regions:
            continue
        offsets[name] = cursor
        cursor += len(regions[name])
        while cursor % 8:
            cursor += 1

    header_ints = [SANITY, version]
    for name in schema:
        if name.endswith("Count"):
            header_ints.append(len(classes))
            continue
        header_ints.append(offsets.get(name, 0))
        header_ints.append(len(regions.get(name, b"")))

    out = bytearray(MAGIC)
    out += struct.pack("<%dI" % len(header_ints), *header_ints)
    assert len(out) == payload_start, (len(out), payload_start)
    for name in offsets:
        out += b"\x00" * (offsets[name] - len(out))
        out += regions[name]
    return bytes(out)


def so_blob(classes: list[FxClass] | None = None, *, runtime_config: bool = False) -> bytes:
    """Minimal, honestly structured ELF64.

    ``runtime_config=True`` adds a mapped 16 KiB ``.modkitcfg`` section matching
    the generic Android Menu runtime, so the payload-config patcher is testable
    without an NDK toolchain.
    """
    classes = classes or neon_drift()

    text = bytearray(TEXT_SIZE)
    stub = struct.pack("<4I", 0xA9BF7BFD, 0x910003FD, 0xF9000BF3, 0xD65F03C0)  # stp/mov/str/ret
    for rva in sorted({m.rva for c in classes for m in c.methods if m.rva}):
        if TEXT_VADDR <= rva < TEXT_VADDR + TEXT_SIZE:
            text[rva - TEXT_VADDR: rva - TEXT_VADDR + len(stub)] = stub

    data = bytearray(DATA_SIZE)
    for c in classes:                                   # static storage, zero-initialised
        for f in c.fields:
            if f.static_rva and DATA_VADDR <= f.static_rva < DATA_VADDR + DATA_SIZE:
                struct.pack_into("<i", data, f.static_rva - DATA_VADDR, 0)

    rodata = b"Assembly-CSharp.dll\0global/v1\0NeonDrift\0"
    dynstr = ((b"\0liblog.so\0libandroid.so\0libGLESv2.so\0libneon.so\0"
               b"il2cpp_domain_get\0il2cpp_thread_attach\0") + b"\0" * 128)
    names = {n: dynstr.index(n.encode()) for n in ("liblog.so", "libandroid.so", "libGLESv2.so",
                                                    "libneon.so", "il2cpp_domain_get",
                                                    "il2cpp_thread_attach")}
    dynsym = bytearray(b"\0" * 24)                      # SHN_UNDEF
    for i, (nm, addr) in enumerate((("il2cpp_domain_get", TEXT_VADDR + 8),
                                     ("il2cpp_thread_attach", TEXT_VADDR + 16)), start=1):
        dynsym += struct.pack("<IBBHQQ", names[nm], 0x12, 0, 1, addr, 16)   # GLOBAL | FUNC
    dynamic = b"".join(struct.pack("<QQ", tag, val) for tag, val in (
        (1, names["liblog.so"]), (1, names["libandroid.so"]), (1, names["libGLESv2.so"]),
        (14, names["libneon.so"]), (5, 0), (10, len(dynstr)), (0, 0), (0, 0)))

    config = (b"MODKITCFG_RESERVED_V1\0" + b"\0" * (16 * 1024 - len(b"MODKITCFG_RESERVED_V1\0"))) if runtime_config else b""
    section_names = [".text", ".rodata", ".dynsym", ".dynstr", ".dynamic", ".data.rel.ro"]
    if runtime_config:
        section_names.append(".modkitcfg")
    section_names.append(".shstrtab")
    shstrtab = bytearray(b"\0")
    sh_names: dict[str, int] = {}
    for name in section_names:
        sh_names[name] = len(shstrtab)
        shstrtab += name.encode() + b"\0"

    # (name, sh_type, sh_flags, sh_addr, data, sh_link, sh_entsize)
    sections = [
        (".text", 1, 0x6, TEXT_VADDR, bytes(text), 0, 4),
        (".rodata", 1, 0x2, 0, rodata, 0, 1),
        (".dynsym", 11, 0x2, 0, bytes(dynsym), 4, 24),      # link -> .dynstr
        (".dynstr", 3, 0x2, 0, dynstr, 0, 0),
        (".dynamic", 6, 0x3, 0, dynamic, 4, 16),
        (".data.rel.ro", 1, 0x3, DATA_VADDR, bytes(data), 0, 1),
    ]
    if runtime_config:
        sections.append((".modkitcfg", 1, 0x2, DATA_VADDR + len(data), config, 0, 16))
    sections.append((".shstrtab", 3, 0x0, 0, bytes(shstrtab), 0, 1))
    index = {s[0]: i + 1 for i, s in enumerate(sections)}   # +1: index 0 is SHT_NULL

    EHDR, PH = 64, 56
    rx_end = DATA_VADDR                                       # first PT_LOAD covers everything before .data
    offs = {".text": TEXT_VADDR}
    cursor = TEXT_VADDR + len(text)
    for entry in sections[1:-1]:
        name, d = entry[0], entry[4]
        offs[name] = cursor
        cursor += len(d)
        while cursor % 8:
            cursor += 1
    offs[".data.rel.ro"] = DATA_VADDR
    cursor = DATA_VADDR + len(data)
    if runtime_config:
        offs[".modkitcfg"] = cursor
        cursor += len(config)
    while cursor % 8:
        cursor += 1
    offs[".shstrtab"] = cursor
    cursor += len(shstrtab)
    while cursor % 8:
        cursor += 1
    sh_off = cursor

    out = bytearray()
    out += struct.pack("<4sBBBBB7x", b"\x7fELF", 2, 1, 1, 0, 0)
    out += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, TEXT_VADDR, EHDR, sh_off, 0, EHDR, PH, 2,
                       64, len(sections) + 1, index[".shstrtab"])
    assert len(out) == EHDR, len(out)
    out += struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, rx_end, rx_end, 0x1000)  # R+X
    rw_size = len(data) + (len(config) if runtime_config else 0)
    out += struct.pack("<IIQQQQQQ", 1, 6, DATA_VADDR, DATA_VADDR, DATA_VADDR,
                       rw_size, rw_size, 0x1000)                             # R+W
    assert len(out) == EHDR + 2 * PH
    for name, _t, _f, _a, d, _l, _e in sections:
        out += b"\x00" * (offs[name] - len(out))
        assert len(out) == offs[name], (name, len(out), offs[name])
        out += d
    out += b"\x00" * (sh_off - len(out))
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)              # SHT_NULL
    for name, stype, flags, addr, d, link, entsize in sections:
        out += struct.pack("<IIQQQQIIQQ", sh_names[name], stype, flags, addr, offs[name], len(d),
                           link, 0, 8, entsize)
    return bytes(out)



def runtime_so_blob() -> bytes:
    return so_blob(runtime_config=True)


def write_all(dest: Path) -> dict[str, Path]:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    classes = neon_drift()
    (dest / "global-metadata.dat").write_bytes(metadata_blob(classes))
    (dest / "libil2cpp.so").write_bytes(so_blob(classes))
    (dest / "dump.cs").write_text(dump_text(classes), encoding="utf-8")
    return {"metadata": dest / "global-metadata.dat", "so": dest / "libil2cpp.so",
            "dump": dest / "dump.cs"}
