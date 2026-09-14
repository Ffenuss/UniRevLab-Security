"""Binary configuration for the built-in DEX-free Menu runtime.

The Android build packages a generic ``libmodkit_runtime.so`` with a fixed-size
``.modkitcfg`` section.  Menu Builder writes this compact configuration into a
copy of that library before Patch Pack adds it to the target APK.

The format is deliberately fixed-width and dependency-free so the injected
runtime needs no JSON parser and can validate all bounds before touching RVAs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import unicodedata

from modkit.elf.reader import ElfFile

MAGIC = b"MKCFG01\0"
VERSION = 4
MAX_CONTROLS = 64
CONFIG_CAPACITY = 16 * 1024
RESERVED_MARKER = b"MODKITCFG_RESERVED_V1\0"
HEADER = struct.Struct("<8sII64s64s64s48s")  # 256 bytes
ENTRY_V1 = struct.Struct("<IIQfff48s80s4s")   # 160 bytes
ENTRY = struct.Struct("<IIQQfff48s80s4s")     # 168 bytes (v2, resolver RVA)

K_ACTION = 1
K_BOOL = 2
K_INT = 3
K_FLOAT = 4
K_PROBE_BOOL = 10
K_PROBE_INT = 11
K_PROBE_UINT = 12
K_PROBE_FLOAT = 13

F_DEFAULT_BOOL = 1 << 0
F_ABI_IL2CPP = 1 << 8
F_INSTANCE = 1 << 9
F_RESOLVER_RETURN_PTR = 1 << 10
F_PROBE_READ_ONLY = 1 << 11

TAB_ALL = 0
TAB_COMBAT = 1
TAB_PLAYER = 2
TAB_RESOURCES = 3
TAB_WORLD = 4
TAB_DEBUG = 5


def _tab_for_category(category: str, title: str = "") -> int:
    """Map a review-time MenuSpec category to one generic runtime tab.

    This is UI-only metadata. It never changes executable binding eligibility.
    """
    text = f"{category} {title}".lower()
    words = set(text.replace("/", " ").replace("-", " ").replace("_", " ").split())
    if words & {"combat", "damage", "health", "hp", "cooldown", "attack", "defense", "defence"}:
        return TAB_COMBAT
    if words & {"player", "movement", "speed", "progression", "level", "xp", "character", "actor"}:
        return TAB_PLAYER
    if words & {"resource", "resources", "currency", "inventory", "gold", "coin", "coins", "gems", "mana", "energy", "stamina"}:
        return TAB_RESOURCES
    if words & {"world", "camera", "fov", "weather", "time", "environment"}:
        return TAB_WORLD
    if words & {"debug", "developer", "dev", "console", "diagnostic", "diagnostics"}:
        return TAB_DEBUG
    return TAB_ALL

_RU = str.maketrans({
    "А":"A","Б":"B","В":"V","Г":"G","Д":"D","Е":"E","Ё":"E","Ж":"Zh","З":"Z","И":"I","Й":"I","К":"K","Л":"L","М":"M","Н":"N","О":"O","П":"P","Р":"R","С":"S","Т":"T","У":"U","Ф":"F","Х":"Kh","Ц":"Ts","Ч":"Ch","Ш":"Sh","Щ":"Sch","Ъ":"","Ы":"Y","Ь":"","Э":"E","Ю":"Yu","Я":"Ya",
    "а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"e","ж":"zh","з":"z","и":"i","й":"i","к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f","х":"kh","ц":"ts","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya",
})


def _fixed(text: str, size: int) -> bytes:
    text = str(text).translate(_RU)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    raw = text.encode("ascii", "replace")[: max(0, size - 1)]
    return raw + b"\0" * (size - len(raw))


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def encode_runtime_config(spec, *, render_host: str = "libunity.so") -> bytes:
    """Serialize executable MenuControl bindings into the generic runtime format."""
    spec.validate()
    executable = [c for c in spec.controls if c.binding is not None]
    probes = [c for c in spec.controls if getattr(c, "probe_kind", None) is not None]
    runtime_controls = executable + probes
    if len(runtime_controls) > MAX_CONTROLS:
        raise ValueError(f"generic runtime supports at most {MAX_CONTROLS} runtime controls")
    targets = {c.target_so for c in executable}
    if len(targets) > 1:
        raise ValueError("generic runtime can target only one native module")
    target_so = next(iter(targets), "libil2cpp.so")

    header = HEADER.pack(MAGIC, VERSION, len(runtime_controls), _fixed(target_so, 64),
                         _fixed(render_host, 64), _fixed(spec.title, 64), b"\0" * 48)
    rows = bytearray()
    for c in runtime_controls:
        if getattr(c, "probe_kind", None) is not None:
            primitive = str(getattr(c, "probe_primitive", ""))
            kind = {"bool": K_PROBE_BOOL, "int32": K_PROBE_INT, "uint32": K_PROBE_UINT, "float": K_PROBE_FLOAT}.get(primitive)
            if kind is None:
                raise ValueError(f"{c.id}: unsupported probe primitive {primitive!r}")
            owner = str(getattr(c, "probe_owner", ""))
            field = str(getattr(c, "probe_field", ""))
            encoded_label = f"{owner}\x1f{field}"
            if len(encoded_label.encode("ascii", "ignore")) >= 80:
                raise ValueError(f"{c.id}: probe owner/field identity does not fit runtime entry")
            tab = _tab_for_category(getattr(c, "category", ""), c.title or c.id)
            status_code = {"CONFIRMED": 1, "FIELD OBSERVED": 2, "RUNTIME TEST": 3, "WATCH/PROBE": 4, "REVIEW": 5}.get(str(getattr(c, "probe_status", "")), 0)
            rows += ENTRY.pack(kind, F_PROBE_READ_ONLY, int(getattr(c, "probe_offset", 0) or 0), 0, 0.0, 0.0, 0.0,
                               _fixed(c.id, 48), _fixed(encoded_label, 80), bytes((tab, status_code, 0, 0)))
            continue
        if c.rva is None or c.rva <= 0:
            raise ValueError(f"{c.id}: executable binding has no positive RVA")
        if c.binding == "action":
            kind = K_ACTION
        elif c.binding == "bool_setter":
            kind = K_BOOL
        elif c.binding == "number_setter" and c.type == "slider_int":
            if c.value_type != "System.Int32":
                raise ValueError(f"{c.id}: generic runtime integer setter requires System.Int32")
            kind = K_INT
        elif c.binding == "number_setter" and c.type == "slider_float":
            if c.value_type != "System.Single":
                raise ValueError(f"{c.id}: generic runtime float setter requires System.Single")
            kind = K_FLOAT
        else:
            raise ValueError(f"{c.id}: unsupported generic-runtime binding/type combination")
        lo = float(c.min_value if c.min_value is not None else 0.0)
        hi = float(c.max_value if c.max_value is not None else 1.0)
        default = float(c.default if c.default is not None else (0.0 if kind == K_BOOL else lo))
        flags = F_DEFAULT_BOOL if (kind == K_BOOL and bool(c.default)) else 0
        if c.call_abi == "il2cpp":
            flags |= F_ABI_IL2CPP
        resolver_rva = 0
        if not c.is_static:
            if c.call_abi != "il2cpp":
                raise ValueError(f"{c.id}: instance runtime binding requires il2cpp ABI")
            if c.resolver_kind not in {"out_ptr_bool", "return_ptr"} or not c.resolver_rva:
                raise ValueError(f"{c.id}: instance runtime binding requires a supported resolver RVA")
            if not c.resolver_verified:
                raise ValueError(f"{c.id}: instance runtime binding requires a type-verified resolver")
            flags |= F_INSTANCE
            if c.resolver_kind == "return_ptr":
                flags |= F_RESOLVER_RETURN_PTR
            resolver_rva = int(c.resolver_rva)
        tab = _tab_for_category(getattr(c, "category", ""), c.title or c.id)
        rows += ENTRY.pack(kind, flags, int(c.rva), resolver_rva, lo, hi, default,
                           _fixed(c.id, 48), _fixed(c.title or c.id, 80), bytes((tab, 0, 0, 0)))
    blob = header + bytes(rows)
    if len(blob) > CONFIG_CAPACITY:
        raise ValueError(f"runtime configuration is {len(blob)} bytes; capacity is {CONFIG_CAPACITY}")
    return blob


def decode_runtime_config(blob: bytes) -> dict:
    if len(blob) < HEADER.size:
        raise ValueError("runtime config is truncated")
    magic, version, count, target, render, title, _ = HEADER.unpack_from(blob, 0)
    if magic != MAGIC or version not in (1, 2, 3, VERSION):
        raise ValueError("runtime config magic/version mismatch")
    if count > MAX_CONTROLS:
        raise ValueError("runtime config control count exceeds limit")
    entry_struct = ENTRY if version >= 2 else ENTRY_V1
    need = HEADER.size + count * entry_struct.size
    if need > len(blob):
        raise ValueError("runtime config entries are truncated")
    controls = []
    pos = HEADER.size
    for _i in range(count):
        if version >= 2:
            kind, flags, rva, resolver_rva, lo, hi, default, cid, label, _pad = ENTRY.unpack_from(blob, pos)
        else:
            kind, flags, rva, lo, hi, default, cid, label, _pad = ENTRY_V1.unpack_from(blob, pos)
            resolver_rva = 0
        pos += entry_struct.size
        call_abi = "il2cpp" if (flags & F_ABI_IL2CPP) else "native"
        is_static = not bool(flags & F_INSTANCE)
        resolver_kind = None
        if resolver_rva:
            resolver_kind = "return_ptr" if (flags & F_RESOLVER_RETURN_PTR) else "out_ptr_bool"
        tab = int(_pad[0]) if version >= 3 and _pad else TAB_ALL
        raw_label = _cstr(label)
        probe = bool(version >= 4 and (flags & F_PROBE_READ_ONLY) and kind in {K_PROBE_BOOL, K_PROBE_INT, K_PROBE_UINT, K_PROBE_FLOAT})
        probe_owner = probe_field = None
        if probe and "\x1f" in raw_label:
            probe_owner, probe_field = raw_label.split("\x1f", 1)
        controls.append({"kind": kind, "flags": flags, "rva": rva, "resolverRva": resolver_rva or None,
                         "resolverKind": resolver_kind,
                         "callAbi": call_abi, "isStatic": is_static, "min": lo, "max": hi,
                         "default": default, "id": _cstr(cid), "label": probe_field or raw_label,
                         "tab": tab, "probeReadOnly": probe, "probeOwner": probe_owner,
                         "probeField": probe_field, "probeOffset": rva if probe else None,
                         "probeStatusCode": int(_pad[1]) if version >= 4 and _pad else 0})
    schema = "modkit-runtime-config-4.0" if version == 4 else ("modkit-runtime-config-3.0" if version == 3 else ("modkit-runtime-config-2.0" if version == 2 else "modkit-runtime-config-1.0"))
    return {"schema": schema,
            "version": version, "targetSo": _cstr(target), "renderHost": _cstr(render),
            "title": _cstr(title), "controls": controls, "bytesUsed": need}


def patch_runtime_blob(runtime_blob: bytes, config_blob: bytes) -> tuple[bytes, dict]:
    """Write config into .modkitcfg (preferred) or a mapped reserved marker region."""
    if len(config_blob) > CONFIG_CAPACITY:
        raise ValueError("runtime config exceeds reserved capacity")
    elf = ElfFile(runtime_blob)
    if not elf.is_arm64():
        raise ValueError("built-in Menu runtime must be arm64-v8a")
    sec = elf.section(".modkitcfg")
    if sec is not None:
        if sec.size < CONFIG_CAPACITY:
            raise ValueError(f".modkitcfg is only {sec.size} bytes; {CONFIG_CAPACITY} required")
        off = sec.offset
        capacity = sec.size
        location = ".modkitcfg"
    else:
        off = runtime_blob.find(RESERVED_MARKER)
        if off < 0:
            raise ValueError("runtime has neither .modkitcfg nor the reserved config marker")
        if elf.off_to_rva(off) is None:
            raise ValueError("reserved config marker is not inside a mapped PT_LOAD segment")
        capacity = CONFIG_CAPACITY
        if off + capacity > len(runtime_blob):
            raise ValueError("reserved runtime config region is truncated")
        location = "marker"
    if len(config_blob) > capacity:
        raise ValueError("encoded runtime config does not fit reserved region")
    view = bytearray(runtime_blob)
    old = bytes(view[off:off + capacity])
    view[off:off + capacity] = config_blob + b"\0" * (capacity - len(config_blob))
    patched = bytes(view)
    decoded = decode_runtime_config(patched[off:off + len(config_blob)])
    return patched, {
        "location": location,
        "fileOffset": off,
        "capacity": capacity,
        "bytesUsed": len(config_blob),
        "oldSha256": hashlib.sha256(old).hexdigest(),
        "newRegionSha256": hashlib.sha256(patched[off:off + capacity]).hexdigest(),
        "config": decoded,
    }


def patch_runtime_file(runtime_so: str | Path, spec, output_so: str | Path | None = None,
                       *, render_host: str = "libunity.so") -> dict:
    runtime_so = Path(runtime_so)
    config = encode_runtime_config(spec, render_host=render_host)
    patched, report = patch_runtime_blob(runtime_so.read_bytes(), config)
    dest = Path(output_so) if output_so else runtime_so.with_name(runtime_so.stem + "-configured.so")
    dest.write_bytes(patched)
    report.update({"path": str(dest), "sha256": hashlib.sha256(patched).hexdigest()})
    return report
