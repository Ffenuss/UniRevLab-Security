"""Independent structural cross-check for IL2CPP metadata and native RVAs.

This backend intentionally does *not* claim to be a second CodeRegistration resolver.
It parses global-metadata.dat and ELF program headers itself, then checks whether rows
from ModKit's method catalog refer to real metadata method names and executable ELF
ranges.  A positive result is corroborating evidence only: it does not prove the
method-name-to-RVA association and it never makes a candidate buildable.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "modkit-il2cpp-crosscheck-1.0"
_METADATA_SANITY = 0xFAB11BAF


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _number(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        try:
            return int(text, 16 if text.startswith("0x") else 10)
        except ValueError:
            return None
    return None


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _cstring(blob: bytes, start: int, limit: int) -> str:
    if start < 0 or start >= limit or start >= len(blob):
        return ""
    end = blob.find(b"\x00", start, min(limit, start + 4096))
    if end < 0:
        end = min(limit, start + 4096)
    raw = blob[start:end]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
    return text.strip()


def _plausible_name(value: str) -> bool:
    if not value or len(value) > 512:
        return False
    printable = sum(1 for ch in value if ch.isprintable() and ch not in "\r\n\t")
    if printable < max(1, int(len(value) * 0.90)):
        return False
    return any(ch.isalpha() or ch == "_" for ch in value)


def _method_record_candidates(version: int) -> tuple[int, ...]:
    # Il2CppMethodDefinition is 56 bytes in the old <=24 layout, 52 in 24.1,
    # 32 after the legacy index fields disappear, and 36 in v31 when
    # returnParameterToken is present. Version 24 has several sub-layouts, so
    # score all structurally plausible variants rather than guessing the subversion.
    if version >= 31:
        return (36, 32)
    if version == 24:
        return (56, 52, 32)
    if version < 24:
        return (56, 52)
    return (32,)


def _choose_method_record_size(blob: bytes, string_offset: int, string_size: int,
                               methods_offset: int, methods_size: int, version: int) -> tuple[int | None, float]:
    best_size: int | None = None
    best_score = -1.0
    string_limit = string_offset + string_size
    for record_size in _method_record_candidates(version):
        if record_size <= 0 or methods_size <= 0 or methods_size % record_size:
            continue
        count = methods_size // record_size
        if count <= 0:
            continue
        sample = min(count, 512)
        valid = 0
        checked = 0
        for index in range(sample):
            pos = methods_offset + index * record_size
            if pos + 4 > len(blob):
                break
            name_index = _u32(blob, pos)
            checked += 1
            if name_index >= string_size:
                continue
            if _plausible_name(_cstring(blob, string_offset + name_index, string_limit)):
                valid += 1
        score = valid / checked if checked else 0.0
        if score > best_score or (score == best_score and best_size is not None and record_size < best_size):
            best_size, best_score = record_size, score
    if best_score < 0.35:
        return None, max(0.0, best_score)
    return best_size, best_score


def parse_metadata(path: str | Path) -> tuple[dict[str, Any], set[str]]:
    source = Path(path)
    blob = source.read_bytes()
    if len(blob) < 56:
        raise ValueError("global-metadata.dat is too small")
    sanity = _u32(blob, 0)
    version = _i32(blob, 4)
    if sanity != _METADATA_SANITY:
        raise ValueError(f"unexpected metadata sanity: 0x{sanity:08x}")
    if version < 16 or version > 64:
        raise ValueError(f"unsupported/implausible metadata version: {version}")

    string_offset, string_size = _i32(blob, 24), _i32(blob, 28)
    methods_offset, methods_size = _i32(blob, 48), _i32(blob, 52)
    for label, offset, size in (
        ("string", string_offset, string_size),
        ("methods", methods_offset, methods_size),
    ):
        if offset < 0 or size < 0 or offset > len(blob) or offset + size > len(blob):
            raise ValueError(f"metadata {label} table is out of bounds")

    record_size, score = _choose_method_record_size(
        blob, string_offset, string_size, methods_offset, methods_size, version
    )
    names: set[str] = set()
    method_count = 0
    if record_size:
        method_count = methods_size // record_size
        string_limit = string_offset + string_size
        for index in range(method_count):
            pos = methods_offset + index * record_size
            name_index = _u32(blob, pos)
            if name_index >= string_size:
                continue
            name = _cstring(blob, string_offset + name_index, string_limit)
            if _plausible_name(name):
                names.add(name)

    return ({
        "sanityHex": f"0x{sanity:08x}",
        "version": version,
        "fileSize": len(blob),
        "stringOffset": string_offset,
        "stringSize": string_size,
        "methodsOffset": methods_offset,
        "methodsSize": methods_size,
        "methodRecordSize": record_size,
        "methodRecordLayoutScore": round(score, 4),
        "methodDefinitionCount": method_count,
        "uniqueMethodNameCount": len(names),
        "methodTableParsed": record_size is not None,
    }, names)


def parse_elf(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    with source.open("rb") as fh:
        header = fh.read(64)
        if len(header) < 52 or header[:4] != b"\x7fELF":
            raise ValueError("libil2cpp.so is not ELF")
        elf_class = header[4]
        endian = header[5]
        if endian != 1:
            raise ValueError("only little-endian ELF is supported")
        if elf_class == 2:
            if len(header) < 64:
                raise ValueError("truncated ELF64 header")
            phoff = struct.unpack_from("<Q", header, 32)[0]
            phentsize = struct.unpack_from("<H", header, 54)[0]
            phnum = struct.unpack_from("<H", header, 56)[0]
            expected_min = 56
        elif elf_class == 1:
            phoff = struct.unpack_from("<I", header, 28)[0]
            phentsize = struct.unpack_from("<H", header, 42)[0]
            phnum = struct.unpack_from("<H", header, 44)[0]
            expected_min = 32
        else:
            raise ValueError(f"unsupported ELF class: {elf_class}")
        if phentsize < expected_min or phnum <= 0 or phnum > 65535:
            raise ValueError("invalid ELF program-header table")

        segments: list[dict[str, Any]] = []
        for index in range(phnum):
            fh.seek(phoff + index * phentsize)
            row = fh.read(phentsize)
            if len(row) < expected_min:
                raise ValueError("truncated ELF program header")
            if elf_class == 2:
                p_type, p_flags = struct.unpack_from("<II", row, 0)
                p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from("<QQQQQQ", row, 8)
            else:
                p_type = struct.unpack_from("<I", row, 0)[0]
                p_offset, p_vaddr, _paddr, p_filesz, p_memsz = struct.unpack_from("<IIIII", row, 4)
                p_flags = struct.unpack_from("<I", row, 24)[0]
            if p_type != 1:  # PT_LOAD
                continue
            segments.append({
                "index": index,
                "offset": int(p_offset),
                "vaddr": int(p_vaddr),
                "filesz": int(p_filesz),
                "memsz": int(p_memsz),
                "flags": int(p_flags),
                "executable": bool(p_flags & 0x1),  # PF_X
            })

    if not segments:
        raise ValueError("ELF has no PT_LOAD segments")
    load_base = min(row["vaddr"] for row in segments)
    executable = [row for row in segments if row["executable"] and row["memsz"] > 0]
    return {
        "class": "ELF64" if elf_class == 2 else "ELF32",
        "fileSize": source.stat().st_size,
        "programHeaderCount": phnum,
        "loadSegmentCount": len(segments),
        "executableSegmentCount": len(executable),
        "minimumLoadVaddr": load_base,
        "segments": segments,
    }


def _rva_segment(rva: int, elf: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    segments = elf.get("segments") if isinstance(elf.get("segments"), list) else []
    executable = [row for row in segments if isinstance(row, dict) and row.get("executable")]
    for row in executable:
        start = int(row.get("vaddr") or 0)
        end = start + int(row.get("memsz") or 0)
        if start <= rva < end:
            return row, "DIRECT_ELF_VADDR"
    base = int(elf.get("minimumLoadVaddr") or 0)
    absolute = base + rva
    if absolute != rva:
        for row in executable:
            start = int(row.get("vaddr") or 0)
            end = start + int(row.get("memsz") or 0)
            if start <= absolute < end:
                return row, "LOAD_BASE_RELATIVE_RVA"
    return None, "RVA_OUTSIDE_EXECUTABLE_PT_LOAD"


def _walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            if isinstance(nested, dict):
                yield from _walk_dicts(nested)


def _extract_rva(row: dict[str, Any]) -> int | None:
    for obj in _walk_dicts(row):
        for key in ("rva", "RVA", "nativeRva", "native_rva"):
            if key in obj:
                value = _number(obj.get(key))
                if value is not None and value >= 0:
                    return value
    return None


def _method_name(row: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("method", "methodName", "method_name", "name", "title", "fullName", "displayName"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, dict):
            nested = value.get("name") or value.get("methodName")
            if isinstance(nested, str) and nested.strip():
                values.append(nested.strip())
    for value in values:
        text = value
        if "::" in text:
            text = text.rsplit("::", 1)[1]
        if "(" in text:
            text = text.split("(", 1)[0]
        text = text.strip().split()[-1] if text.strip() else ""
        if text:
            return text
    return ""


def _row_id(row: dict[str, Any], index: int) -> Any:
    for key in ("id", "methodId", "metadataMethodId", "methodIndex", "index"):
        if row.get(key) not in (None, ""):
            return row.get(key)
    return index


def _crosscheck_row(row: dict[str, Any], index: int, method_names: set[str], elf: dict[str, Any]) -> dict[str, Any] | None:
    rva = _extract_rva(row)
    if rva is None:
        return None
    name = _method_name(row)
    metadata_match = bool(name and name in method_names)
    segment, rva_mode = _rva_segment(rva, elf)
    executable_match = segment is not None
    if metadata_match and executable_match:
        status = "STRUCTURAL_BOTH_PRESENT"
    elif executable_match:
        status = "ELF_EXECUTABLE_RVA_CONFIRMED"
    elif metadata_match:
        status = "METADATA_METHOD_NAME_CONFIRMED"
    else:
        status = "UNRESOLVED"
    return {
        "id": _row_id(row, index),
        "methodName": name or None,
        "rva": rva,
        "rvaHex": _hex(rva),
        "metadataMethodNamePresent": metadata_match,
        "executableElfRangePresent": executable_match,
        "elfRangeMode": rva_mode,
        "segmentIndex": None if segment is None else segment.get("index"),
        "status": status,
        "associationConfirmed": False,
        "promotesBuildability": False,
    }


def run_crosscheck(metadata_path: str | Path, library_path: str | Path, methods_path: str | Path,
                   output_path: str | Path, rows_path: str | Path | None = None) -> dict[str, Any]:
    metadata, method_names = parse_metadata(metadata_path)
    elf = parse_elf(library_path)
    methods_file = Path(methods_path)
    destination = Path(output_path)
    rows_destination = Path(rows_path) if rows_path else destination.with_name("il2cpp-crosscheck.methods.jsonl")

    counts = {
        "catalogRows": 0,
        "rowsWithRva": 0,
        "structuralBothPresent": 0,
        "metadataNameOnly": 0,
        "executableRvaOnly": 0,
        "unresolved": 0,
    }
    samples: list[dict[str, Any]] = []
    rows_destination.parent.mkdir(parents=True, exist_ok=True)
    with methods_file.open("r", encoding="utf-8", errors="replace") as source, rows_destination.open("w", encoding="utf-8") as sink:
        for index, line in enumerate(source):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            counts["catalogRows"] += 1
            checked = _crosscheck_row(row, index, method_names, elf)
            if checked is None:
                continue
            counts["rowsWithRva"] += 1
            status = checked["status"]
            if status == "STRUCTURAL_BOTH_PRESENT":
                counts["structuralBothPresent"] += 1
            elif status == "METADATA_METHOD_NAME_CONFIRMED":
                counts["metadataNameOnly"] += 1
            elif status == "ELF_EXECUTABLE_RVA_CONFIRMED":
                counts["executableRvaOnly"] += 1
            else:
                counts["unresolved"] += 1
            sink.write(json.dumps(checked, ensure_ascii=False, separators=(",", ":")) + "\n")
            if len(samples) < 64 and status != "UNRESOLVED":
                samples.append(checked)

    public_elf = {key: value for key, value in elf.items() if key != "segments"}
    result = {
        "schema": SCHEMA,
        "engine": "il2cpp.structural-crosscheck-embedded",
        "mode": "STATIC_READ_ONLY",
        "executesTargetCode": False,
        "writesTarget": False,
        "promotesBuildability": False,
        "confirmsMethodToRvaAssociation": False,
        "note": "Metadata-name presence and executable RVA range are independently checked. CodeRegistration mapping is not inferred by this backend.",
        "metadata": metadata,
        "elf": public_elf,
        "counts": counts,
        "rowsFile": rows_destination.name,
        "samples": samples,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
