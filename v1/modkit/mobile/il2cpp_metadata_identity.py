"""Resolve IL2CPP method identity from global-metadata.dat without inventing an RVA.

This backend is deliberately narrower than a native address resolver.  It can confirm
that a method name (and, for supported metadata layouts, declaring type) exists in
metadata even when the method catalogue has no native RVA.  Such evidence remains
non-actionable and never becomes a patch binding.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from modkit.mobile.il2cpp_crosscheck import parse_metadata

SCHEMA = "modkit-il2cpp-metadata-identity-1.0"
_SANITY = 0xFAB11BAF


def _u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _i32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<i", blob, offset)[0]


def _u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def _string(blob: bytes, string_offset: int, string_size: int, index: int) -> str:
    if index < 0 or index >= string_size:
        return ""
    start = string_offset + index
    limit = string_offset + string_size
    end = blob.find(b"\x00", start, min(limit, start + 4096))
    if end < 0:
        end = min(limit, start + 4096)
    try:
        return blob[start:end].decode("utf-8").strip()
    except UnicodeDecodeError:
        return blob[start:end].decode("utf-8", "replace").strip()


def _clean_method_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "::" in text:
        text = text.rsplit("::", 1)[1]
    if "(" in text:
        text = text.split("(", 1)[0]
    text = text.strip()
    if " " in text:
        text = text.split()[-1]
    return text


def _method_name(row: dict[str, Any]) -> str:
    for key in ("method", "methodName", "method_name", "name", "label", "title"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            name = _clean_method_name(value)
            if name:
                return name
        if isinstance(value, dict):
            nested = value.get("name") or value.get("methodName")
            name = _clean_method_name(nested)
            if name:
                return name
    return ""


def _class_name(row: dict[str, Any]) -> str:
    for key in ("class", "className", "declaringType", "typeName", "type"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().replace("/", ".")
        if isinstance(value, dict):
            nested = value.get("fullName") or value.get("name") or value.get("className")
            if isinstance(nested, str) and nested.strip():
                return nested.strip().replace("/", ".")
    return ""


def _rva(row: dict[str, Any]) -> int | None:
    candidates: list[Any] = []
    for key in ("rva", "RVA", "nativeRva", "native_rva", "address", "virtualAddress"):
        if key in row:
            candidates.append(row.get(key))
    for value in row.values():
        if isinstance(value, dict):
            for key in ("rva", "RVA", "nativeRva", "native_rva"):
                if key in value:
                    candidates.append(value.get(key))
    for value in candidates:
        if value in (None, "", 0, "0", "0x0"):
            continue
        try:
            if isinstance(value, int):
                return value if value > 0 else None
            text = str(value).strip().lower()
            number = int(text, 16 if text.startswith("0x") else 10)
            if number > 0:
                return number
        except (TypeError, ValueError):
            continue
    return None


def _row_id(row: dict[str, Any], index: int) -> Any:
    for key in ("id", "methodId", "metadataMethodId", "methodIndex", "index"):
        value = row.get(key)
        if value not in (None, ""):
            return value
    return index


def _type_layout(version: int, type_size: int) -> tuple[int | None, str]:
    # Versions >=25 use the compact Il2CppTypeDefinition layout in which
    # methodStart is at +36, method_count at +64 and the record is 88 bytes.
    # For older 24.x sub-layouts we deliberately fall back to name-only evidence.
    if version >= 25 and type_size > 0 and type_size % 88 == 0:
        return 88, "COMPACT_TYPEDEF_88"
    return None, "TYPE_LAYOUT_UNRESOLVED"


def parse_metadata_identities(metadata_path: str | Path) -> dict[str, Any]:
    source = Path(metadata_path)
    blob = source.read_bytes()
    info, method_names = parse_metadata(source)
    if len(blob) < 168 or _u32(blob, 0) != _SANITY:
        return {
            "metadata": info,
            "methodNames": method_names,
            "qualifiedMethods": set(),
            "typeLayout": "TYPE_TABLE_UNAVAILABLE",
            "typeDefinitionCount": 0,
        }

    version = int(info.get("version") or 0)
    string_offset = int(info.get("stringOffset") or 0)
    string_size = int(info.get("stringSize") or 0)
    methods_offset = int(info.get("methodsOffset") or 0)
    method_record_size = info.get("methodRecordSize")
    method_count = int(info.get("methodDefinitionCount") or 0)
    type_offset = _u32(blob, 160)
    type_size = _i32(blob, 164)
    if type_offset > len(blob) or type_size < 0 or type_offset + type_size > len(blob):
        return {
            "metadata": info,
            "methodNames": method_names,
            "qualifiedMethods": set(),
            "typeLayout": "TYPE_TABLE_OUT_OF_BOUNDS",
            "typeDefinitionCount": 0,
        }

    type_record_size, layout = _type_layout(version, type_size)
    qualified: set[tuple[str, str]] = set()
    if type_record_size is None or not isinstance(method_record_size, int) or method_record_size <= 0:
        return {
            "metadata": info,
            "methodNames": method_names,
            "qualifiedMethods": qualified,
            "typeLayout": layout,
            "typeDefinitionCount": 0 if type_record_size is None else type_size // type_record_size,
        }

    type_count = type_size // type_record_size
    for type_index in range(type_count):
        pos = type_offset + type_index * type_record_size
        if pos + 88 > len(blob):
            break
        name = _string(blob, string_offset, string_size, _u32(blob, pos))
        namespace = _string(blob, string_offset, string_size, _u32(blob, pos + 4))
        if not name:
            continue
        full = f"{namespace}.{name}" if namespace else name
        method_start = _i32(blob, pos + 36)
        method_len = _u16(blob, pos + 64)
        if method_start < 0 or method_start >= method_count:
            continue
        end = min(method_count, method_start + method_len)
        for method_index in range(method_start, end):
            mpos = methods_offset + method_index * method_record_size
            if mpos + 8 > len(blob):
                break
            method_name = _string(blob, string_offset, string_size, _u32(blob, mpos))
            declaring_type = _i32(blob, mpos + 4)
            if method_name and declaring_type == type_index:
                qualified.add((full, method_name))
                qualified.add((name, method_name))

    return {
        "metadata": info,
        "methodNames": method_names,
        "qualifiedMethods": qualified,
        "typeLayout": layout,
        "typeDefinitionCount": type_count,
    }


def build_identity_evidence(metadata_path: str | Path, methods_path: str | Path,
                            output_path: str | Path, rows_path: str | Path | None = None) -> dict[str, Any]:
    parsed = parse_metadata_identities(metadata_path)
    method_names: set[str] = parsed["methodNames"]
    qualified: set[tuple[str, str]] = parsed["qualifiedMethods"]
    output = Path(output_path)
    rows_output = Path(rows_path) if rows_path else output.with_name("il2cpp-metadata-identity.methods.jsonl")

    counts = {
        "catalogRows": 0,
        "rowsWithoutRva": 0,
        "qualifiedMethodConfirmedNoRva": 0,
        "methodNamePresentNoRva": 0,
        "unresolvedNoRva": 0,
    }
    samples: list[dict[str, Any]] = []
    rows_output.parent.mkdir(parents=True, exist_ok=True)
    with Path(methods_path).open("r", encoding="utf-8", errors="replace") as source, rows_output.open("w", encoding="utf-8") as sink:
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
            if _rva(row) is not None:
                continue
            counts["rowsWithoutRva"] += 1
            method = _method_name(row)
            cls = _class_name(row)
            exact_qualified = bool(method and cls and ((cls, method) in qualified or (cls.rsplit(".", 1)[-1], method) in qualified))
            name_present = bool(method and method in method_names)
            if exact_qualified:
                status = "METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA"
                counts["qualifiedMethodConfirmedNoRva"] += 1
            elif name_present:
                status = "METADATA_METHOD_NAME_PRESENT_NO_RVA"
                counts["methodNamePresentNoRva"] += 1
            else:
                status = "UNRESOLVED_NO_RVA"
                counts["unresolvedNoRva"] += 1
            evidence = {
                "id": _row_id(row, index),
                "class": cls or None,
                "methodName": method or None,
                "status": status,
                "metadataMethodNamePresent": name_present,
                "metadataQualifiedMethodPresent": exact_qualified,
                "addressConfirmed": False,
                "rva": None,
                "actionable": False,
                "buildable": False,
                "promotesBuildability": False,
            }
            sink.write(json.dumps(evidence, ensure_ascii=False, separators=(",", ":")) + "\n")
            if len(samples) < 64 and status != "UNRESOLVED_NO_RVA":
                samples.append(evidence)

    result = {
        "schema": SCHEMA,
        "engine": "il2cpp.metadata-identity-embedded",
        "mode": "STATIC_METADATA_IDENTITY_ONLY",
        "metadataVersion": parsed["metadata"].get("version"),
        "typeLayout": parsed["typeLayout"],
        "typeDefinitionCount": parsed["typeDefinitionCount"],
        "uniqueMethodNameCount": len(method_names),
        "qualifiedMethodPairCount": len(qualified),
        "counts": counts,
        "rowsFile": rows_output.name,
        "addressResolver": False,
        "executesTargetCode": False,
        "writesTarget": False,
        "actionable": False,
        "promotesBuildability": False,
        "note": "Confirms metadata identity only. Missing RVA remains unresolved and cannot be used as a patch binding.",
        "samples": samples,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def build_workspace_identity(workspace: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workspace)
    metadata = root / "metadata.bin"
    methods = root / "analysis.methods.jsonl"
    if not metadata.is_file() or not methods.is_file():
        raise ValueError("metadata.bin and analysis.methods.jsonl are required")
    output = Path(output_path) if output_path else root / "il2cpp-metadata-identity.json"
    return build_identity_evidence(metadata, methods, output, root / "il2cpp-metadata-identity.methods.jsonl")
