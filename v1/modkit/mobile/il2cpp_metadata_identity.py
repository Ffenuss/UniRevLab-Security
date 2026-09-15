"""Resolve IL2CPP method identity from global-metadata.dat without inventing an RVA.

This backend is deliberately narrower than a native address resolver. It can confirm
that a method token/name and, for structurally recognized metadata layouts, its
declaring type exist even when the method catalogue has no native RVA. Such evidence
remains non-actionable and never becomes a patch binding.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from modkit.mobile.il2cpp_crosscheck import parse_metadata

SCHEMA = "modkit-il2cpp-metadata-identity-1.1"
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


def _parse_positive_int(value: Any) -> int | None:
    if value in (None, "", 0, "0", "0x0") or isinstance(value, bool):
        return None
    try:
        if isinstance(value, int):
            return value if value > 0 else None
        text = str(value).strip().lower()
        number = int(text, 16 if text.startswith("0x") else 10)
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


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
        parsed = _parse_positive_int(value)
        if parsed is not None:
            return parsed
    return None


def _method_token(row: dict[str, Any]) -> int | None:
    candidates: list[Any] = []
    for key in ("token", "methodToken", "method_token", "metadataToken", "metadata_token"):
        if key in row:
            candidates.append(row.get(key))
    for value in row.values():
        if isinstance(value, dict):
            for key in ("token", "methodToken", "method_token", "metadataToken", "metadata_token"):
                if key in value:
                    candidates.append(value.get(key))
    for value in candidates:
        parsed = _parse_positive_int(value)
        if parsed is not None:
            return parsed
    return None


def _row_id(row: dict[str, Any], index: int) -> Any:
    for key in ("id", "methodId", "metadataMethodId", "methodIndex", "index"):
        value = row.get(key)
        if value not in (None, ""):
            return value
    return index


def _type_layout_candidates(version: int) -> tuple[tuple[int, int, int, int, str], ...]:
    # Layout tuple: (type record size, methodStart offset, method_count offset,
    # expected method record size, name). The sizes include bitfield + token.
    if version == 24:
        return (
            (104, 52, 80, 56, "LEGACY24_0_TYPEDEF_104"),
            (100, 48, 76, 52, "LEGACY24_1_TYPEDEF_100"),
            (92, 40, 68, 32, "LEGACY24_2_5_TYPEDEF_92"),
        )
    if version >= 25:
        expected_method = 36 if version >= 31 else 32
        return ((88, 36, 64, expected_method, "COMPACT_TYPEDEF_88"),)
    return ()


def _method_token_offset(method_record_size: int) -> int | None:
    # Il2CppMethodDefinition token field for the supported layouts.
    return {56: 44, 52: 40, 32: 20, 36: 24}.get(int(method_record_size))


def _method_token_index(blob: bytes, methods_offset: int, method_record_size: int,
                        method_count: int, string_offset: int, string_size: int,
                        type_labels: dict[int, str]) -> dict[int, dict[str, Any]]:
    token_offset = _method_token_offset(method_record_size)
    if token_offset is None:
        return {}
    unique: dict[int, dict[str, Any]] = {}
    duplicate: set[int] = set()
    for method_index in range(method_count):
        pos = methods_offset + method_index * method_record_size
        if pos < 0 or pos + method_record_size > len(blob) or pos + token_offset + 4 > len(blob):
            break
        token = _u32(blob, pos + token_offset)
        if token == 0 or token >> 24 != 0x06:
            continue
        name = _string(blob, string_offset, string_size, _u32(blob, pos))
        declaring = _i32(blob, pos + 4)
        entry = {
            "metadataMethodId": method_index,
            "token": token,
            "tokenHex": f"0x{token:08x}",
            "methodName": name or None,
            "declaringTypeIndex": declaring,
            "class": type_labels.get(declaring),
        }
        if token in unique:
            duplicate.add(token)
        else:
            unique[token] = entry
    for token in duplicate:
        unique.pop(token, None)
    return unique


def _choose_type_layout(blob: bytes, version: int, type_offset: int, type_size: int,
                        string_offset: int, string_size: int, methods_offset: int,
                        method_record_size: int, method_count: int) -> tuple[int | None, int, int, str, float]:
    best: tuple[int | None, int, int, str, float] = (None, 0, 0, "TYPE_LAYOUT_UNRESOLVED", 0.0)
    for record_size, method_start_offset, method_count_offset, expected_method_size, layout in _type_layout_candidates(version):
        if method_record_size != expected_method_size:
            continue
        if type_size <= 0 or type_size % record_size:
            continue
        type_count = type_size // record_size
        if type_count <= 0:
            continue
        sample = min(type_count, 256)
        score = 0.0
        checked = 0
        for type_index in range(sample):
            pos = type_offset + type_index * record_size
            if pos < 0 or pos + record_size > len(blob):
                break
            checked += 1
            name_index = _u32(blob, pos)
            namespace_index = _u32(blob, pos + 4)
            name = _string(blob, string_offset, string_size, name_index)
            namespace = _string(blob, string_offset, string_size, namespace_index)
            if name:
                score += 1.0
            if namespace_index < string_size and (namespace or namespace_index == 0):
                score += 0.15
            method_start = _i32(blob, pos + method_start_offset)
            method_len = _u16(blob, pos + method_count_offset)
            range_ok = method_len == 0 and -1 <= method_start <= method_count
            if method_len > 0 and 0 <= method_start < method_count and method_start + method_len <= method_count:
                range_ok = True
            if range_ok:
                score += 0.45
            if method_len > 0 and 0 <= method_start < method_count:
                mpos = methods_offset + method_start * method_record_size
                if mpos + 8 <= len(blob) and _i32(blob, mpos + 4) == type_index:
                    score += 0.9
        if checked:
            normalized = score / checked
            if normalized > best[4]:
                best = (record_size, method_start_offset, method_count_offset, layout, normalized)
    if best[4] < 1.20:
        return None, 0, 0, "TYPE_LAYOUT_UNRESOLVED", best[4]
    return best


def _base_result(info: dict[str, Any], method_names: set[str], *, layout: str,
                 score: float = 0.0, count: int = 0,
                 qualified: set[tuple[str, str]] | None = None,
                 method_tokens: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "metadata": info,
        "methodNames": method_names,
        "qualifiedMethods": qualified or set(),
        "methodTokens": method_tokens or {},
        "typeLayout": layout,
        "typeLayoutScore": round(score, 4),
        "typeDefinitionCount": count,
    }


def parse_metadata_identities(metadata_path: str | Path) -> dict[str, Any]:
    source = Path(metadata_path)
    blob = source.read_bytes()
    info, method_names = parse_metadata(source)
    if len(blob) < 168 or _u32(blob, 0) != _SANITY:
        return _base_result(info, method_names, layout="TYPE_TABLE_UNAVAILABLE")

    version = int(info.get("version") or 0)
    string_offset = int(info.get("stringOffset") or 0)
    string_size = int(info.get("stringSize") or 0)
    methods_offset = int(info.get("methodsOffset") or 0)
    method_record_size = info.get("methodRecordSize")
    method_count = int(info.get("methodDefinitionCount") or 0)
    if not isinstance(method_record_size, int) or method_record_size <= 0:
        return _base_result(info, method_names, layout="TYPE_LAYOUT_UNRESOLVED")

    type_offset = _u32(blob, 160)
    type_size = _i32(blob, 164)
    if type_offset > len(blob) or type_size < 0 or type_offset + type_size > len(blob):
        tokens = _method_token_index(blob, methods_offset, method_record_size, method_count, string_offset, string_size, {})
        return _base_result(info, method_names, layout="TYPE_TABLE_OUT_OF_BOUNDS", method_tokens=tokens)

    type_record_size, method_start_offset, method_count_offset, layout, layout_score = _choose_type_layout(
        blob, version, type_offset, type_size, string_offset, string_size,
        methods_offset, method_record_size, method_count,
    )
    if type_record_size is None:
        tokens = _method_token_index(blob, methods_offset, method_record_size, method_count, string_offset, string_size, {})
        return _base_result(info, method_names, layout=layout, score=layout_score, method_tokens=tokens)

    type_count = type_size // type_record_size
    type_labels: dict[int, str] = {}
    for type_index in range(type_count):
        pos = type_offset + type_index * type_record_size
        if pos + type_record_size > len(blob):
            break
        name = _string(blob, string_offset, string_size, _u32(blob, pos))
        namespace = _string(blob, string_offset, string_size, _u32(blob, pos + 4))
        if name:
            type_labels[type_index] = f"{namespace}.{name}" if namespace else name

    method_tokens = _method_token_index(
        blob, methods_offset, method_record_size, method_count,
        string_offset, string_size, type_labels,
    )
    qualified: set[tuple[str, str]] = set()
    for type_index, full in type_labels.items():
        pos = type_offset + type_index * type_record_size
        method_start = _i32(blob, pos + method_start_offset)
        method_len = _u16(blob, pos + method_count_offset)
        if method_len == 0:
            continue
        if method_start < 0 or method_start >= method_count or method_start + method_len > method_count:
            continue
        short = full.rsplit(".", 1)[-1]
        for method_index in range(method_start, method_start + method_len):
            mpos = methods_offset + method_index * method_record_size
            if mpos + 8 > len(blob):
                break
            method_name = _string(blob, string_offset, string_size, _u32(blob, mpos))
            declaring_type = _i32(blob, mpos + 4)
            if method_name and declaring_type == type_index:
                qualified.add((full, method_name))
                qualified.add((short, method_name))

    return _base_result(
        info, method_names, layout=layout, score=layout_score, count=type_count,
        qualified=qualified, method_tokens=method_tokens,
    )


def _same_class(left: str, right: str) -> bool:
    a = left.strip().replace("/", ".").casefold()
    b = right.strip().replace("/", ".").casefold()
    if not a or not b:
        return True
    return a == b or a.rsplit(".", 1)[-1] == b.rsplit(".", 1)[-1]


def build_identity_evidence(metadata_path: str | Path, methods_path: str | Path,
                            output_path: str | Path, rows_path: str | Path | None = None) -> dict[str, Any]:
    parsed = parse_metadata_identities(metadata_path)
    method_names: set[str] = parsed["methodNames"]
    qualified: set[tuple[str, str]] = parsed["qualifiedMethods"]
    method_tokens: dict[int, dict[str, Any]] = parsed.get("methodTokens") or {}
    output = Path(output_path)
    rows_output = Path(rows_path) if rows_path else output.with_name("il2cpp-metadata-identity.methods.jsonl")

    counts = {
        "catalogRows": 0,
        "rowsWithoutRva": 0,
        "tokenMethodConfirmedNoRva": 0,
        "qualifiedMethodConfirmedNoRva": 0,
        "methodNamePresentNoRva": 0,
        "tokenConflictNoRva": 0,
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
            token = _method_token(row)
            token_entry = method_tokens.get(token) if token is not None else None
            token_method = str(token_entry.get("methodName") or "") if token_entry else ""
            token_class = str(token_entry.get("class") or "") if token_entry else ""
            token_conflict = bool(token_entry and (
                (method and token_method and method != token_method)
                or (cls and token_class and not _same_class(cls, token_class))
            ))
            token_confirmed = bool(token_entry and not token_conflict)

            effective_method = method or (token_method if token_confirmed else "")
            effective_class = cls or (token_class if token_confirmed else "")
            pair_confirmed = bool(
                effective_method and effective_class
                and ((effective_class, effective_method) in qualified
                     or (effective_class.rsplit(".", 1)[-1], effective_method) in qualified)
            )
            name_present = bool(effective_method and effective_method in method_names)
            qualified_confirmed = bool(pair_confirmed or (token_confirmed and token_class))

            if token_conflict:
                status = "METADATA_TOKEN_CONFLICT_NO_RVA"
                counts["tokenConflictNoRva"] += 1
            elif token_confirmed:
                status = "METADATA_TOKEN_METHOD_CONFIRMED_NO_RVA"
                counts["tokenMethodConfirmedNoRva"] += 1
            elif pair_confirmed:
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
                "class": effective_class or None,
                "methodName": effective_method or None,
                "status": status,
                "metadataMethodNamePresent": name_present,
                "metadataQualifiedMethodPresent": qualified_confirmed,
                "metadataToken": f"0x{token:08x}" if token is not None else None,
                "metadataTokenConfirmed": token_confirmed,
                "metadataTokenConflict": token_conflict,
                "metadataResolvedClass": token_class or None,
                "metadataResolvedMethodName": token_method or None,
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
        "typeLayoutScore": parsed.get("typeLayoutScore", 0.0),
        "typeDefinitionCount": parsed["typeDefinitionCount"],
        "uniqueMethodNameCount": len(method_names),
        "uniqueMethodTokenCount": len(method_tokens),
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
