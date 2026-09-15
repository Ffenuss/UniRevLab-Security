"""Cancellation-aware release adapter for the structural IL2CPP cross-check."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import il2cpp_crosscheck as _base

SCHEMA = _base.SCHEMA


class CrosscheckCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


class _Gate:
    def __init__(self, cb: Any | None, interval: int = 128):
        self.cb = cb
        self.interval = max(1, int(interval))
        self.count = 0

    def force(self) -> None:
        if _cancelled(self.cb):
            raise CrosscheckCancelled("IL2CPP structural cross-check cancelled")

    def tick(self) -> None:
        self.count += 1
        if self.count % self.interval == 0:
            self.force()


def _part(path: Path) -> Path:
    return path.with_name(path.name + ".part")


def _read_blob(path: str | Path, gate: _Gate) -> bytearray:
    data = bytearray()
    with Path(path).open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            gate.force()
            data.extend(chunk)
    gate.force()
    return data


def parse_metadata(metadata_path: str | Path, cb: Any | None = None) -> tuple[dict[str, Any], set[str]]:
    """Base-compatible metadata parser with cooperative checks in the full method loop."""
    gate = _Gate(cb)
    gate.force()
    blob = _read_blob(metadata_path, gate)
    if len(blob) < 56:
        raise ValueError("global-metadata.dat is too small")
    sanity = _base._u32(blob, 0)
    version = _base._i32(blob, 4)
    if sanity != _base._METADATA_SANITY:
        raise ValueError(f"unexpected metadata sanity: 0x{sanity:08x}")
    if version < 16 or version > 64:
        raise ValueError(f"unsupported/implausible metadata version: {version}")

    string_offset, string_size = _base._i32(blob, 24), _base._i32(blob, 28)
    methods_offset, methods_size = _base._i32(blob, 48), _base._i32(blob, 52)
    for label, offset, size in (
        ("string", string_offset, string_size),
        ("methods", methods_offset, methods_size),
    ):
        if offset < 0 or size < 0 or offset > len(blob) or offset + size > len(blob):
            raise ValueError(f"metadata {label} table is out of bounds")

    record_size, score = _base._choose_method_record_size(
        blob, string_offset, string_size, methods_offset, methods_size, version
    )
    gate.force()
    names: set[str] = set()
    method_count = 0
    if record_size:
        method_count = methods_size // record_size
        string_limit = string_offset + string_size
        for index in range(method_count):
            gate.tick()
            pos = methods_offset + index * record_size
            name_index = _base._u32(blob, pos)
            if name_index >= string_size:
                continue
            name = _base._cstring(blob, string_offset + name_index, string_limit)
            if _base._plausible_name(name):
                names.add(name)
    gate.force()
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


def run_crosscheck(metadata_path: str | Path, library_path: str | Path, methods_path: str | Path,
                   output_path: str | Path, rows_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    gate = _Gate(cb)
    gate.force()
    metadata, method_names = parse_metadata(metadata_path, cb)
    gate.force()
    elf = _base.parse_elf(library_path)
    gate.force()

    methods_file = Path(methods_path)
    destination = Path(output_path)
    rows_destination = Path(rows_path) if rows_path else destination.with_name("il2cpp-crosscheck.methods.jsonl")
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows_destination.parent.mkdir(parents=True, exist_ok=True)
    output_part = _part(destination)
    rows_part = _part(rows_destination)
    output_part.unlink(missing_ok=True)
    rows_part.unlink(missing_ok=True)

    counts = {
        "catalogRows": 0,
        "rowsWithRva": 0,
        "structuralBothPresent": 0,
        "metadataNameOnly": 0,
        "executableRvaOnly": 0,
        "unresolved": 0,
    }
    samples: list[dict[str, Any]] = []
    try:
        with methods_file.open("r", encoding="utf-8", errors="replace") as source, rows_part.open("w", encoding="utf-8") as sink:
            for index, line in enumerate(source):
                gate.tick()
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
                checked = _base._crosscheck_row(row, index, method_names, elf)
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

        gate.force()
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
            "cancelAware": cb is not None,
            "metadataParsingCancelAware": cb is not None,
            "atomicOutputPromotion": True,
        }
        output_part.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        gate.force()
        rows_part.replace(rows_destination)
        output_part.replace(destination)
        return result
    except Exception:
        output_part.unlink(missing_ok=True)
        rows_part.unlink(missing_ok=True)
        raise
