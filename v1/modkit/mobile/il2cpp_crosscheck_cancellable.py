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


def run_crosscheck(metadata_path: str | Path, library_path: str | Path, methods_path: str | Path,
                   output_path: str | Path, rows_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    gate = _Gate(cb)
    gate.force()
    metadata, method_names = _base.parse_metadata(metadata_path)
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
