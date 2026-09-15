"""Correlate static native locators with a read-only procfs runtime snapshot.

This module never opens process memory and never mutates the target.  It consumes the
module load-bias information already captured by Process Lab and turns an exact static
RVA into an observed runtime virtual address when the owning module can be matched.
Runtime correlation is evidence only: it must not promote a finding to buildable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-runtime-correlation-1.0"


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _module_images(session: dict) -> list[dict]:
    rows = session.get("moduleImages")
    if not isinstance(rows, list):
        return []
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path") or "").strip()
        base = _number(row.get("loadBaseHex") if row.get("loadBaseHex") is not None else row.get("loadBase"))
        if not path or base is None:
            continue
        out.append({
            **row,
            "path": path,
            "basename": _basename(path),
            "loadBase": base,
        })
    return out


def _mappings(session: dict) -> list[dict]:
    rows = session.get("mappings")
    if not isinstance(rows, list):
        return []
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        start = _number(row.get("startHex") if row.get("startHex") is not None else row.get("start"))
        end = _number(row.get("endHex") if row.get("endHex") is not None else row.get("end"))
        path = str(row.get("path") or "")
        if start is None or end is None or end <= start:
            continue
        out.append({**row, "start": start, "end": end, "path": path})
    return out


def _match_module(locator: dict, card: dict, images: list[dict]) -> tuple[dict | None, str]:
    library = str(locator.get("library") or locator.get("module") or "").strip()
    if library:
        wanted = _basename(library).casefold()
        matches = [m for m in images if m["basename"].casefold() == wanted]
        if len(matches) == 1:
            return matches[0], "EXACT_LIBRARY_BASENAME"
        if len(matches) > 1:
            exact = [m for m in matches if m["path"] == library]
            if len(exact) == 1:
                return exact[0], "EXACT_LIBRARY_PATH"
            return None, "AMBIGUOUS_LIBRARY"
        return None, "LIBRARY_NOT_LOADED"

    joined = " ".join(str(card.get(k) or "") for k in ("source", "title", "category")).casefold()
    if "il2cpp" in joined:
        matches = [m for m in images if m["basename"].casefold() == "libil2cpp.so"]
        if len(matches) == 1:
            return matches[0], "IL2CPP_SOURCE_INFERENCE"

    executable_so = [
        m for m in images
        if m["basename"].casefold().endswith(".so") and int(m.get("executableMappings") or 0) > 0
    ]
    if len(executable_so) == 1:
        return executable_so[0], "UNIQUE_EXECUTABLE_SO"
    return None, "MODULE_UNRESOLVED"


def _mapped_segment(module: dict, runtime_va: int, mappings: list[dict]) -> dict | None:
    path = module["path"]
    for row in mappings:
        if row.get("path") != path:
            continue
        if row["start"] <= runtime_va < row["end"]:
            return row
    return None


def correlate(catalog: dict, session: dict) -> dict:
    images = _module_images(session)
    mappings = _mappings(session)
    cards = catalog.get("cards") if isinstance(catalog, dict) else []
    if not isinstance(cards, list):
        cards = []

    rows: list[dict] = []
    unresolved: list[dict] = []
    native_locator_count = 0
    for card in cards:
        if not isinstance(card, dict):
            continue
        locator = card.get("locator")
        if not isinstance(locator, dict):
            continue
        rva = _number(locator.get("rva"))
        if rva is None or rva < 0:
            continue
        native_locator_count += 1
        module, match_mode = _match_module(locator, card, images)
        if module is None:
            unresolved.append({
                "id": card.get("id"),
                "title": card.get("title"),
                "rvaHex": _hex(rva),
                "library": locator.get("library") or locator.get("module"),
                "reason": match_mode,
            })
            continue
        runtime_va = module["loadBase"] + rva
        segment = _mapped_segment(module, runtime_va, mappings)
        rows.append({
            "id": card.get("id"),
            "title": card.get("title"),
            "verificationStage": card.get("verificationStage"),
            "rvaHex": _hex(rva),
            "library": locator.get("library") or locator.get("module"),
            "modulePath": module["path"],
            "moduleBasename": module["basename"],
            "loadBaseHex": _hex(module["loadBase"]),
            "runtimeVaHex": _hex(runtime_va),
            "mapped": segment is not None,
            "mappingPerms": None if segment is None else segment.get("perms"),
            "matchMode": match_mode,
            "runtimeEvidence": "PROCFS_MODULE_LAYOUT",
            "promotesBuildability": False,
        })

    mapped_count = sum(1 for row in rows if row["mapped"])
    return {
        "schema": SCHEMA,
        "mode": "READ_ONLY_PROCFS_CORRELATION",
        "writesTargetMemory": False,
        "injectsCode": False,
        "promotesBuildability": False,
        "process": session.get("process"),
        "moduleImageCount": len(images),
        "mappingCount": len(mappings),
        "nativeLocatorCount": native_locator_count,
        "correlationCount": len(rows),
        "mappedRuntimeVaCount": mapped_count,
        "unresolvedCount": len(unresolved),
        "correlations": rows,
        "unresolved": unresolved,
    }


def build_workspace_correlation(workspace: str | Path, session_path: str | Path | None = None,
                                output_path: str | Path | None = None) -> dict:
    root = Path(workspace)
    session_file = Path(session_path) if session_path else root / "runtime-session.json"
    output_file = Path(output_path) if output_path else root / "runtime-correlation.json"
    catalog = _json(root / "simple-catalog.json") or {"cards": []}
    session = _json(session_file)
    if not isinstance(session, dict):
        raise ValueError("runtime-session.json is missing or invalid")
    result = correlate(catalog, session)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
