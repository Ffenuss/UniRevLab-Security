from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-connected-report-1.0"


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _norm_hex(value: Any) -> str:
    if value in (None, "", 0, "0"):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip().lower()
    try:
        return f"0x{int(text, 0):x}"
    except Exception:
        return text


def _first(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = obj.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _method_index(path: Path, limit: int = 250000) -> tuple[dict[int, dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[int, dict[str, Any]] = {}
    by_rva: dict[str, list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    if not path.is_file():
        return by_id, by_rva, by_name
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for no, line in enumerate(stream):
            if no >= limit:
                break
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            mid = row.get("id")
            if isinstance(mid, int):
                by_id[mid] = row
            rva = _norm_hex(_first(row, "rva", "RVA", "address", "virtualAddress"))
            if rva:
                by_rva.setdefault(rva, []).append(row)
            name = str(_first(row, "name", "method", "methodName", "label") or "").strip().casefold()
            if name:
                by_name.setdefault(name, []).append(row)
    return by_id, by_rva, by_name


def _locator(card: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for source in (card.get("locator"), card.get("evidence"), card):
        if not isinstance(source, dict):
            continue
        for target, keys in {
            "methodId": ("methodId", "method_id", "id"),
            "class": ("class", "className", "type"),
            "method": ("method", "methodName", "name"),
            "rva": ("rva", "RVA", "address"),
            "entry": ("entry", "path", "file", "artifact"),
            "codeOffset": ("codeOffset", "offset"),
        }.items():
            if target not in out:
                value = _first(source, *keys)
                if value not in (None, ""):
                    out[target] = value
    if "rva" in out:
        out["rva"] = _norm_hex(out["rva"])
    return out


def _link_methods(locator: dict[str, Any], by_id: dict[int, dict[str, Any]], by_rva: dict[str, list[dict[str, Any]]], by_name: dict[str, list[dict[str, Any]]]) -> tuple[str, list[dict[str, Any]]]:
    mid = locator.get("methodId")
    if isinstance(mid, int) and mid in by_id:
        return "EXACT_METHOD_ID", [by_id[mid]]
    try:
        parsed = int(str(mid)) if mid not in (None, "") else None
    except Exception:
        parsed = None
    if parsed is not None and parsed in by_id:
        return "EXACT_METHOD_ID", [by_id[parsed]]
    rva = _norm_hex(locator.get("rva"))
    if rva and rva in by_rva:
        return "EXACT_RVA", by_rva[rva][:25]
    name = str(locator.get("method") or "").strip().casefold()
    if name and name in by_name:
        return "EXACT_NAME", by_name[name][:25]
    return "UNRESOLVED", []


def build_connected_report(workdir: str | Path, output_json: str | Path | None = None, output_md: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    catalog = _json(root / "simple-catalog.json")
    analysis = _json(root / "analysis.summary.json")
    security = _json(root / "security-surfaces.json")
    embedded = _json(root / "embedded-analysis.json")
    apktool = _json(root / "apktool-analysis.json")
    by_id, by_rva, by_name = _method_index(root / "analysis.methods.jsonl")
    rows: list[dict[str, Any]] = []
    exact = 0
    cards = catalog.get("cards") if isinstance(catalog.get("cards"), list) else []
    for card in cards:
        if not isinstance(card, dict):
            continue
        loc = _locator(card)
        link_status, methods = _link_methods(loc, by_id, by_rva, by_name)
        if link_status != "UNRESOLVED":
            exact += 1
        rows.append({
            "id": card.get("id"),
            "title": card.get("title"),
            "status": card.get("status"),
            "verificationStage": card.get("verificationStage"),
            "category": card.get("category"),
            "ownership": card.get("ownership"),
            "buildable": bool(card.get("buildable")),
            "actionable": bool(card.get("actionable")),
            "serverAudit": bool(card.get("serverAudit")),
            "locator": loc,
            "methodLinkStatus": link_status,
            "linkedMethods": methods,
            "description": card.get("description"),
        })
    out = {
        "schema": SCHEMA,
        "findingCount": len(rows),
        "exactLinked": exact,
        "unresolvedLinks": len(rows) - exact,
        "methodCatalogRows": len(by_id),
        "summary": {
            "targetProfile": analysis.get("targetProfile"),
            "total": catalog.get("total", 0),
            "important": catalog.get("important", 0),
            "buildable": catalog.get("buildable", 0),
            "actionable": catalog.get("actionable", 0),
            "serverAudit": catalog.get("serverAudit", 0),
        },
        "embedded": {
            "apktool": {"status": apktool.get("status"), "decoded": apktool.get("decoded"), "failed": apktool.get("failed")},
            "families": embedded.get("familyCounts") or embedded.get("families"),
            "manualImportRequired": False,
        },
        "securitySummary": security.get("summary") or security.get("counts"),
        "findings": rows,
    }
    if output_json:
        Path(output_json).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_md:
        md = ["# ModKit connected report", "", f"Findings: {len(rows)}", f"Exact method/locator links: {exact}", f"Unresolved links: {len(rows)-exact}", ""]
        for row in rows:
            md.append(f"## {row.get('title') or 'Finding'}")
            md.append(f"- Status: {row.get('status')}")
            md.append(f"- Verification: {row.get('verificationStage')}")
            md.append(f"- Link: {row.get('methodLinkStatus')}")
            loc = row.get("locator") or {}
            if loc:
                md.append("- Locator: " + ", ".join(f"{k}={v}" for k, v in loc.items()))
            for method in row.get("linkedMethods") or []:
                label = _first(method, "label", "name", "method", "methodName")
                rva = _norm_hex(_first(method, "rva", "address"))
                md.append(f"  - Method: {label or '?'}" + (f" @ {rva}" if rva else ""))
            if row.get("description"):
                md.append(f"- {row['description']}")
            md.append("")
        Path(output_md).write_text("\n".join(md), encoding="utf-8")
    return out
