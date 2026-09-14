"""Normalize evidence exported by heavyweight external reverse-engineering engines.

The bridge is deliberately data-only: ModKit does not execute untrusted tool commands or target
code. Ghidra/Rizin/Cpp2IL/Hermes/Frida outputs can be imported and correlated with local evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-external-engine-evidence-1.0"
SUPPORTED = {
    "ghidra": "ghidra.bridge",
    "rizin": "rizin.bridge",
    "cpp2il": "cpp2il.bridge",
    "hermes": "hermes.deep-bridge",
    "flutter": "flutter.deep-bridge",
    "frida": "frida.local-bridge",
    "apktool": "apktool.bridge",
    "ptrace": "ptrace.bridge",
}
MAX_FILE = 96 * 1024 * 1024
MAX_RECORDS = 20000


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _flatten_json(value: Any, path: str = "$") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    stack: list[tuple[str, Any]] = [(path, value)]
    while stack and len(rows) < MAX_RECORDS:
        current_path, current = stack.pop()
        if isinstance(current, dict):
            interesting = {k: v for k, v in current.items() if k.lower() in {
                "name", "address", "offset", "rva", "va", "size", "type", "kind", "signature",
                "prototype", "symbol", "function", "caller", "callee", "from", "to", "module",
                "class", "method", "namespace", "assembly", "event", "thread", "tid", "pid"
            } and isinstance(v, (str, int, float, bool))}
            if interesting:
                rows.append({"path": current_path, "fields": interesting})
            for key, child in reversed(list(current.items())):
                if isinstance(child, (dict, list)):
                    stack.append((f"{current_path}.{key}", child))
        elif isinstance(current, list):
            for idx in range(len(current) - 1, -1, -1):
                child = current[idx]
                if isinstance(child, (dict, list)):
                    stack.append((f"{current_path}[{idx}]", child))
                elif isinstance(child, (str, int, float, bool)) and len(rows) < MAX_RECORDS:
                    rows.append({"path": f"{current_path}[{idx}]", "value": child})
    return rows


def _parse_text(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        rows.append({"line": no, "text": stripped[:4000]})
        if len(rows) >= MAX_RECORDS:
            break
    return rows


def _jsonl(text: str) -> list[Any] | None:
    values: list[Any] = []
    nonempty = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        nonempty += 1
        try:
            values.append(json.loads(line))
        except Exception:
            return None
        if len(values) >= MAX_RECORDS:
            break
    return values if nonempty else None


def _read_candidate(path: Path) -> tuple[str, Any]:
    data = path.read_bytes()
    text = data.decode("utf-8", "replace")
    suffix = path.suffix.lower()
    stripped = text.lstrip("\ufeff \t\r\n")
    # Android's document picker may copy a JSON export into a neutral .dat name. Sniff content
    # before trusting the local temporary suffix so structured evidence stays structured.
    if suffix == ".json" or stripped.startswith(("{", "[")):
        try:
            return "json", json.loads(stripped)
        except Exception:
            pass
    if suffix in {".jsonl", ".ndjson"}:
        values = _jsonl(text)
        if values is not None:
            return "jsonl", values
    if "\n" in text:
        values = _jsonl(text)
        if values is not None and len(values) > 1:
            return "jsonl", values
    return "text", text


def normalize_file(tool: str, input_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    tool_key = str(tool or "").strip().lower()
    if tool_key not in SUPPORTED:
        raise ValueError(f"unsupported bridge: {tool_key}")
    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > MAX_FILE:
        raise ValueError("bridge input is too large")

    source_kind, payload = _read_candidate(source)
    records = _flatten_json(payload) if source_kind in {"json", "jsonl"} else _parse_text(str(payload))
    out = {
        "schema": SCHEMA,
        "tool": tool_key,
        "engineId": SUPPORTED[tool_key],
        "source": source.name,
        "sourceKind": source_kind,
        "sourceSize": source.stat().st_size,
        "sourceSha256": _sha256(source),
        "recordCount": len(records),
        "records": records,
        "executesImportedCode": False,
        "trusted": False,
        "status": "IMPORTED_EVIDENCE",
        "notes": "Imported external evidence is corroborating data until local locators/runtime proof confirm it.",
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def bridge_catalog_json() -> str:
    return json.dumps({"schema": "modkit-engine-bridge-catalog-1.0", "tools": SUPPORTED}, ensure_ascii=False, sort_keys=True)
