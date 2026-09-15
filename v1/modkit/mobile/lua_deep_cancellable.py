"""Cooperative-cancellation adapter for the embedded Lua bytecode backend.

The canonical decoder and evidence schema remain in ``lua_deep``.  This release-path
adapter avoids duplicating that parser: it subclasses ``Reader`` so every substantial
advance through a Lua chunk observes the Android cancellation callback, and it replaces
single-shot ZIP reads with bounded chunked reads.  Cancellation is never converted into
opaque/parse-failed evidence and a partial report is never published.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

from modkit.mobile import lua_deep as _base

SCHEMA = _base.SCHEMA
ENGINE_ID = _base.ENGINE_ID
READ_CHUNK_BYTES = 1024 * 1024
PARSER_CHECK_BYTES = 16 * 1024
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")


class LuaScanCancelled(RuntimeError):
    """Explicit cooperative cancellation for Lua extraction/decoding."""


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise LuaScanCancelled("Lua deep scan cancelled")


class CancellableReader(_base.Reader):
    def __init__(self, data: bytes, cb: Any | None = None):
        super().__init__(data)
        self._cancel_cb = cb
        self._next_cancel_check = 0
        _check(cb)

    def raw(self, n: int) -> bytes:
        if self.pos >= self._next_cancel_check or n >= PARSER_CHECK_BYTES:
            _check(self._cancel_cb)
            self._next_cancel_check = self.pos + PARSER_CHECK_BYTES
        return super().raw(n)


def parse_chunk(data: bytes, cb: Any | None = None) -> dict[str, Any]:
    reader = CancellableReader(data, cb)
    header = reader.header()
    reader.prototype(None, "0")
    _check(cb)
    return {
        "status": "BYTECODE_DISASSEMBLED",
        "recoveryLevel": "DISASSEMBLED_METADATA",
        "header": header,
        "prototypeCount": reader.proto_total,
        "storedPrototypeCount": len(reader.protos),
        "instructionCount": reader.instruction_total,
        "constantCount": reader.constant_total,
        "debugRecordCount": reader.debug_total,
        "strings": reader.strings,
        "prototypes": reader.protos,
        "trailingBytes": len(data) - reader.pos,
        "truncated": (
            len(reader.protos) < reader.proto_total
            or reader.stored_instructions < reader.instruction_total
            or reader.stored_constants < reader.constant_total
        ),
    }


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cb: Any | None = None) -> bytes:
    chunks: list[bytes] = []
    with zf.open(info, "r") as source:
        while True:
            _check(cb)
            chunk = source.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    _check(cb)
    return b"".join(chunks)


def _printable(data: bytes, cb: Any | None = None, limit: int = 120) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for no, match in enumerate(PRINTABLE.finditer(data[:8 * 1024 * 1024])):
        if (no & 0xFF) == 0:
            _check(cb)
        text = match.group().decode("utf-8", "replace").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text[:300])
            if len(out) >= limit:
                break
    _check(cb)
    return out


def _opaque_report(data: bytes, entry: str, cb: Any | None = None) -> dict[str, Any]:
    _check(cb)
    low = entry.casefold()
    markers: list[str] = []
    if "xlua" in low or b"xlua" in data[:1024].lower():
        markers.append("xLua")
    if "slua" in low or b"slua" in data[:1024].lower():
        markers.append("SLua")
    if data.startswith(b"\x1bLJ"):
        version = data[3] if len(data) > 3 else 0
        return {
            "status": "LUAJIT_HEADER_ONLY", "recoveryLevel": "DISASSEMBLED_METADATA", "runtime": "LuaJIT",
            "bytecodeVersion": version, "markers": markers + ["luajit"], "strings": _printable(data, cb),
            "structuralOnly": True,
        }
    if data.startswith(b"\x1bLua") and len(data) > 4 and data[4] == 0x54:
        return {
            "status": "STANDARD_5_4_HEADER_ONLY", "recoveryLevel": "DISASSEMBLED_METADATA", "runtime": "Lua 5.4",
            "markers": markers + ["lua-bytecode-5.4"], "strings": _printable(data, cb), "structuralOnly": True,
            "blocker": "Lua 5.4 variable-length prototype layout is not promoted to decoded instructions by this parser",
        }
    return {
        "status": "OPAQUE_OR_ENCRYPTED", "recoveryLevel": "OPAQUE", "runtime": "Lua-compatible container",
        "markers": markers, "strings": _printable(data, cb), "structuralOnly": True,
        "blocker": "No validated standard Lua bytecode header; encrypted/custom xLua/SLua containers are not guessed",
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    apk_count = 0
    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    if len(chunks) >= _base.MAX_CHUNKS:
                        break
                    if info.is_dir() or info.file_size <= 0 or info.file_size > _base.MAX_ENTRY_BYTES:
                        continue
                    low = info.filename.casefold()
                    likely = low.endswith((".luac", ".luae", ".lua")) or "xlua" in low or "slua" in low or "/lua/" in "/" + low
                    if not likely:
                        continue
                    try:
                        data = _read_entry(zf, info, cb)
                    except LuaScanCancelled:
                        raise
                    except Exception as exc:
                        if _cancelled(cb):
                            raise LuaScanCancelled("Lua deep scan cancelled") from exc
                        errors.append({"apk": apk.name, "entry": info.filename, "error": str(exc)})
                        continue
                    if not _base._candidate(info.filename, data):
                        continue
                    base = {"apk": apk.name, "entry": info.filename, "size": info.file_size}
                    try:
                        detail = (
                            parse_chunk(data, cb)
                            if data.startswith(b"\x1bLua") and len(data) > 4 and data[4] in (0x51, 0x52, 0x53)
                            else _opaque_report(data, info.filename, cb)
                        )
                    except LuaScanCancelled:
                        raise
                    except Exception as exc:
                        if _cancelled(cb):
                            raise LuaScanCancelled("Lua deep scan cancelled") from exc
                        detail = _opaque_report(data, info.filename, cb)
                        detail["status"] = "BYTECODE_PARSE_FAILED"
                        detail["parseError"] = str(exc)
                    row = {**base, **detail}
                    chunks.append(row)
                    findings.append({
                        "id": "lua-chunk:" + _base._id(apk.name, info.filename),
                        "kind": "LUA_BYTECODE", "title": f"Lua bytecode: {Path(info.filename).name}",
                        "category": "Runtime/Lua", "status": row.get("status"), "family": "lua", "engineId": ENGINE_ID,
                        "apk": apk.name, "entry": info.filename, "recoveryLevel": row.get("recoveryLevel"),
                        "prototypeCount": int(row.get("prototypeCount") or 0), "instructionCount": int(row.get("instructionCount") or 0),
                        "markers": row.get("markers") or [], "strings": row.get("strings") or [],
                        "ownershipKind": "APP_OR_GAME", "trustBoundary": "local", "patchReady": False,
                        "structuralOnly": True, "evidenceRole": "embedded-lua-bytecode",
                    })
                    protos = row.get("prototypes", [])[:500] if isinstance(row.get("prototypes"), list) else []
                    for proto_no, proto in enumerate(protos):
                        if (proto_no & 0x7F) == 0:
                            _check(cb)
                        source = str(proto.get("source") or Path(info.filename).name)
                        label = f"{source}:{proto.get('lineDefined',0)} [{proto.get('path')}]"
                        domain = str(proto.get("gameplayDomain") or "")
                        findings.append({
                            "id": "lua-proto:" + _base._id(apk.name, info.filename, str(proto.get("path"))),
                            "kind": "LUA_PROTOTYPE", "title": label,
                            "category": "Gameplay/Lua" if domain else "Runtime/Lua", "status": "BYTECODE_STRUCTURAL",
                            "family": "lua", "engineId": ENGINE_ID, "apk": apk.name, "entry": info.filename,
                            "prototypePath": proto.get("path"), "byteOffset": proto.get("byteOffset"), "source": source,
                            "lineDefined": proto.get("lineDefined"), "lastLineDefined": proto.get("lastLineDefined"),
                            "instructionCount": proto.get("instructionCount"), "constantCount": proto.get("constantCount"),
                            "opcodeHistogram": proto.get("opcodeHistogram") or {}, "gameplayDomain": domain,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local", "patchReady": False,
                            "structuralOnly": True, "evidenceRole": "embedded-lua-prototype",
                        })
        except LuaScanCancelled:
            raise
        except Exception as exc:
            if _cancelled(cb):
                raise LuaScanCancelled("Lua deep scan cancelled") from exc
            errors.append({"apk": apk.name, "error": str(exc)})

    _check(cb)
    out = {
        "schema": SCHEMA, "engineId": ENGINE_ID, "bundled": True, "manualImportRequired": False,
        "passive": True, "executesTargetCode": False, "cancelAware": cb is not None,
        "available": bool(chunks), "apkCount": apk_count, "chunkCount": len(chunks), "findingCount": len(findings),
        "chunks": chunks, "findings": findings, "errors": errors[:100], "truncated": len(chunks) >= _base.MAX_CHUNKS,
    }
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_base._workspace_apks(root), output_path, cb)
