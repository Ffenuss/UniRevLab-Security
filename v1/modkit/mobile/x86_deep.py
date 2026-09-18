"""Capstone-backed x86/x86-64 control-flow analysis for Android ELF targets.

Instruction decoding is delegated to the isolated Android JNI bridge. The backend
only analyzes exact ELF STT_FUNC ranges and never byte-scans for call opcodes.
Desktop tests can inject a deterministic decoder without requiring Android/JNI.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterable
import zipfile

from modkit.mobile.native_portable import ElfView, EM_386, EM_X86_64

SCHEMA = "modkit-x86-deep-1.0"
ENGINE_ID = "native.x86-deep-embedded"
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_FUNCTION_BYTES = 512 * 1024
MAX_TOTAL_CODE_BYTES = 64 * 1024 * 1024
MAX_INSTRUCTIONS_PER_FUNCTION = 8192
MAX_EDGES = 16000
MAX_FINDINGS = 2000

Decoder = Callable[[bytes, int, str, int], dict[str, Any]]


class X86ScanCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    return bool(cb()) if callable(cb) else False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise X86ScanCancelled("x86 scan cancelled")


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    installed = root / "installed-apks"
    if installed.is_dir():
        for path in sorted(installed.glob("*.apk")):
            if path not in paths:
                paths.append(path)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _function_regions(view: ElfView) -> list[dict[str, Any]]:
    funcs = [
        sym for sym in view.symbols
        if not sym.undefined and sym.sym_type == 2 and sym.value
        and 0 < sym.shndx < len(view.sections)
    ]
    by_section: dict[int, list[Any]] = {}
    for sym in funcs:
        by_section.setdefault(sym.shndx, []).append(sym)

    rows: list[dict[str, Any]] = []
    for shndx, symbols in by_section.items():
        sec = next((row for row in view.sections if row.index == shndx), None)
        if not sec or not sec.executable or sec.size <= 0:
            continue
        symbols.sort(key=lambda sym: (sym.value, sym.name))
        for idx, sym in enumerate(symbols):
            start = int(sym.value)
            if start < sec.addr or start >= sec.addr + sec.size:
                continue
            next_start = (
                int(symbols[idx + 1].value)
                if idx + 1 < len(symbols) else sec.addr + sec.size
            )
            size = int(sym.size or 0)
            end = start + size if size > 0 else next_start
            end = min(end, next_start, sec.addr + sec.size)
            if end <= start:
                continue
            rows.append({
                "name": sym.name or f"sub_{start:x}",
                "rva": start,
                "endRva": end,
                "size": end - start,
                "section": sec,
            })
    rows.sort(key=lambda row: (row["rva"], row["name"]))
    return rows


def _java_capstone_decode(code: bytes, address: int, arch: str,
                          max_instructions: int) -> dict[str, Any]:
    try:
        from java import jclass  # type: ignore
    except Exception as exc:
        return {
            "available": False,
            "error": f"java-bridge-unavailable:{exc.__class__.__name__}",
            "instructions": [],
        }

    try:
        bridge = jclass("dev.modkit.mobile.NativeDisasmBridge")
        raw = bridge.disassemble(
            code, int(address), arch, False, int(max_instructions)
        )
        obj = json.loads(str(raw))
        if not isinstance(obj, dict):
            raise ValueError("bridge returned non-object JSON")
        obj.setdefault("instructions", [])
        return obj
    except Exception as exc:
        return {
            "available": False,
            "error": f"capstone-bridge-failed:{exc.__class__.__name__}:{exc}",
            "instructions": [],
        }


def _edge_from_instruction(
    insn: dict[str, Any],
    *,
    source_rva: int,
    source_function: str,
    targets: dict[int, str],
) -> dict[str, Any] | None:
    is_call = bool(insn.get("isCall"))
    is_jump = bool(insn.get("isJump"))
    is_ret = bool(insn.get("isRet"))
    if not (is_call or is_jump or is_ret):
        return None

    address = int(insn.get("address") or 0)
    size = int(insn.get("size") or 0)
    has_target = bool(insn.get("hasImmediateTarget")) and insn.get("immediateTarget") is not None
    target = int(insn["immediateTarget"]) if has_target else None

    if is_ret:
        kind = "x86-return"
        edge_kind = "return"
        resolution = "RETURN"
    elif is_call:
        kind = "x86-direct-call" if has_target else "x86-indirect-call"
        edge_kind = "call" if has_target else "indirect-call"
        resolution = (
            "STATIC_SYMBOL" if target in targets
            else "DIRECT_IMMEDIATE" if has_target
            else "INDIRECT_UNRESOLVED"
        )
    else:
        kind = "x86-direct-jump" if has_target else "x86-indirect-jump"
        edge_kind = "branch" if has_target else "indirect-branch"
        resolution = (
            "STATIC_SYMBOL" if target in targets
            else "DIRECT_IMMEDIATE" if has_target
            else "INDIRECT_UNRESOLVED"
        )

    return {
        "sourceRva": source_rva,
        "sourceFunction": source_function,
        "instructionRva": address,
        "instructionSize": size,
        "bytes": str(insn.get("bytes") or ""),
        "mnemonic": str(insn.get("mnemonic") or ""),
        "opStr": str(insn.get("opStr") or ""),
        "kind": kind,
        "edgeKind": edge_kind,
        "targetRva": target,
        "targetFunction": targets.get(target) if target is not None else None,
        "targetResolution": resolution,
        "regsRead": [str(x) for x in (insn.get("regsRead") or [])],
        "regsWrite": [str(x) for x in (insn.get("regsWrite") or [])],
        "instructionWidth": size,
        "decoder": "capstone",
    }


def analyze_elf(
    data: bytes,
    *,
    apk_name: str = "",
    entry: str = "",
    decoder: Decoder | None = None,
    cb: Any | None = None,
) -> dict[str, Any]:
    view = ElfView(data)
    if view.machine not in {EM_386, EM_X86_64}:
        return {
            "available": False, "arch": "non-x86", "functionCount": 0,
            "edgeCount": 0, "edges": [], "findings": [],
        }

    arch = "x86" if view.machine == EM_386 else "x86_64"
    regions = _function_regions(view)
    targets = {int(row["rva"]): str(row["name"]) for row in regions}
    decode = decoder or _java_capstone_decode
    edges: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    total = 0
    analyzed = 0
    decoder_available = False
    decoder_version: str | None = None

    for row in regions:
        _check(cb)
        size = int(row["size"])
        if size <= 0 or size > MAX_FUNCTION_BYTES or total + size > MAX_TOTAL_CODE_BYTES:
            continue
        sec = row["section"]
        rel_start = int(row["rva"]) - sec.addr
        file_start = sec.offset + rel_start
        if rel_start < 0 or file_start < 0 or file_start + size > len(data):
            continue
        raw = data[file_start:file_start + size]
        total += len(raw)

        decoded = decode(raw, int(row["rva"]), arch, MAX_INSTRUCTIONS_PER_FUNCTION)
        if not isinstance(decoded, dict) or not decoded.get("available"):
            errors.append({
                "function": row["name"],
                "rva": row["rva"],
                "error": str(decoded.get("error") if isinstance(decoded, dict) else "decoder-invalid"),
            })
            continue

        decoder_available = True
        if decoded.get("version"):
            decoder_version = str(decoded.get("version"))
        instructions = decoded.get("instructions") or []
        if not isinstance(instructions, list):
            errors.append({
                "function": row["name"], "rva": row["rva"],
                "error": "decoder-instructions-not-list",
            })
            continue

        analyzed += 1
        for insn in instructions:
            if not isinstance(insn, dict):
                continue
            edge = _edge_from_instruction(
                insn,
                source_rva=int(row["rva"]),
                source_function=str(row["name"]),
                targets=targets,
            )
            if edge:
                edges.append(edge)
                if len(edges) >= MAX_EDGES:
                    break
        if len(edges) >= MAX_EDGES:
            break

    findings: list[dict[str, Any]] = []
    for idx, edge in enumerate(edges[:MAX_FINDINGS]):
        findings.append({
            "id": "x86-edge:" + hashlib.sha256(
                f"{apk_name}!{entry}!{idx}!{edge.get('instructionRva')}!{edge.get('kind')}".encode()
            ).hexdigest()[:20],
            "kind": "X86_CONTROL_FLOW_EDGE",
            "title": (
                f"{edge.get('sourceFunction') or 'function'} → "
                f"{edge.get('targetFunction') or edge.get('targetResolution')}"
            ),
            "category": "Native/X86 Control Flow",
            "status": "CORRELATED_EVIDENCE",
            "engineId": ENGINE_ID,
            "apk": apk_name,
            "entry": entry,
            "arch": arch,
            **edge,
            "instructionBoundaryConfirmed": True,
            "functionBoundarySource": "ELF_FUNCTION_SYMBOL",
            "patchReady": False,
            "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME",
            "trustBoundary": "local",
            "evidenceRole": "capstone-x86-symbol-bounded-control-flow",
        })

    return {
        "available": bool(regions) and decoder_available,
        "decoderAvailable": decoder_available,
        "decoder": "capstone",
        "decoderVersion": decoder_version,
        "arch": arch,
        "bits": view.bits,
        "functionCount": len(regions),
        "analyzedFunctionCount": analyzed,
        "scannedCodeBytes": total,
        "edgeCount": len(edges),
        "edges": edges,
        "findingCount": len(findings),
        "findings": findings,
        "errors": errors,
        "policy": {
            "symbolBoundedOnly": True,
            "strippedRegionGuessing": False,
            "rawOpcodeByteScanning": False,
            "instructionBoundaryFromCapstone": True,
            "indirectTargetsResolvedWithoutProof": False,
            "patchReadyFromControlFlow": False,
        },
    }


def scan_apk_paths(
    paths: Iterable[str | Path],
    output_path: str | Path | None = None,
    cb: Any | None = None,
) -> dict[str, Any]:
    libraries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    apk_count = 0

    for raw_path in paths:
        _check(cb)
        apk = Path(raw_path)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    if info.is_dir() or info.file_size < 52 or info.file_size > MAX_LIBRARY_BYTES:
                        continue
                    low = info.filename.casefold()
                    if not low.endswith(".so") or not (
                        "/x86/" in f"/{low}" or "/x86_64/" in f"/{low}"
                    ):
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_LIBRARY_BYTES + 1)
                    except Exception:
                        continue
                    if data[:4] != b"\x7fELF":
                        continue
                    try:
                        report = analyze_elf(
                            data, apk_name=apk.name, entry=info.filename, cb=cb
                        )
                    except Exception as exc:
                        libraries.append({
                            "apk": apk.name,
                            "entry": info.filename,
                            "available": False,
                            "error": str(exc),
                        })
                        continue
                    libraries.append({
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": info.file_size,
                        **{
                            k: v for k, v in report.items()
                            if k not in {"edges", "findings", "errors"}
                        },
                        "errorCount": len(report.get("errors") or []),
                    })
                    findings.extend(report.get("findings") or [])
                    if len(findings) >= MAX_FINDINGS:
                        findings = findings[:MAX_FINDINGS]
        except X86ScanCancelled:
            raise
        except Exception:
            continue

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "libraryCount": len(libraries),
        "availableLibraryCount": sum(1 for row in libraries if row.get("available")),
        "functionCount": sum(int(row.get("functionCount") or 0) for row in libraries),
        "edgeCount": sum(int(row.get("edgeCount") or 0) for row in libraries),
        "libraries": libraries,
        "findingCount": len(findings),
        "findings": findings,
        "policy": {
            "symbolBoundedOnly": True,
            "strippedRegionGuessing": False,
            "rawOpcodeByteScanning": False,
            "capstoneRequiredForInstructionLayer": True,
        },
    }
    if output_path:
        Path(output_path).write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    return out


def scan_workspace(
    workdir: str | Path,
    output_path: str | Path | None = None,
    cb: Any | None = None,
) -> dict[str, Any]:
    return scan_apk_paths(_workspace_apks(Path(workdir)), output_path, cb)
