"""Capstone-backed x86/x86-64 control-flow and conservative data-flow analysis.

Instruction decoding is delegated to the isolated Android JNI bridge. The backend
analyzes exact ELF STT_FUNC ranges and never byte-scans for x86 opcodes. Operand
semantics are consumed only when Capstone provided structured operands.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterable
import zipfile

from modkit.mobile.cfg_flow import (
    build_cfg, clone_token_list, clone_token_map, merge_token_lists, merge_token_maps,
)
from modkit.mobile.native_portable import ElfView, EM_386, EM_X86_64

SCHEMA = "modkit-x86-deep-1.2"
ENGINE_ID = "native.x86-deep-embedded"
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_FUNCTION_BYTES = 512 * 1024
MAX_TOTAL_CODE_BYTES = 64 * 1024 * 1024
MAX_INSTRUCTIONS_PER_FUNCTION = 8192
MAX_EDGES = 16000
MAX_FINDINGS = 2000
MAX_STRING_BYTES = 512

Decoder = Callable[[bytes, int, str, int], dict[str, Any]]

_X64_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_X64_CALLER_SAVED = {
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
}
_X86_CALLER_SAVED = {"eax", "ecx", "edx"}
_REG_ALIASES_X64 = {
    "rax": "rax", "eax": "rax",
    "rbx": "rbx", "ebx": "rbx",
    "rcx": "rcx", "ecx": "rcx",
    "rdx": "rdx", "edx": "rdx",
    "rsi": "rsi", "esi": "rsi",
    "rdi": "rdi", "edi": "rdi",
    "rbp": "rbp", "ebp": "rbp",
    "rsp": "rsp", "esp": "rsp",
    "r8": "r8", "r8d": "r8",
    "r9": "r9", "r9d": "r9",
    "r10": "r10", "r10d": "r10",
    "r11": "r11", "r11d": "r11",
    "r12": "r12", "r12d": "r12",
    "r13": "r13", "r13d": "r13",
    "r14": "r14", "r14d": "r14",
    "r15": "r15", "r15d": "r15",
}
_REG_ALIASES_X86 = {
    "eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
    "esi": "esi", "edi": "edi", "ebp": "ebp", "esp": "esp",
}


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


def _java_capstone_decode(
    code: bytes,
    address: int,
    arch: str,
    max_instructions: int,
) -> dict[str, Any]:
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


def _canonical_reg(name: Any, arch: str) -> str | None:
    low = str(name or "").casefold()
    if arch == "x86_64":
        return _REG_ALIASES_X64.get(low)
    return _REG_ALIASES_X86.get(low)


def _operands(insn: dict[str, Any]) -> list[dict[str, Any]]:
    value = insn.get("operands") or []
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _memory_address(insn: dict[str, Any], operand: dict[str, Any], arch: str) -> int | None:
    if str(operand.get("type") or "") != "MEM":
        return None
    mem = operand.get("mem")
    if not isinstance(mem, dict):
        return None
    base = str(mem.get("base") or "").casefold()
    index = str(mem.get("index") or "").casefold()
    disp = int(mem.get("disp") or 0)
    address = int(insn.get("address") or 0)
    size = int(insn.get("size") or 0)
    if arch == "x86_64" and base == "rip" and not index:
        return address + size + disp
    if not base and not index and disp >= 0:
        return disp
    return None


def _string_token(view: ElfView, address: int) -> dict[str, Any] | None:
    for sec in view.sections:
        if not sec.allocated or sec.executable or sec.size <= 0:
            continue
        if not (sec.addr <= address < sec.addr + sec.size):
            continue
        rel = address - sec.addr
        start = sec.offset + rel
        if start < 0 or start >= len(view.data):
            return None
        end = min(len(view.data), sec.offset + sec.size, start + MAX_STRING_BYTES)
        raw = view.data[start:end]
        zero = raw.find(b"\0")
        if zero < 0:
            return None
        raw = raw[:zero]
        if not raw or any(byte < 0x20 or byte > 0x7E for byte in raw):
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return {
            "kind": "string",
            "value": text,
            "address": address,
            "section": sec.name,
        }
    return None


def _relocation_symbols(view: ElfView) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in view.relocations:
        symbol = str(row.get("symbol") or "")
        offset = row.get("offset")
        if not symbol or not isinstance(offset, int):
            continue
        out.setdefault(offset, symbol)
    return out


def _value_from_operand(
    operand: dict[str, Any],
    *,
    state: dict[str, dict[str, Any]],
    insn: dict[str, Any],
    arch: str,
    view: ElfView,
    relocation_symbols: dict[int, str],
    lea: bool = False,
) -> dict[str, Any] | None:
    kind = str(operand.get("type") or "")
    if kind == "REG":
        reg = _canonical_reg(operand.get("reg"), arch)
        return dict(state[reg]) if reg and reg in state else None
    if kind == "IMM":
        return {"kind": "immediate", "value": int(operand.get("imm") or 0)}
    if kind != "MEM":
        return None

    address = _memory_address(insn, operand, arch)
    if address is None:
        return None
    symbol = relocation_symbols.get(address)
    if symbol:
        return {
            "kind": "import-slot" if lea else "import-function",
            "symbol": symbol,
            "address": address,
        }
    if lea:
        return _string_token(view, address) or {"kind": "address", "address": address}
    return {"kind": "memory", "address": address}


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
    has_target = (
        bool(insn.get("hasImmediateTarget"))
        and insn.get("immediateTarget") is not None
    )
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


def _plt_import_targets(
    view: ElfView,
    arch: str,
    decoder: Decoder,
    relocation_symbols: dict[int, str],
) -> dict[int, str]:
    out: dict[int, str] = {}
    if not relocation_symbols:
        return out
    for sec in view.sections:
        if sec.name not in {".plt", ".plt.sec"} or not sec.executable or sec.size <= 0:
            continue
        raw = view._slice(sec)
        if not raw or len(raw) > MAX_FUNCTION_BYTES:
            continue
        decoded = decoder(raw, sec.addr, arch, MAX_INSTRUCTIONS_PER_FUNCTION)
        if not isinstance(decoded, dict) or not decoded.get("available"):
            continue
        instructions = decoded.get("instructions") or []
        if not isinstance(instructions, list):
            continue
        for insn in instructions:
            if not isinstance(insn, dict) or not insn.get("isJump"):
                continue
            ops = _operands(insn)
            if not ops:
                continue
            slot = _memory_address(insn, ops[0], arch)
            symbol = relocation_symbols.get(slot) if slot is not None else None
            if symbol:
                out[int(insn.get("address") or 0)] = symbol
    return out


def _capture_arguments(
    arch: str,
    state: dict[str, dict[str, Any]],
    stack_args: list[dict[str, Any] | None],
) -> list[dict[str, Any] | None]:
    if arch == "x86_64":
        return [dict(state[reg]) if reg in state else None for reg in _X64_ARG_REGS]
    return [dict(row) if isinstance(row, dict) else None for row in stack_args[:8]]


def _enrich_call_edge(
    edge: dict[str, Any],
    insn: dict[str, Any],
    *,
    arch: str,
    state: dict[str, dict[str, Any]],
    stack_args: list[dict[str, Any] | None],
    relocation_symbols: dict[int, str],
    plt_targets: dict[int, str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    item = dict(edge)
    target = item.get("targetRva")
    if isinstance(target, int) and target in plt_targets:
        item["targetFunction"] = plt_targets[target]
        item["targetResolution"] = "ELF_RELOCATION_PLT"

    ops = _operands(insn)
    if not item.get("targetFunction") and ops:
        first = ops[0]
        if str(first.get("type") or "") == "MEM":
            slot = _memory_address(insn, first, arch)
            symbol = relocation_symbols.get(slot) if slot is not None else None
            if symbol:
                item["targetFunction"] = symbol
                item["targetResolution"] = "ELF_RELOCATION_MEMORY"
                item["relocationSlotRva"] = slot
        elif str(first.get("type") or "") == "REG":
            reg = _canonical_reg(first.get("reg"), arch)
            token = state.get(reg) if reg else None
            if token and token.get("kind") == "dynamic-symbol":
                item["targetFunction"] = token.get("symbol")
                item["targetResolution"] = "DLSYM_RESULT_FLOW"
                item["dynamicLookupCallRva"] = token.get("sourceCallRva")
            elif token and token.get("kind") == "import-function":
                item["targetFunction"] = token.get("symbol")
                item["targetResolution"] = "ELF_RELOCATION_REGISTER_FLOW"
                item["relocationSlotRva"] = token.get("address")

    args = _capture_arguments(arch, state, stack_args)
    if any(row is not None for row in args):
        item["argumentEvidence"] = args

    return_value: dict[str, Any] | None = None
    target_name = str(item.get("targetFunction") or "")
    if target_name == "dlsym" and len(args) >= 2:
        symbol_arg = args[1]
        if symbol_arg and symbol_arg.get("kind") == "string":
            symbol_name = str(symbol_arg.get("value") or "")
            if symbol_name:
                item["lookupIdentifier"] = symbol_name
                item["lookupIdentifierAddress"] = symbol_arg.get("address")
                item["dynamicLookup"] = True
                return_value = {
                    "kind": "dynamic-symbol",
                    "symbol": symbol_name,
                    "sourceCallRva": item.get("instructionRva"),
                }
    return item, return_value


def _run_block(
    instructions: list[dict[str, Any]],
    *,
    block_start: int,
    row: dict[str, Any],
    arch: str,
    view: ElfView,
    targets: dict[int, str],
    relocation_symbols: dict[int, str],
    plt_targets: dict[int, str],
    initial_state: dict[str, dict[str, Any]],
    initial_stack_args: list[dict[str, Any] | None],
    cb: Any | None,
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any] | None],
    list[dict[str, Any]],
]:
    state = clone_token_map(initial_state)
    stack_args = clone_token_list(initial_stack_args)
    edges: list[dict[str, Any]] = []

    for index, insn in enumerate(instructions):
        if (index & 0x3FF) == 0:
            _check(cb)
        if not isinstance(insn, dict):
            continue
        mnemonic = str(insn.get("mnemonic") or "").casefold()
        ops = _operands(insn)
        handled_writes: set[str] = set()

        if mnemonic in {"mov", "movabs"} and len(ops) >= 2 and ops[0].get("type") == "REG":
            dest = _canonical_reg(ops[0].get("reg"), arch)
            if dest:
                token = _value_from_operand(
                    ops[1], state=state, insn=insn, arch=arch, view=view,
                    relocation_symbols=relocation_symbols,
                )
                if token is None:
                    state.pop(dest, None)
                else:
                    state[dest] = token
                handled_writes.add(dest)

        elif mnemonic == "lea" and len(ops) >= 2 and ops[0].get("type") == "REG":
            dest = _canonical_reg(ops[0].get("reg"), arch)
            if dest:
                token = _value_from_operand(
                    ops[1], state=state, insn=insn, arch=arch, view=view,
                    relocation_symbols=relocation_symbols, lea=True,
                )
                if token is None:
                    state.pop(dest, None)
                else:
                    state[dest] = token
                handled_writes.add(dest)

        elif mnemonic == "xor" and len(ops) >= 2:
            left = _canonical_reg(ops[0].get("reg"), arch) if ops[0].get("type") == "REG" else None
            right = _canonical_reg(ops[1].get("reg"), arch) if ops[1].get("type") == "REG" else None
            if left and left == right:
                state[left] = {"kind": "immediate", "value": 0}
                handled_writes.add(left)

        if arch == "x86" and mnemonic == "push" and ops:
            token = _value_from_operand(
                ops[0], state=state, insn=insn, arch=arch, view=view,
                relocation_symbols=relocation_symbols,
            )
            stack_args.insert(0, token)
            del stack_args[8:]

        edge = _edge_from_instruction(
            insn,
            source_rva=int(row["rva"]),
            source_function=str(row["name"]),
            targets=targets,
        )
        return_value: dict[str, Any] | None = None
        if edge and edge["edgeKind"] in {"call", "indirect-call"}:
            edge, return_value = _enrich_call_edge(
                edge, insn, arch=arch, state=state, stack_args=stack_args,
                relocation_symbols=relocation_symbols, plt_targets=plt_targets,
            )
            caller_saved = _X64_CALLER_SAVED if arch == "x86_64" else _X86_CALLER_SAVED
            for reg in caller_saved:
                state.pop(reg, None)
            if return_value is not None:
                state["rax" if arch == "x86_64" else "eax"] = return_value
            stack_args.clear()
        if edge:
            edge["basicBlockRva"] = block_start
            edge["cfgReachable"] = True
            edges.append(edge)

        for written in insn.get("regsWrite") or []:
            reg = _canonical_reg(written, arch)
            if reg and reg not in handled_writes:
                if not (edge and edge["edgeKind"] in {"call", "indirect-call"}):
                    state.pop(reg, None)

    return state, stack_args, edges


def _function_flow(
    instructions: list[dict[str, Any]],
    *,
    row: dict[str, Any],
    arch: str,
    view: ElfView,
    targets: dict[int, str],
    relocation_symbols: dict[int, str],
    plt_targets: dict[int, str],
    cb: Any | None,
) -> dict[str, Any]:
    cfg = build_cfg(instructions, arch=arch)
    blocks = cfg.get("blocks") or []
    entry = cfg.get("entry")
    if entry is None or not blocks:
        return {
            "edges": [],
            "basicBlockCount": 0,
            "reachableBlockCount": 0,
            "cfgEdgeCount": 0,
            "cfgConverged": True,
        }

    by_start = {int(block["start"]): block for block in blocks}
    incoming_state: dict[int, dict[str, dict[str, Any]]] = {int(entry): {}}
    incoming_stack: dict[int, list[dict[str, Any] | None]] = {int(entry): []}
    worklist: list[int] = [int(entry)]
    queued: set[int] = {int(entry)}
    block_edges: dict[int, list[dict[str, Any]]] = {}
    reached: set[int] = set()
    iterations = 0
    max_iterations = max(64, len(blocks) * 64)

    while worklist and iterations < max_iterations:
        _check(cb)
        block_start = worklist.pop(0)
        queued.discard(block_start)
        block = by_start.get(block_start)
        if block is None:
            continue
        reached.add(block_start)
        iterations += 1
        state, stack_args, produced = _run_block(
            block.get("instructions") or [],
            block_start=block_start,
            row=row,
            arch=arch,
            view=view,
            targets=targets,
            relocation_symbols=relocation_symbols,
            plt_targets=plt_targets,
            initial_state=incoming_state.get(block_start, {}),
            initial_stack_args=incoming_stack.get(block_start, []),
            cb=cb,
        )
        block_edges[block_start] = produced

        for raw_successor in block.get("successors") or []:
            successor = int(raw_successor)
            if successor not in by_start:
                continue
            candidate_state = clone_token_map(state)
            candidate_stack = clone_token_list(stack_args)
            if successor not in incoming_state:
                incoming_state[successor] = candidate_state
                incoming_stack[successor] = candidate_stack
                changed = True
            else:
                merged_state = merge_token_maps(
                    incoming_state[successor], candidate_state
                )
                merged_stack = merge_token_lists(
                    incoming_stack.get(successor, []), candidate_stack
                )
                changed = (
                    merged_state != incoming_state[successor]
                    or merged_stack != incoming_stack.get(successor, [])
                )
                if changed:
                    incoming_state[successor] = merged_state
                    incoming_stack[successor] = merged_stack
            if changed and successor not in queued:
                worklist.append(successor)
                queued.add(successor)

    edges: list[dict[str, Any]] = []
    for block in blocks:
        block_start = int(block["start"])
        if block_start in reached:
            edges.extend(block_edges.get(block_start, []))

    return {
        "edges": edges,
        "basicBlockCount": len(blocks),
        "reachableBlockCount": len(reached),
        "cfgEdgeCount": int(cfg.get("edgeCount") or 0),
        "cfgConverged": not worklist,
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
    relocation_symbols = _relocation_symbols(view)
    plt_targets = _plt_import_targets(view, arch, decode, relocation_symbols)

    edges: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    total = 0
    analyzed = 0
    decoder_available = False
    decoder_version: str | None = None
    operand_detail_available = False
    basic_block_count = 0
    reachable_block_count = 0
    cfg_edge_count = 0
    cfg_converged = True

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
                "error": str(
                    decoded.get("error") if isinstance(decoded, dict)
                    else "decoder-invalid"
                ),
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
        if any(isinstance(insn, dict) and "operands" in insn for insn in instructions):
            operand_detail_available = True

        analyzed += 1
        flow = _function_flow(
            instructions,
            row=row,
            arch=arch,
            view=view,
            targets=targets,
            relocation_symbols=relocation_symbols,
            plt_targets=plt_targets,
            cb=cb,
        )
        basic_block_count += int(flow.get("basicBlockCount") or 0)
        reachable_block_count += int(flow.get("reachableBlockCount") or 0)
        cfg_edge_count += int(flow.get("cfgEdgeCount") or 0)
        cfg_converged = cfg_converged and bool(flow.get("cfgConverged", True))
        new_edges = flow.get("edges") or []
        remaining = MAX_EDGES - len(edges)
        if remaining <= 0:
            break
        edges.extend(new_edges[:remaining])

    findings: list[dict[str, Any]] = []
    for idx, edge in enumerate(edges[:MAX_FINDINGS]):
        findings.append({
            "id": "x86-edge:" + hashlib.sha256(
                f"{apk_name}!{entry}!{idx}!{edge.get('instructionRva')}!"
                f"{edge.get('kind')}".encode()
            ).hexdigest()[:20],
            "kind": (
                "X86_DYNAMIC_LOOKUP_FLOW"
                if edge.get("targetResolution") == "DLSYM_RESULT_FLOW"
                else "X86_CONTROL_FLOW_EDGE"
            ),
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
            "nativeEdgeKind": edge.get("kind"),
            "kind": (
                "X86_DYNAMIC_LOOKUP_FLOW"
                if edge.get("targetResolution") == "DLSYM_RESULT_FLOW"
                else "X86_CONTROL_FLOW_EDGE"
            ),
            "instructionBoundaryConfirmed": True,
            "functionBoundarySource": "ELF_FUNCTION_SYMBOL",
            "patchReady": False,
            "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME",
            "trustBoundary": "local",
            "evidenceRole": "capstone-x86-symbol-bounded-control-data-flow",
        })

    return {
        "available": bool(regions) and decoder_available,
        "decoderAvailable": decoder_available,
        "operandDetailAvailable": operand_detail_available,
        "decoder": "capstone",
        "decoderVersion": decoder_version,
        "arch": arch,
        "bits": view.bits,
        "functionCount": len(regions),
        "analyzedFunctionCount": analyzed,
        "scannedCodeBytes": total,
        "relocationSymbolCount": len(relocation_symbols),
        "pltImportTargetCount": len(plt_targets),
        "basicBlockCount": basic_block_count,
        "reachableBasicBlockCount": reachable_block_count,
        "cfgEdgeCount": cfg_edge_count,
        "cfgConverged": cfg_converged,
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
            "structuredOperandsRequiredForDataFlow": True,
            "x86_64SysVArgumentFlow": True,
            "x86StackArgumentFlow": True,
            "ripRelativeRelocationFlow": True,
            "dlsymReturnFlow": True,
            "basicBlockCfg": True,
            "crossBasicBlockValuePropagation": True,
            "joinPolicy": "IDENTICAL_FACTS_ONLY",
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
                    except X86ScanCancelled:
                        raise
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
                            key: value for key, value in report.items()
                            if key not in {"edges", "findings", "errors"}
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
            "operandDataFlowFailClosed": True,
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
