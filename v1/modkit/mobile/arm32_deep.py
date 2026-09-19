"""Conservative ARMv7 A32/Thumb control-flow analysis.

Uses exact ELF function-symbol boundaries from the portable ELF parser. A32 has
fixed-width instructions; Thumb instruction width is determined from the first
halfword. The backend decodes only well-defined branch/call forms and never treats
arbitrary byte matches as instructions.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Callable, Iterable
import zipfile

from modkit.mobile.cfg_flow import build_cfg, clone_token_map, merge_token_maps
from modkit.mobile.native_portable import ElfView, EM_ARM

SCHEMA = "modkit-arm32-deep-1.2"
ENGINE_ID = "native.arm32-deep-embedded"
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_FUNCTION_BYTES = 512 * 1024
MAX_TOTAL_CODE_BYTES = 64 * 1024 * 1024
MAX_EDGES = 12000
MAX_FINDINGS = 1800
MAX_INSTRUCTIONS_PER_FUNCTION = 8192
MAX_STRING_BYTES = 512

Decoder = Callable[[bytes, int, bool, int], dict[str, Any]]


class Arm32ScanCancelled(RuntimeError):
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
        raise Arm32ScanCancelled("ARM32 scan cancelled")


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


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _function_regions(view: ElfView) -> list[dict[str, Any]]:
    funcs = [
        sym for sym in view.symbols
        if not sym.undefined and sym.sym_type == 2 and sym.value and 0 < sym.shndx < len(view.sections)
    ]
    rows: list[dict[str, Any]] = []
    by_section: dict[int, list[Any]] = {}
    for sym in funcs:
        by_section.setdefault(sym.shndx, []).append(sym)

    for shndx, symbols in by_section.items():
        sec = next((row for row in view.sections if row.index == shndx), None)
        if not sec or not sec.executable or sec.size <= 0:
            continue
        symbols.sort(key=lambda sym: ((sym.value & ~1), sym.name))
        for idx, sym in enumerate(symbols):
            start = int(sym.value & ~1)
            if start < sec.addr or start >= sec.addr + sec.size:
                continue
            next_start = (
                int(symbols[idx + 1].value & ~1)
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
                "thumb": bool(sym.value & 1),
                "section": sec,
            })
    rows.sort(key=lambda row: (row["rva"], row["name"]))
    return rows


def _target_names(regions: list[dict[str, Any]]) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in regions:
        out.setdefault(int(row["rva"]), str(row["name"]))
    return out


def _a32_edges(raw: bytes, start: int, source: str, file_base: int,
               targets: dict[int, str], cb: Any | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    size = len(raw) & ~3
    for rel in range(0, size, 4):
        if (rel & 0x3FFF) == 0:
            _check(cb)
        word = struct.unpack_from("<I", raw, rel)[0]
        pc = start + rel
        cond = (word >> 28) & 0xF

        # A32 B/BL immediate. cond=0xF is BLX-immediate encoding and is not
        # folded into this path because its H bit changes target construction.
        if cond != 0xF and (word & 0x0E000000) == 0x0A000000:
            link = bool(word & 0x01000000)
            offset = _sign_extend(word & 0x00FFFFFF, 24) << 2
            target = pc + 8 + offset
            out.append({
                "sourceRva": start, "sourceFunction": source,
                "instructionRva": pc, "fileOffset": file_base + rel,
                "kind": "arm-a32-bl" if link else "arm-a32-b",
                "edgeKind": "call" if link else "branch",
                "conditional": cond != 0xE,
                "conditionCode": cond,
                "targetRva": target,
                "targetFunction": targets.get(target),
                "targetResolution": "STATIC_SYMBOL" if target in targets else "DIRECT_IMMEDIATE",
                "instructionWidth": 4,
                "mode": "A32",
            })
            continue

        # BX / BLX register. The register target is deliberately unresolved.
        op = word & 0x0FFFFFF0
        if op in {0x012FFF10, 0x012FFF30}:
            link = op == 0x012FFF30
            out.append({
                "sourceRva": start, "sourceFunction": source,
                "instructionRva": pc, "fileOffset": file_base + rel,
                "kind": "arm-a32-blx-register" if link else "arm-a32-bx-register",
                "edgeKind": "indirect-call" if link else "indirect-branch",
                "conditional": cond != 0xE,
                "conditionCode": cond,
                "targetRegister": word & 0xF,
                "targetRva": None,
                "targetFunction": None,
                "targetResolution": "REGISTER_INDIRECT_UNRESOLVED",
                "instructionWidth": 4,
                "mode": "A32",
            })
    return out


def _thumb_is_32(first: int) -> bool:
    return (first & 0xF800) in {0xE800, 0xF000, 0xF800}


def _thumb_bl_target(first: int, second: int, pc: int) -> int:
    s = (first >> 10) & 1
    imm10 = first & 0x03FF
    j1 = (second >> 13) & 1
    j2 = (second >> 11) & 1
    imm11 = second & 0x07FF
    i1 = (~(j1 ^ s)) & 1
    i2 = (~(j2 ^ s)) & 1
    imm25 = (
        (s << 24) | (i1 << 23) | (i2 << 22)
        | (imm10 << 12) | (imm11 << 1)
    )
    return pc + 4 + _sign_extend(imm25, 25)


def _thumb_edges(raw: bytes, start: int, source: str, file_base: int,
                 targets: dict[int, str], cb: Any | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rel = 0
    while rel + 2 <= len(raw):
        if (rel & 0x3FFF) == 0:
            _check(cb)
        first = struct.unpack_from("<H", raw, rel)[0]
        pc = start + rel

        if _thumb_is_32(first):
            if rel + 4 > len(raw):
                break
            second = struct.unpack_from("<H", raw, rel + 2)[0]
            # Thumb-2 BL T1: first 11110..., second has bits 15,14,12 set.
            if (first & 0xF800) == 0xF000 and (second & 0xD000) == 0xD000:
                target = _thumb_bl_target(first, second, pc)
                out.append({
                    "sourceRva": start, "sourceFunction": source,
                    "instructionRva": pc, "fileOffset": file_base + rel,
                    "kind": "arm-thumb2-bl",
                    "edgeKind": "call", "conditional": False,
                    "targetRva": target,
                    "targetFunction": targets.get(target),
                    "targetResolution": "STATIC_SYMBOL" if target in targets else "DIRECT_IMMEDIATE",
                    "instructionWidth": 4, "mode": "THUMB",
                })
            # Thumb-2 B.W T4: same immediate encoding but second bits 15/12
            # are set while bit14 is clear.
            elif (first & 0xF800) == 0xF000 and (second & 0xD000) == 0x9000:
                target = _thumb_bl_target(first, second, pc)
                out.append({
                    "sourceRva": start, "sourceFunction": source,
                    "instructionRva": pc, "fileOffset": file_base + rel,
                    "kind": "arm-thumb2-bw",
                    "edgeKind": "branch", "conditional": False,
                    "targetRva": target,
                    "targetFunction": targets.get(target),
                    "targetResolution": "STATIC_SYMBOL" if target in targets else "DIRECT_IMMEDIATE",
                    "instructionWidth": 4, "mode": "THUMB",
                })
            rel += 4
            continue

        # Thumb-1 conditional B T1, excluding SVC/UDF encodings.
        if (first & 0xF000) == 0xD000:
            cond = (first >> 8) & 0xF
            if cond < 0xE:
                offset = _sign_extend((first & 0xFF) << 1, 9)
                target = pc + 4 + offset
                out.append({
                    "sourceRva": start, "sourceFunction": source,
                    "instructionRva": pc, "fileOffset": file_base + rel,
                    "kind": "arm-thumb-b-cond",
                    "edgeKind": "branch", "conditional": True,
                    "conditionCode": cond,
                    "targetRva": target,
                    "targetFunction": targets.get(target),
                    "targetResolution": "STATIC_SYMBOL" if target in targets else "DIRECT_IMMEDIATE",
                    "instructionWidth": 2, "mode": "THUMB",
                })
        elif (first & 0xF800) == 0xE000:
            offset = _sign_extend((first & 0x7FF) << 1, 12)
            target = pc + 4 + offset
            out.append({
                "sourceRva": start, "sourceFunction": source,
                "instructionRva": pc, "fileOffset": file_base + rel,
                "kind": "arm-thumb-b",
                "edgeKind": "branch", "conditional": False,
                "targetRva": target,
                "targetFunction": targets.get(target),
                "targetResolution": "STATIC_SYMBOL" if target in targets else "DIRECT_IMMEDIATE",
                "instructionWidth": 2, "mode": "THUMB",
            })
        # Thumb BX/BLX register T1.
        elif (first & 0xFF07) == 0x4700:
            link = bool(first & 0x0080)
            out.append({
                "sourceRva": start, "sourceFunction": source,
                "instructionRva": pc, "fileOffset": file_base + rel,
                "kind": "arm-thumb-blx-register" if link else "arm-thumb-bx-register",
                "edgeKind": "indirect-call" if link else "indirect-branch",
                "conditional": False,
                "targetRegister": (first >> 3) & 0xF,
                "targetRva": None, "targetFunction": None,
                "targetResolution": "REGISTER_INDIRECT_UNRESOLVED",
                "instructionWidth": 2, "mode": "THUMB",
            })
        rel += 2
    return out



def _java_capstone_decode(
    code: bytes,
    address: int,
    thumb: bool,
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
            code, int(address), "arm", bool(thumb), int(max_instructions)
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


def _arm_reg(value: Any) -> str | None:
    low = str(value or "").casefold()
    aliases = {
        "sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12",
        "sp": "r13", "lr": "r14", "pc": "r15",
    }
    if low in aliases:
        return aliases[low]
    if low.startswith("r") and low[1:].isdigit() and 0 <= int(low[1:]) <= 15:
        return low
    return None


def _operands(insn: dict[str, Any]) -> list[dict[str, Any]]:
    value = insn.get("operands") or []
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _relocation_symbols(view: ElfView) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in view.relocations:
        offset = row.get("offset")
        symbol = str(row.get("symbol") or "")
        if isinstance(offset, int) and symbol:
            out.setdefault(offset, symbol)
    return out

def _plt_import_targets(
    view: ElfView,
    decoder: Decoder,
    relocations: dict[int, str],
) -> dict[int, str]:
    """Resolve ARM/Thumb PLT entry starts only when decoded address arithmetic
    lands exactly on an ELF relocation slot carrying a symbol name.
    """
    out: dict[int, str] = {}
    if not relocations:
        return out

    for sec in view.sections:
        if sec.name not in {".plt", ".plt.sec", ".iplt"}:
            continue
        if not sec.executable or sec.size <= 0 or sec.size > MAX_FUNCTION_BYTES:
            continue
        raw = view._slice(sec)
        if not raw:
            continue

        # Android ARM PLT is normally A32. Thumb is attempted only when A32
        # produced no relocation-backed entries for the section.
        for thumb in (False, True):
            decoded = decoder(
                raw, int(sec.addr), thumb, MAX_INSTRUCTIONS_PER_FUNCTION
            )
            if not isinstance(decoded, dict) or not decoded.get("available"):
                continue
            instructions = decoded.get("instructions") or []
            if not isinstance(instructions, list):
                continue

            constants: dict[str, int] = {}
            entry_start: int | None = None
            found_before = len(out)
            ordered = [
                insn for insn in instructions
                if isinstance(insn, dict) and int(insn.get("address") or 0) > 0
            ]
            for idx, insn in enumerate(ordered):
                address = int(insn.get("address") or 0)
                if entry_start is None:
                    entry_start = address
                mnemonic = str(insn.get("mnemonic") or "").casefold()
                ops = _operands(insn)

                if (
                    mnemonic in {"add", "addw", "sub", "subw"}
                    and len(ops) >= 3
                    and ops[0].get("type") == "REG"
                    and ops[1].get("type") == "REG"
                    and ops[2].get("type") == "IMM"
                ):
                    dest = _arm_reg(ops[0].get("reg"))
                    source = _arm_reg(ops[1].get("reg"))
                    if dest and source:
                        if source == "r15":
                            base = ((address + 4) & ~3) if thumb else address + 8
                        else:
                            base = constants.get(source)
                        if base is None:
                            constants.pop(dest, None)
                        else:
                            imm = int(ops[2].get("imm") or 0)
                            constants[dest] = (
                                base - imm if mnemonic.startswith("sub")
                                else base + imm
                            )

                elif (
                    mnemonic == "adr"
                    and len(ops) >= 2
                    and ops[0].get("type") == "REG"
                    and ops[1].get("type") == "IMM"
                ):
                    dest = _arm_reg(ops[0].get("reg"))
                    if dest:
                        constants[dest] = int(ops[1].get("imm") or 0)

                elif (
                    mnemonic in {"mov", "movs"}
                    and len(ops) >= 2
                    and ops[0].get("type") == "REG"
                    and ops[1].get("type") == "IMM"
                ):
                    dest = _arm_reg(ops[0].get("reg"))
                    if dest:
                        constants[dest] = int(ops[1].get("imm") or 0)

                writes_pc = False
                if mnemonic.startswith("ldr") and len(ops) >= 2:
                    dest = _arm_reg(ops[0].get("reg")) if ops[0].get("type") == "REG" else None
                    if dest == "r15" and ops[1].get("type") == "MEM":
                        writes_pc = True
                        mem = ops[1].get("mem")
                        if isinstance(mem, dict):
                            base_reg = _arm_reg(mem.get("base"))
                            index_reg = _arm_reg(mem.get("index"))
                            if index_reg is None:
                                if base_reg == "r15":
                                    base = (
                                        ((address + 4) & ~3)
                                        if thumb else address + 8
                                    )
                                else:
                                    base = constants.get(base_reg or "")
                                if base is not None:
                                    slot = base + int(mem.get("disp") or 0)
                                    symbol = relocations.get(slot)
                                    if symbol and entry_start is not None:
                                        out.setdefault(entry_start, symbol)

                terminates = (
                    bool(insn.get("isJump"))
                    or bool(insn.get("isRet"))
                    or writes_pc
                )
                if terminates:
                    constants.clear()
                    entry_start = (
                        int(ordered[idx + 1].get("address") or 0)
                        if idx + 1 < len(ordered) else None
                    )

            if len(out) > found_before:
                break

    return out



def _section_for_rva(view: ElfView, rva: int):
    return next(
        (
            sec for sec in view.sections
            if sec.size > 0 and sec.addr <= rva < sec.addr + sec.size
        ),
        None,
    )


def _read_u32_rva(view: ElfView, rva: int) -> int | None:
    sec = _section_for_rva(view, rva)
    if sec is None:
        return None
    rel = rva - sec.addr
    pos = sec.offset + rel
    if pos < 0 or pos + 4 > len(view.data) or pos + 4 > sec.offset + sec.size:
        return None
    return struct.unpack_from("<I", view.data, pos)[0]


def _string_token(view: ElfView, rva: int) -> dict[str, Any] | None:
    sec = _section_for_rva(view, rva)
    if sec is None or sec.executable or not sec.allocated:
        return None
    rel = rva - sec.addr
    pos = sec.offset + rel
    if pos < 0 or pos >= len(view.data):
        return None
    end = min(len(view.data), sec.offset + sec.size, pos + MAX_STRING_BYTES)
    raw = view.data[pos:end]
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
    return {"kind": "string", "value": text, "address": rva, "section": sec.name}


def _literal_address(insn: dict[str, Any], operand: dict[str, Any], thumb: bool) -> int | None:
    if str(operand.get("type") or "") != "MEM":
        return None
    mem = operand.get("mem")
    if not isinstance(mem, dict):
        return None
    base = _arm_reg(mem.get("base"))
    index = _arm_reg(mem.get("index"))
    if base != "r15" or index is not None:
        return None
    address = int(insn.get("address") or 0)
    disp = int(mem.get("disp") or 0)
    pc_base = ((address + 4) & ~3) if thumb else address + 8
    return pc_base + disp


def _load_literal_token(
    view: ElfView,
    insn: dict[str, Any],
    operand: dict[str, Any],
    *,
    thumb: bool,
    relocations: dict[int, str],
) -> dict[str, Any] | None:
    literal = _literal_address(insn, operand, thumb)
    if literal is None:
        return None
    direct_symbol = relocations.get(literal)
    if direct_symbol:
        return {
            "kind": "import-function",
            "symbol": direct_symbol,
            "relocationSlotRva": literal,
            "literalRva": literal,
        }

    value = _read_u32_rva(view, literal)
    if value is None:
        return None
    symbol = relocations.get(value)
    if symbol:
        return {
            "kind": "import-function",
            "symbol": symbol,
            "relocationSlotRva": value,
            "literalRva": literal,
        }
    return _string_token(view, value) or {
        "kind": "address",
        "address": value,
        "literalRva": literal,
    }


def _operand_token(
    operand: dict[str, Any],
    *,
    state: dict[str, dict[str, Any]],
    stack_slots: dict[int, dict[str, Any]],
    insn: dict[str, Any],
    view: ElfView,
    thumb: bool,
    relocations: dict[int, str],
) -> dict[str, Any] | None:
    kind = str(operand.get("type") or "")
    if kind == "REG":
        reg = _arm_reg(operand.get("reg"))
        return dict(state[reg]) if reg and reg in state else None
    if kind == "IMM":
        value = int(operand.get("imm") or 0)
        return _string_token(view, value) or {"kind": "immediate", "value": value}
    if kind != "MEM":
        return None
    mem = operand.get("mem")
    if not isinstance(mem, dict):
        return None
    base = _arm_reg(mem.get("base"))
    index = _arm_reg(mem.get("index"))
    disp = int(mem.get("disp") or 0)
    if base == "r13" and index is None:
        token = stack_slots.get(disp)
        return dict(token) if token else None
    return _load_literal_token(
        view, insn, operand, thumb=thumb, relocations=relocations
    )


def _run_capstone_block(
    instructions: list[dict[str, Any]],
    *,
    block_start: int,
    row: dict[str, Any],
    file_start: int,
    view: ElfView,
    targets: dict[int, str],
    relocations: dict[int, str],
    plt_targets: dict[int, str],
    initial_state: dict[str, dict[str, Any]],
    initial_stack_slots: dict[str, dict[str, Any]],
    cb: Any | None,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
]:
    thumb = bool(row["thumb"])
    state = clone_token_map(initial_state)
    stack_slots = clone_token_map(initial_stack_slots)
    out: list[dict[str, Any]] = []

    for index, insn in enumerate(instructions):
        if (index & 0x3FF) == 0:
            _check(cb)
        if not isinstance(insn, dict):
            continue
        mnemonic = str(insn.get("mnemonic") or "").casefold()
        ops = _operands(insn)
        handled: set[str] = set()

        if mnemonic in {"mov", "movs"} and len(ops) >= 2 and ops[0].get("type") == "REG":
            dest = _arm_reg(ops[0].get("reg"))
            if dest:
                token = _operand_token(
                    ops[1], state=state,
                    stack_slots={int(k): v for k, v in stack_slots.items()},
                    insn=insn, view=view, thumb=thumb, relocations=relocations,
                )
                if token is None:
                    state.pop(dest, None)
                else:
                    state[dest] = token
                handled.add(dest)

        elif mnemonic == "adr" and len(ops) >= 2 and ops[0].get("type") == "REG":
            dest = _arm_reg(ops[0].get("reg"))
            if dest:
                token = _operand_token(
                    ops[1], state=state,
                    stack_slots={int(k): v for k, v in stack_slots.items()},
                    insn=insn, view=view, thumb=thumb, relocations=relocations,
                )
                if token is None:
                    state.pop(dest, None)
                else:
                    state[dest] = token
                handled.add(dest)

        elif mnemonic.startswith("ldr") and len(ops) >= 2 and ops[0].get("type") == "REG":
            dest = _arm_reg(ops[0].get("reg"))
            if dest:
                token = _operand_token(
                    ops[1], state=state,
                    stack_slots={int(k): v for k, v in stack_slots.items()},
                    insn=insn, view=view, thumb=thumb, relocations=relocations,
                )
                if token is None:
                    state.pop(dest, None)
                else:
                    state[dest] = token
                handled.add(dest)

        elif mnemonic.startswith("str") and len(ops) >= 2 and ops[1].get("type") == "MEM":
            mem = ops[1].get("mem")
            if isinstance(mem, dict) and _arm_reg(mem.get("base")) == "r13":
                if _arm_reg(mem.get("index")) is None:
                    disp = int(mem.get("disp") or 0)
                    token = _operand_token(
                        ops[0], state=state,
                        stack_slots={int(k): v for k, v in stack_slots.items()},
                        insn=insn, view=view, thumb=thumb, relocations=relocations,
                    )
                    key = str(disp)
                    if token is None:
                        stack_slots.pop(key, None)
                    else:
                        stack_slots[key] = token

        is_call = bool(insn.get("isCall"))
        if is_call:
            address = int(insn.get("address") or 0)
            size = int(insn.get("size") or 0)
            has_target = (
                bool(insn.get("hasImmediateTarget"))
                and insn.get("immediateTarget") is not None
            )
            target = int(insn["immediateTarget"]) & ~1 if has_target else None
            target_name = targets.get(target) if target is not None else None
            resolution = (
                "STATIC_SYMBOL" if target_name
                else "DIRECT_IMMEDIATE" if target is not None
                else "REGISTER_INDIRECT_UNRESOLVED"
            )
            if target is not None and target in plt_targets:
                target_name = plt_targets[target]
                resolution = "ELF_RELOCATION_PLT"

            if not target_name and ops and ops[0].get("type") == "REG":
                reg = _arm_reg(ops[0].get("reg"))
                token = state.get(reg) if reg else None
                if token and token.get("kind") == "import-function":
                    target_name = str(token.get("symbol") or "")
                    resolution = "ELF_RELOCATION_REGISTER_FLOW"
                elif token and token.get("kind") == "dynamic-symbol":
                    target_name = str(token.get("symbol") or "")
                    resolution = "DLSYM_RESULT_FLOW"

            args = [
                dict(state[reg]) if reg in state else None
                for reg in ("r0", "r1", "r2", "r3")
            ]
            for key in sorted(
                (k for k in stack_slots if int(k) >= 0),
                key=lambda value: int(value),
            ):
                args.append(dict(stack_slots[key]))

            edge: dict[str, Any] = {
                "sourceRva": int(row["rva"]),
                "sourceFunction": str(row["name"]),
                "instructionRva": address,
                "fileOffset": file_start + max(0, address - int(row["rva"])),
                "kind": "arm-capstone-direct-call" if target is not None else "arm-capstone-indirect-call",
                "edgeKind": "call" if target is not None else "indirect-call",
                "conditional": False,
                "targetRva": target,
                "targetFunction": target_name,
                "targetResolution": resolution,
                "instructionWidth": size,
                "mode": "THUMB" if thumb else "A32",
                "decoder": "capstone",
                "basicBlockRva": block_start,
                "cfgReachable": True,
            }
            if any(arg is not None for arg in args):
                edge["argumentEvidence"] = args

            return_token: dict[str, Any] | None = None
            if target_name == "dlsym" and len(args) >= 2:
                symbol_arg = args[1]
                if symbol_arg and symbol_arg.get("kind") == "string":
                    symbol = str(symbol_arg.get("value") or "")
                    if symbol:
                        edge["dynamicLookup"] = True
                        edge["lookupIdentifier"] = symbol
                        edge["lookupIdentifierAddress"] = symbol_arg.get("address")
                        return_token = {
                            "kind": "dynamic-symbol",
                            "symbol": symbol,
                            "sourceCallRva": address,
                        }

            out.append(edge)
            for reg in ("r0", "r1", "r2", "r3", "r12", "r14"):
                state.pop(reg, None)
            if return_token is not None:
                state["r0"] = return_token
            stack_slots.clear()

        for raw_reg in insn.get("regsWrite") or []:
            reg = _arm_reg(raw_reg)
            if reg and reg not in handled and not is_call:
                state.pop(reg, None)

    return state, stack_slots, out


def _capstone_call_flow(
    instructions: list[dict[str, Any]],
    *,
    row: dict[str, Any],
    file_start: int,
    view: ElfView,
    targets: dict[int, str],
    relocations: dict[int, str],
    plt_targets: dict[int, str],
    cb: Any | None,
) -> dict[str, Any]:
    cfg = build_cfg(instructions, arch="arm")
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
    incoming_stack: dict[int, dict[str, dict[str, Any]]] = {int(entry): {}}
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

        state, stack_slots, produced = _run_capstone_block(
            block.get("instructions") or [],
            block_start=block_start,
            row=row,
            file_start=file_start,
            view=view,
            targets=targets,
            relocations=relocations,
            plt_targets=plt_targets,
            initial_state=incoming_state.get(block_start, {}),
            initial_stack_slots=incoming_stack.get(block_start, {}),
            cb=cb,
        )
        block_edges[block_start] = produced

        for raw_successor in block.get("successors") or []:
            successor = int(raw_successor)
            if successor not in by_start:
                continue
            candidate_state = clone_token_map(state)
            candidate_stack = clone_token_map(stack_slots)
            if successor not in incoming_state:
                incoming_state[successor] = candidate_state
                incoming_stack[successor] = candidate_stack
                changed = True
            else:
                merged_state = merge_token_maps(
                    incoming_state[successor], candidate_state
                )
                merged_stack = merge_token_maps(
                    incoming_stack.get(successor, {}), candidate_stack
                )
                changed = (
                    merged_state != incoming_state[successor]
                    or merged_stack != incoming_stack.get(successor, {})
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

def _merge_capstone_flow(
    base_edges: list[dict[str, Any]],
    flow_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out = [dict(row) for row in base_edges]
    by_rva = {
        int(row["instructionRva"]): row
        for row in out
        if isinstance(row.get("instructionRva"), int)
    }
    for flow in flow_edges:
        rva = flow.get("instructionRva")
        current = by_rva.get(rva) if isinstance(rva, int) else None
        if current is None:
            out.append(flow)
            if isinstance(rva, int):
                by_rva[rva] = flow
            continue
        for key in (
            "targetFunction", "targetResolution", "argumentEvidence",
            "dynamicLookup", "lookupIdentifier", "lookupIdentifierAddress",
            "decoder",
        ):
            value = flow.get(key)
            if value not in (None, "", []):
                current[key] = value
    return out



def analyze_elf(
    data: bytes,
    *,
    apk_name: str = "",
    entry: str = "",
    decoder: Decoder | None = None,
    cb: Any | None = None,
) -> dict[str, Any]:
    view = ElfView(data)
    if view.machine != EM_ARM or view.bits != 32:
        return {
            "available": False, "arch": "non-arm32", "functionCount": 0,
            "edgeCount": 0, "edges": [], "findings": [],
        }

    regions = _function_regions(view)
    targets = _target_names(regions)
    relocations = _relocation_symbols(view)
    decode = decoder or _java_capstone_decode
    plt_targets = _plt_import_targets(view, decode, relocations)
    edges: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    total = 0
    analyzed = 0
    thumb_count = 0
    a32_count = 0
    capstone_function_count = 0
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
        analyzed += 1

        if row["thumb"]:
            thumb_count += 1
            base_edges = _thumb_edges(
                raw, int(row["rva"]), str(row["name"]), file_start, targets, cb
            )
        else:
            a32_count += 1
            base_edges = _a32_edges(
                raw, int(row["rva"]), str(row["name"]), file_start, targets, cb
            )

        flow_edges: list[dict[str, Any]] = []
        decoded = decode(
            raw, int(row["rva"]), bool(row["thumb"]), MAX_INSTRUCTIONS_PER_FUNCTION
        )
        if isinstance(decoded, dict) and decoded.get("available"):
            instructions = decoded.get("instructions") or []
            if isinstance(instructions, list):
                capstone_function_count += 1
                if any(
                    isinstance(insn, dict) and "operands" in insn
                    for insn in instructions
                ):
                    operand_detail_available = True
                flow = _capstone_call_flow(
                    instructions,
                    row=row,
                    file_start=file_start,
                    view=view,
                    targets=targets,
                    relocations=relocations,
                    plt_targets=plt_targets,
                    cb=cb,
                )
                basic_block_count += int(flow.get("basicBlockCount") or 0)
                reachable_block_count += int(flow.get("reachableBlockCount") or 0)
                cfg_edge_count += int(flow.get("cfgEdgeCount") or 0)
                cfg_converged = cfg_converged and bool(flow.get("cfgConverged", True))
                flow_edges = flow.get("edges") or []
            else:
                errors.append({
                    "function": row["name"],
                    "rva": row["rva"],
                    "error": "decoder-instructions-not-list",
                })
        elif isinstance(decoded, dict):
            error = decoded.get("error")
            if error and not str(error).startswith("java-bridge-unavailable"):
                errors.append({
                    "function": row["name"],
                    "rva": row["rva"],
                    "error": str(error),
                })

        new_edges = _merge_capstone_flow(base_edges, flow_edges)
        remaining = MAX_EDGES - len(edges)
        if remaining <= 0:
            break
        edges.extend(new_edges[:remaining])

    findings: list[dict[str, Any]] = []
    for idx, edge in enumerate(edges[:MAX_FINDINGS]):
        findings.append({
            "id": "arm32-edge:" + hashlib.sha256(
                f"{apk_name}!{entry}!{idx}!{edge.get('instructionRva')}!"
                f"{edge.get('kind')}".encode()
            ).hexdigest()[:20],
            "kind": (
                "ARM32_DYNAMIC_LOOKUP_FLOW"
                if edge.get("targetResolution") == "DLSYM_RESULT_FLOW"
                else "ARM32_CONTROL_FLOW_EDGE"
            ),
            "title": (
                f"{edge.get('sourceFunction') or 'function'} → "
                f"{edge.get('targetFunction') or edge.get('targetResolution')}"
            ),
            "category": "Native/ARM32 Control Flow",
            "status": "CORRELATED_EVIDENCE",
            "engineId": ENGINE_ID,
            "apk": apk_name,
            "entry": entry,
            **edge,
            "nativeEdgeKind": edge.get("kind"),
            "kind": (
                "ARM32_DYNAMIC_LOOKUP_FLOW"
                if edge.get("targetResolution") == "DLSYM_RESULT_FLOW"
                else "ARM32_CONTROL_FLOW_EDGE"
            ),
            "instructionBoundaryConfirmed": True,
            "functionBoundarySource": "ELF_FUNCTION_SYMBOL",
            "patchReady": False,
            "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME",
            "trustBoundary": "local",
            "evidenceRole": "arm32-symbol-bounded-control-data-flow",
        })

    return {
        "available": bool(regions),
        "arch": "arm",
        "bits": 32,
        "functionCount": len(regions),
        "analyzedFunctionCount": analyzed,
        "capstoneFunctionCount": capstone_function_count,
        "operandDetailAvailable": operand_detail_available,
        "thumbFunctionCount": thumb_count,
        "a32FunctionCount": a32_count,
        "scannedCodeBytes": total,
        "relocationSymbolCount": len(relocations),
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
            "x86ByteHeuristicUsed": False,
            "capstoneOperandFlowOptional": True,
            "armEabiRegisterArguments": True,
            "stackSlotFlow": True,
            "pcRelativeLiteralFlow": True,
            "armPltRelocationFlow": True,
            "dlsymReturnFlow": True,
            "basicBlockCfg": True,
            "crossBasicBlockValuePropagation": True,
            "joinPolicy": "IDENTICAL_FACTS_ONLY",
            "indirectRegisterTargetsResolvedWithoutProof": False,
            "patchReadyFromControlFlow": False,
        },
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
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
                    low = info.filename.casefold()
                    if info.is_dir() or not low.endswith(".so"):
                        continue
                    if "/armeabi-v7a/" not in f"/{low}" or info.file_size > MAX_LIBRARY_BYTES:
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_LIBRARY_BYTES + 1)
                    except Exception:
                        continue
                    if data[:4] != b"\x7fELF":
                        continue
                    try:
                        report = analyze_elf(data, apk_name=apk.name, entry=info.filename, cb=cb)
                    except Arm32ScanCancelled:
                        raise
                    except Exception as exc:
                        libraries.append({
                            "apk": apk.name, "entry": info.filename,
                            "available": False, "error": str(exc),
                        })
                        continue
                    libraries.append({
                        "apk": apk.name, "entry": info.filename,
                        "size": info.file_size,
                        **{k: v for k, v in report.items() if k not in {"edges", "findings"}},
                    })
                    findings.extend(report.get("findings") or [])
                    if len(findings) >= MAX_FINDINGS:
                        findings = findings[:MAX_FINDINGS]
        except Arm32ScanCancelled:
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
            "x86ByteHeuristicUsed": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    return scan_apk_paths(_workspace_apks(Path(workdir)), output_path, cb)
