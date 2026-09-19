"""Small fail-closed CFG helpers for symbol-bounded native analysis.

The helpers operate only on already-decoded instructions. They never infer an
instruction boundary or an indirect branch target. Data-flow callers can use the
predecessor graph to propagate only values that remain identical at joins.
"""
from __future__ import annotations

from typing import Any


def _address(insn: dict[str, Any]) -> int:
    return int(insn.get("address") or 0)


def _size(insn: dict[str, Any]) -> int:
    return max(0, int(insn.get("size") or 0))


def _direct_target(insn: dict[str, Any]) -> int | None:
    if not bool(insn.get("hasImmediateTarget")):
        return None
    value = insn.get("immediateTarget")
    return int(value) if value is not None else None


def _unconditional_jump(insn: dict[str, Any], arch: str) -> bool:
    if not bool(insn.get("isJump")):
        return False
    mnemonic = str(insn.get("mnemonic") or "").casefold().strip()
    if arch in {"x86", "x86_64"}:
        return mnemonic in {"jmp", "ljmp"}
    if arch == "arm":
        # Capstone spells conditional ARM branches as beq/bne/... and Thumb
        # conditional forms likewise. b/b.w and register/table branches do not
        # have a fall-through edge.
        return mnemonic in {"b", "b.w", "bx", "bxj", "tbb", "tbh"}
    return False


def build_cfg(
    instructions: list[dict[str, Any]],
    *,
    arch: str,
) -> dict[str, Any]:
    """Partition decoded instructions into basic blocks and direct CFG edges.

    Only exact decoded addresses and exact immediate branch targets are used.
    Indirect jumps terminate a block but do not manufacture a successor.
    """
    ordered = sorted(
        (
            dict(insn) for insn in instructions
            if isinstance(insn, dict) and _address(insn) > 0 and _size(insn) > 0
        ),
        key=_address,
    )
    if not ordered:
        return {"entry": None, "blocks": [], "edgeCount": 0}

    # Keep the first decode at each address. Duplicate addresses would make
    # block ownership ambiguous, so later duplicates are ignored.
    unique: list[dict[str, Any]] = []
    seen_addresses: set[int] = set()
    for insn in ordered:
        addr = _address(insn)
        if addr in seen_addresses:
            continue
        seen_addresses.add(addr)
        unique.append(insn)

    addresses = [_address(insn) for insn in unique]
    address_set = set(addresses)
    leaders: set[int] = {addresses[0]}

    for idx, insn in enumerate(unique):
        if not (bool(insn.get("isJump")) or bool(insn.get("isRet"))):
            continue
        target = _direct_target(insn)
        if target in address_set:
            leaders.add(int(target))
        if idx + 1 < len(unique):
            # Even after an unconditional branch/return the next decoded
            # instruction starts a distinct (possibly unreachable) block.
            leaders.add(addresses[idx + 1])

    leader_order = sorted(leaders)
    leader_set = set(leader_order)
    blocks: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    current_start: int | None = None
    for insn in unique:
        addr = _address(insn)
        if current and addr in leader_set:
            last = current[-1]
            blocks.append({
                "start": current_start,
                "end": _address(last) + _size(last),
                "instructions": current,
                "successors": [],
                "predecessors": [],
            })
            current = []
        if not current:
            current_start = addr
        current.append(insn)
    if current:
        last = current[-1]
        blocks.append({
            "start": current_start,
            "end": _address(last) + _size(last),
            "instructions": current,
            "successors": [],
            "predecessors": [],
        })

    by_instruction: dict[int, int] = {}
    by_start: dict[int, dict[str, Any]] = {}
    for block in blocks:
        start = int(block["start"])
        by_start[start] = block
        for insn in block["instructions"]:
            by_instruction[_address(insn)] = start

    edge_count = 0
    for idx, block in enumerate(blocks):
        last = block["instructions"][-1]
        successors: list[int] = []
        if not bool(last.get("isRet")):
            if bool(last.get("isJump")):
                target = _direct_target(last)
                target_block = by_instruction.get(target) if target is not None else None
                if target_block is not None:
                    successors.append(target_block)
                if not _unconditional_jump(last, arch) and idx + 1 < len(blocks):
                    fallthrough = int(blocks[idx + 1]["start"])
                    if fallthrough not in successors:
                        successors.append(fallthrough)
            elif idx + 1 < len(blocks):
                successors.append(int(blocks[idx + 1]["start"]))
        block["successors"] = successors
        edge_count += len(successors)

    for block in blocks:
        start = int(block["start"])
        for successor in block["successors"]:
            target = by_start.get(int(successor))
            if target is not None:
                target["predecessors"].append(start)

    return {
        "entry": int(blocks[0]["start"]),
        "blocks": blocks,
        "edgeCount": edge_count,
    }


def clone_token_map(value: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(key): dict(token) for key, token in value.items()}


def merge_token_maps(
    left: dict[str, dict[str, Any]],
    right: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Intersection merge: keep only facts identical on both incoming paths."""
    return {
        key: dict(left[key])
        for key in left.keys() & right.keys()
        if left[key] == right[key]
    }


def clone_token_list(
    value: list[dict[str, Any] | None],
) -> list[dict[str, Any] | None]:
    return [dict(token) if isinstance(token, dict) else None for token in value]


def merge_token_lists(
    left: list[dict[str, Any] | None],
    right: list[dict[str, Any] | None],
) -> list[dict[str, Any] | None]:
    size = max(len(left), len(right))
    merged: list[dict[str, Any] | None] = []
    for idx in range(size):
        a = left[idx] if idx < len(left) else None
        b = right[idx] if idx < len(right) else None
        merged.append(dict(a) if isinstance(a, dict) and a == b else None)
    while merged and merged[-1] is None:
        merged.pop()
    return merged
