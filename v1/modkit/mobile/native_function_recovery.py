"""Fail-closed function-boundary recovery from ELF unwind metadata.

This module does not guess prologues or scan for opcode byte patterns. It accepts
only function starts encoded by standard unwind metadata and only when the decoded
address lands inside an executable ELF section. Callers may then run their normal
architecture decoder inside those recovered regions while keeping the boundary
source explicit and non-patch-ready.
"""
from __future__ import annotations

import struct
from typing import Any

from modkit.mobile.native_portable import ElfView, EM_ARM

MAX_RECOVERED_FUNCTIONS = 20000

_DW_EH_PE_omit = 0xFF
_DW_EH_PE_absptr = 0x00
_DW_EH_PE_uleb128 = 0x01
_DW_EH_PE_udata2 = 0x02
_DW_EH_PE_udata4 = 0x03
_DW_EH_PE_udata8 = 0x04
_DW_EH_PE_sleb128 = 0x09
_DW_EH_PE_sdata2 = 0x0A
_DW_EH_PE_sdata4 = 0x0B
_DW_EH_PE_sdata8 = 0x0C
_DW_EH_PE_pcrel = 0x10
_DW_EH_PE_textrel = 0x20
_DW_EH_PE_datarel = 0x30
_DW_EH_PE_aligned = 0x50
_DW_EH_PE_indirect = 0x80


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _exec_section(view: ElfView, rva: int):
    return next(
        (
            sec for sec in view.sections
            if sec.executable and sec.size > 0
            and sec.addr <= rva < sec.addr + sec.size
        ),
        None,
    )


def _read_uleb(raw: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    pos = offset
    for _ in range(10):
        if pos >= len(raw):
            return None
        byte = raw[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, pos
        shift += 7
    return None


def _read_sleb(raw: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    pos = offset
    byte = 0
    for _ in range(10):
        if pos >= len(raw):
            return None
        byte = raw[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if shift < 64 and (byte & 0x40):
                value |= -(1 << shift)
            return value, pos
    return None


def _read_scalar(
    raw: bytes,
    offset: int,
    encoding: int,
    *,
    bits: int,
    field_rva: int,
    data_base: int,
    text_base: int,
) -> tuple[int, int] | None:
    if encoding == _DW_EH_PE_omit or encoding & _DW_EH_PE_indirect:
        return None

    application = encoding & 0x70
    fmt = encoding & 0x0F
    pos = offset

    if application == _DW_EH_PE_aligned:
        width = 8 if bits == 64 else 4
        aligned_rva = (field_rva + width - 1) & ~(width - 1)
        delta = aligned_rva - field_rva
        pos += delta
        field_rva += delta
        application = 0

    if fmt == _DW_EH_PE_absptr:
        width = 8 if bits == 64 else 4
        if pos + width > len(raw):
            return None
        value = int.from_bytes(raw[pos:pos + width], "little", signed=False)
        pos += width
    elif fmt in {_DW_EH_PE_udata2, _DW_EH_PE_udata4, _DW_EH_PE_udata8}:
        width = {
            _DW_EH_PE_udata2: 2,
            _DW_EH_PE_udata4: 4,
            _DW_EH_PE_udata8: 8,
        }[fmt]
        if pos + width > len(raw):
            return None
        value = int.from_bytes(raw[pos:pos + width], "little", signed=False)
        pos += width
    elif fmt in {_DW_EH_PE_sdata2, _DW_EH_PE_sdata4, _DW_EH_PE_sdata8}:
        width = {
            _DW_EH_PE_sdata2: 2,
            _DW_EH_PE_sdata4: 4,
            _DW_EH_PE_sdata8: 8,
        }[fmt]
        if pos + width > len(raw):
            return None
        value = int.from_bytes(raw[pos:pos + width], "little", signed=True)
        pos += width
    elif fmt == _DW_EH_PE_uleb128:
        decoded = _read_uleb(raw, pos)
        if decoded is None:
            return None
        value, pos = decoded
    elif fmt == _DW_EH_PE_sleb128:
        decoded = _read_sleb(raw, pos)
        if decoded is None:
            return None
        value, pos = decoded
    else:
        return None

    if application == 0:
        result = value
    elif application == _DW_EH_PE_pcrel:
        result = field_rva + value
    elif application == _DW_EH_PE_datarel:
        result = data_base + value
    elif application == _DW_EH_PE_textrel:
        result = text_base + value
    else:
        return None
    return int(result), pos


def _arm_exidx_starts(view: ElfView) -> list[dict[str, Any]]:
    if view.machine != EM_ARM or view.bits != 32:
        return []
    sec = view.section_by_name.get(".ARM.exidx")
    if sec is None or sec.size < 8:
        return []
    raw = view._slice(sec)
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    count = min(len(raw) // 8, MAX_RECOVERED_FUNCTIONS)
    for idx in range(count):
        off = idx * 8
        word = struct.unpack_from("<I", raw, off)[0]
        place = sec.addr + off
        delta = _sign_extend(word & 0x7FFFFFFF, 31)
        encoded = place + delta
        thumb = bool(encoded & 1)
        rva = encoded & ~1
        target = _exec_section(view, rva)
        if target is None or rva in seen:
            continue
        seen.add(rva)
        out.append({
            "rva": rva,
            "thumb": thumb,
            "source": "ARM_EXIDX",
            "metadataSection": ".ARM.exidx",
            "metadataRva": place,
            "confidence": "EXACT_UNWIND_START",
        })
    out.sort(key=lambda row: int(row["rva"]))
    return out


def _eh_frame_hdr_starts(view: ElfView) -> list[dict[str, Any]]:
    sec = view.section_by_name.get(".eh_frame_hdr")
    if sec is None or sec.size < 4:
        return []
    raw = view._slice(sec)
    if len(raw) < 4 or raw[0] != 1:
        return []

    eh_enc = raw[1]
    count_enc = raw[2]
    table_enc = raw[3]
    if eh_enc == _DW_EH_PE_omit or count_enc == _DW_EH_PE_omit or table_enc == _DW_EH_PE_omit:
        return []

    text_sections = [row for row in view.sections if row.executable and row.size > 0]
    text_base = min((row.addr for row in text_sections), default=0)
    pos = 4

    decoded = _read_scalar(
        raw, pos, eh_enc, bits=view.bits,
        field_rva=sec.addr + pos, data_base=sec.addr, text_base=text_base,
    )
    if decoded is None:
        return []
    _eh_frame_ptr, pos = decoded

    decoded = _read_scalar(
        raw, pos, count_enc, bits=view.bits,
        field_rva=sec.addr + pos, data_base=sec.addr, text_base=text_base,
    )
    if decoded is None:
        return []
    count, pos = decoded
    if count < 0:
        return []
    count = min(int(count), MAX_RECOVERED_FUNCTIONS)

    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for _ in range(count):
        field_rva = sec.addr + pos
        decoded = _read_scalar(
            raw, pos, table_enc, bits=view.bits,
            field_rva=field_rva, data_base=sec.addr, text_base=text_base,
        )
        if decoded is None:
            break
        start, pos = decoded

        field_rva = sec.addr + pos
        decoded = _read_scalar(
            raw, pos, table_enc, bits=view.bits,
            field_rva=field_rva, data_base=sec.addr, text_base=text_base,
        )
        if decoded is None:
            break
        _fde, pos = decoded

        target = _exec_section(view, int(start))
        if target is None or int(start) in seen:
            continue
        seen.add(int(start))
        out.append({
            "rva": int(start),
            "thumb": False,
            "source": "EH_FRAME_HDR",
            "metadataSection": ".eh_frame_hdr",
            "confidence": "EXACT_UNWIND_START",
        })

    out.sort(key=lambda row: int(row["rva"]))
    return out


def recover_function_starts(view: ElfView) -> list[dict[str, Any]]:
    """Return exact unwind-backed starts which land inside executable sections."""
    rows = _arm_exidx_starts(view) + _eh_frame_hdr_starts(view)
    by_rva: dict[int, dict[str, Any]] = {}
    for row in rows:
        rva = int(row["rva"])
        current = by_rva.get(rva)
        if current is None:
            by_rva[rva] = dict(row)
            continue
        sources = {
            str(current.get("source") or ""),
            str(row.get("source") or ""),
        }
        current["source"] = "+".join(sorted(value for value in sources if value))
        current["thumb"] = bool(current.get("thumb") or row.get("thumb"))
    return [by_rva[key] for key in sorted(by_rva)]


def recovered_regions(
    view: ElfView,
    existing_regions: list[dict[str, Any]],
    *,
    max_function_bytes: int,
) -> list[dict[str, Any]]:
    """Build bounded regions only for unwind starts not already owned by symbols."""
    candidates = recover_function_starts(view)
    if not candidates:
        return []

    existing = [
        row for row in existing_regions
        if isinstance(row.get("rva"), int) and isinstance(row.get("endRva"), int)
    ]
    boundaries_by_section: dict[int, set[int]] = {}
    for row in existing:
        sec = row.get("section")
        if sec is not None:
            boundaries_by_section.setdefault(int(sec.index), set()).add(int(row["rva"]))
            boundaries_by_section[int(sec.index)].add(int(row["endRva"]))

    valid: list[tuple[dict[str, Any], Any]] = []
    for candidate in candidates:
        rva = int(candidate["rva"])
        if any(int(row["rva"]) <= rva < int(row["endRva"]) for row in existing):
            continue
        sec = _exec_section(view, rva)
        if sec is None:
            continue
        valid.append((candidate, sec))
        boundaries_by_section.setdefault(int(sec.index), set()).add(rva)

    out: list[dict[str, Any]] = []
    for candidate, sec in valid:
        start = int(candidate["rva"])
        boundaries = sorted(
            value for value in boundaries_by_section.get(int(sec.index), set())
            if value > start
        )
        end = boundaries[0] if boundaries else sec.addr + sec.size
        end = min(end, sec.addr + sec.size, start + max_function_bytes)
        if end <= start:
            continue
        source = str(candidate.get("source") or "UNWIND")
        out.append({
            "name": f"recovered_{start:x}",
            "rva": start,
            "endRva": end,
            "size": end - start,
            "thumb": bool(candidate.get("thumb")),
            "section": sec,
            "boundarySource": source,
            "boundaryConfidence": candidate.get("confidence"),
            "recoveredBoundary": True,
            "metadataSection": candidate.get("metadataSection"),
            "metadataRva": candidate.get("metadataRva"),
        })
    out.sort(key=lambda row: (int(row["rva"]), str(row["name"])))
    return out
