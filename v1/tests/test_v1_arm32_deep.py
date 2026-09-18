from __future__ import annotations

import struct

from modkit.mobile import arm32_deep


def _cstr_offsets(values: list[str]) -> tuple[bytes, dict[str, int]]:
    out = bytearray(b"\0")
    offsets: dict[str, int] = {}
    for value in values:
        offsets[value] = len(out)
        out += value.encode("ascii") + b"\0"
    return bytes(out), offsets


def _arm32_code_elf() -> bytes:
    shstr, sh = _cstr_offsets([".shstrtab", ".strtab", ".symtab", ".text"])
    strtab, st = _cstr_offsets([
        "a32_source", "a32_target", "thumb_source", "thumb_target",
    ])

    text = bytearray(b"\x00" * 0x40)
    struct.pack_into("<I", text, 0x00, 0xEB000002)  # BL 0x1010 from 0x1000
    struct.pack_into("<I", text, 0x04, 0xE12FFF1E)  # BX LR
    struct.pack_into("<I", text, 0x10, 0xE12FFF1E)  # target: BX LR

    # Thumb-2 BL 0x1030 from 0x1020: 00 F0 06 F8.
    struct.pack_into("<HH", text, 0x20, 0xF000, 0xF806)
    struct.pack_into("<H", text, 0x24, 0x4770)      # BX LR
    struct.pack_into("<H", text, 0x26, 0xBF00)      # NOP
    struct.pack_into("<H", text, 0x30, 0x4770)      # target: BX LR
    struct.pack_into("<H", text, 0x32, 0xBF00)

    symtab = bytearray(b"\0" * 16)
    symtab += struct.pack("<IIIBBH", st["a32_source"], 0x1000, 8, 0x12, 0, 4)
    symtab += struct.pack("<IIIBBH", st["a32_target"], 0x1010, 4, 0x12, 0, 4)
    symtab += struct.pack("<IIIBBH", st["thumb_source"], 0x1021, 8, 0x12, 0, 4)
    symtab += struct.pack("<IIIBBH", st["thumb_target"], 0x1031, 4, 0x12, 0, 4)

    payloads = [b"", shstr, strtab, bytes(symtab), bytes(text)]
    offsets = [0] * len(payloads)
    blob = bytearray(b"\0" * 52)
    cursor = 52
    for idx in range(1, len(payloads)):
        cursor = (cursor + 3) & ~3
        if len(blob) < cursor:
            blob += b"\0" * (cursor - len(blob))
        offsets[idx] = cursor
        blob += payloads[idx]
        cursor += len(payloads[idx])

    shoff = (len(blob) + 3) & ~3
    if len(blob) < shoff:
        blob += b"\0" * (shoff - len(blob))

    headers = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (sh[".shstrtab"], 3, 0, 0, offsets[1], len(shstr), 0, 0, 1, 0),
        (sh[".strtab"], 3, 0, 0, offsets[2], len(strtab), 0, 0, 1, 0),
        (sh[".symtab"], 2, 0, 0, offsets[3], len(symtab), 2, 1, 4, 16),
        (sh[".text"], 1, 0x6, 0x1000, offsets[4], len(text), 0, 0, 4, 0),
    ]
    for row in headers:
        blob += struct.pack("<IIIIIIIIII", *row)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 1
    ident[6] = 1
    hdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        bytes(ident), 3, 40, 1, 0x1000, 0, shoff, 0,
        52, 0, 0, 40, len(headers), 1,
    )
    blob[:52] = hdr
    return bytes(blob)


def test_arm32_deep_decodes_a32_and_thumb2_symbol_bounded_calls():
    report = arm32_deep.analyze_elf(
        _arm32_code_elf(), apk_name="fixture.apk",
        entry="lib/armeabi-v7a/libgame.so",
    )
    assert report["available"] is True
    assert report["functionCount"] == 4
    assert report["a32FunctionCount"] == 2
    assert report["thumbFunctionCount"] == 2
    assert report["policy"]["symbolBoundedOnly"] is True
    assert report["policy"]["strippedRegionGuessing"] is False
    assert report["policy"]["x86ByteHeuristicUsed"] is False

    edges = report["edges"]
    a32_call = next(row for row in edges if row["kind"] == "arm-a32-bl")
    assert a32_call["sourceFunction"] == "a32_source"
    assert a32_call["instructionRva"] == 0x1000
    assert a32_call["targetRva"] == 0x1010
    assert a32_call["targetFunction"] == "a32_target"
    assert a32_call["targetResolution"] == "STATIC_SYMBOL"

    thumb_call = next(row for row in edges if row["kind"] == "arm-thumb2-bl")
    assert thumb_call["sourceFunction"] == "thumb_source"
    assert thumb_call["instructionRva"] == 0x1020
    assert thumb_call["targetRva"] == 0x1030
    assert thumb_call["targetFunction"] == "thumb_target"
    assert thumb_call["targetResolution"] == "STATIC_SYMBOL"
    assert thumb_call["instructionWidth"] == 4
    assert thumb_call["mode"] == "THUMB"

    a32_bx = next(
        row for row in edges
        if row["sourceFunction"] == "a32_source" and row["kind"] == "arm-a32-bx-register"
    )
    assert a32_bx["targetRegister"] == 14
    assert a32_bx["targetResolution"] == "REGISTER_INDIRECT_UNRESOLVED"

    thumb_bx = next(
        row for row in edges
        if row["sourceFunction"] == "thumb_source" and row["kind"] == "arm-thumb-bx-register"
    )
    assert thumb_bx["targetRegister"] == 14

    assert report["findingCount"] >= 4
    assert all(row["instructionBoundaryConfirmed"] is True for row in report["findings"])
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_thumb_16bit_conditional_and_unconditional_targets():
    # BNE +4 from PC=0x2000 => PC+4 + 4 = 0x2008.
    raw = struct.pack("<HH", 0xD102, 0xE000)
    edges = arm32_deep._thumb_edges(
        raw, 0x2000, "thumb16", 0, {}, None,
    )
    cond = next(row for row in edges if row["kind"] == "arm-thumb-b-cond")
    uncond = next(row for row in edges if row["kind"] == "arm-thumb-b")
    assert cond["targetRva"] == 0x2008
    # second instruction at 0x2002: B +0 => PC+4 = 0x2006
    assert uncond["targetRva"] == 0x2006
