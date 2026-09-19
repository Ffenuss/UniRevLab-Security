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


def _arm32_flow_elf() -> bytes:
    shstr, sh = _cstr_offsets([
        ".shstrtab", ".strtab", ".symtab", ".dynstr", ".dynsym",
        ".rel.dyn", ".rodata", ".text",
    ])
    strtab, st = _cstr_offsets(["flow_source"])
    dynstr, ds = _cstr_offsets(["dlsym"])

    symtab = bytearray(b"\0" * 16)
    symtab += struct.pack("<IIIBBH", st["flow_source"], 0x1000, 0x20, 0x12, 0, 8)

    dynsym = bytearray(b"\0" * 16)
    dynsym += struct.pack("<IIIBBH", ds["dlsym"], 0, 0, 0x12, 0, 0)

    rel = struct.pack("<II", 0x3000, (1 << 8) | 22)
    rodata = bytearray(b"\0" * 0x40)
    struct.pack_into("<I", rodata, 0, 0x2010)
    struct.pack_into("<I", rodata, 4, 0x3000)
    rodata[0x10:0x10 + len(b"target_arm\0")] = b"target_arm\0"
    text = b"\0" * 0x20

    payloads = [
        b"", shstr, strtab, bytes(symtab), dynstr, bytes(dynsym),
        rel, bytes(rodata), text,
    ]
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
        (sh[".dynstr"], 3, 0x2, 0x2800, offsets[4], len(dynstr), 0, 0, 1, 0),
        (sh[".dynsym"], 11, 0x2, 0x2900, offsets[5], len(dynsym), 4, 1, 4, 16),
        (sh[".rel.dyn"], 9, 0x2, 0x2A00, offsets[6], len(rel), 5, 0, 4, 8),
        (sh[".rodata"], 1, 0x2, 0x2000, offsets[7], len(rodata), 0, 0, 4, 0),
        (sh[".text"], 1, 0x6, 0x1000, offsets[8], len(text), 0, 0, 4, 0),
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


def _arm_flow_decoder(code: bytes, address: int, thumb: bool, max_instructions: int):
    assert address == 0x1000
    assert thumb is False
    return {
        "available": True,
        "version": "5.0",
        "instructions": [
            {
                "address": 0x1000, "size": 4, "mnemonic": "ldr",
                "opStr": "r1, [pc, #0xff8]",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": ["pc"], "regsWrite": ["r1"],
                "operands": [
                    {"type": "REG", "reg": "r1", "access": 2},
                    {
                        "type": "MEM", "access": 1,
                        "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8},
                    },
                ],
            },
            {
                "address": 0x1004, "size": 4, "mnemonic": "ldr",
                "opStr": "r4, [pc, #0xff8]",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": ["pc"], "regsWrite": ["r4"],
                "operands": [
                    {"type": "REG", "reg": "r4", "access": 2},
                    {
                        "type": "MEM", "access": 1,
                        "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8},
                    },
                ],
            },
            {
                "address": 0x1008, "size": 4, "mnemonic": "mov",
                "opStr": "r0, #0",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": [], "regsWrite": ["r0"],
                "operands": [
                    {"type": "REG", "reg": "r0", "access": 2},
                    {"type": "IMM", "imm": 0, "access": 1},
                ],
            },
            {
                "address": 0x100C, "size": 4, "mnemonic": "blx",
                "opStr": "r4",
                "isCall": True, "isJump": False, "isRet": False,
                "hasImmediateTarget": False,
                "regsRead": ["r4"], "regsWrite": ["lr"],
                "operands": [
                    {"type": "REG", "reg": "r4", "access": 1},
                ],
            },
            {
                "address": 0x1010, "size": 4, "mnemonic": "mov",
                "opStr": "r5, r0",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": ["r0"], "regsWrite": ["r5"],
                "operands": [
                    {"type": "REG", "reg": "r5", "access": 2},
                    {"type": "REG", "reg": "r0", "access": 1},
                ],
            },
            {
                "address": 0x1014, "size": 4, "mnemonic": "blx",
                "opStr": "r5",
                "isCall": True, "isJump": False, "isRet": False,
                "hasImmediateTarget": False,
                "regsRead": ["r5"], "regsWrite": ["lr"],
                "operands": [
                    {"type": "REG", "reg": "r5", "access": 1},
                ],
            },
        ],
    }


def test_arm32_capstone_tracks_literal_import_arguments_and_dlsym_result():
    report = arm32_deep.analyze_elf(
        _arm32_flow_elf(),
        apk_name="fixture.apk",
        entry="lib/armeabi-v7a/libgame.so",
        decoder=_arm_flow_decoder,
    )

    assert report["available"] is True
    assert report["capstoneFunctionCount"] == 1
    assert report["operandDetailAvailable"] is True
    assert report["relocationSymbolCount"] == 1

    dlsym_call = next(
        row for row in report["edges"]
        if row["instructionRva"] == 0x100C
    )
    assert dlsym_call["targetFunction"] == "dlsym"
    assert dlsym_call["targetResolution"] == "ELF_RELOCATION_REGISTER_FLOW"
    assert dlsym_call["lookupIdentifier"] == "target_arm"
    assert dlsym_call["argumentEvidence"][1]["kind"] == "string"
    assert dlsym_call["argumentEvidence"][1]["address"] == 0x2010

    indirect = next(
        row for row in report["edges"]
        if row["instructionRva"] == 0x1014
    )
    assert indirect["targetFunction"] == "target_arm"
    assert indirect["targetResolution"] == "DLSYM_RESULT_FLOW"

    finding = next(
        row for row in report["findings"]
        if row["instructionRva"] == 0x1014
    )
    assert finding["kind"] == "ARM32_DYNAMIC_LOOKUP_FLOW"
    assert finding["patchReady"] is False
    assert finding["automationExcluded"] is True


def test_arm32_apk_scan_propagates_cancellation(tmp_path):
    import zipfile

    apk = tmp_path / "cancel.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/armeabi-v7a/libgame.so", _arm32_code_elf())

    class Cancel:
        def isCancelled(self):
            return True

    import pytest
    with pytest.raises(arm32_deep.Arm32ScanCancelled):
        arm32_deep.scan_apk_paths([apk], cb=Cancel())


def test_arm32_cfg_propagates_literal_fact_across_branch_and_skips_dead_block():
    def decoder(code: bytes, address: int, thumb: bool, max_instructions: int):
        return {
            "available": True,
            "version": "5.0",
            "instructions": [
                {
                    "address": 0x1000, "size": 4, "mnemonic": "ldr",
                    "opStr": "r1, [pc, #0xff8]",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": ["pc"], "regsWrite": ["r1"],
                    "operands": [
                        {"type": "REG", "reg": "r1", "access": 2},
                        {"type": "MEM", "access": 1,
                         "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8}},
                    ],
                },
                {
                    "address": 0x1004, "size": 4, "mnemonic": "ldr",
                    "opStr": "r4, [pc, #0xff8]",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": ["pc"], "regsWrite": ["r4"],
                    "operands": [
                        {"type": "REG", "reg": "r4", "access": 2},
                        {"type": "MEM", "access": 1,
                         "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8}},
                    ],
                },
                {
                    "address": 0x1008, "size": 4, "mnemonic": "b",
                    "opStr": "0x1014",
                    "isCall": False, "isJump": True, "isRet": False,
                    "hasImmediateTarget": True, "immediateTarget": 0x1014,
                    "regsRead": [], "regsWrite": ["pc"],
                    "operands": [{"type": "IMM", "imm": 0x1014, "access": 1}],
                },
                {
                    "address": 0x100C, "size": 4, "mnemonic": "mov",
                    "opStr": "r1, #0",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": [], "regsWrite": ["r1"],
                    "operands": [
                        {"type": "REG", "reg": "r1", "access": 2},
                        {"type": "IMM", "imm": 0, "access": 1},
                    ],
                },
                {
                    "address": 0x1014, "size": 4, "mnemonic": "mov",
                    "opStr": "r0, #0",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": [], "regsWrite": ["r0"],
                    "operands": [
                        {"type": "REG", "reg": "r0", "access": 2},
                        {"type": "IMM", "imm": 0, "access": 1},
                    ],
                },
                {
                    "address": 0x1018, "size": 4, "mnemonic": "blx",
                    "opStr": "r4",
                    "isCall": True, "isJump": False, "isRet": False,
                    "hasImmediateTarget": False,
                    "regsRead": ["r4"], "regsWrite": ["lr"],
                    "operands": [{"type": "REG", "reg": "r4", "access": 1}],
                },
            ],
        }

    report = arm32_deep.analyze_elf(_arm32_flow_elf(), decoder=decoder)
    call = next(row for row in report["edges"] if row["instructionRva"] == 0x1018)
    assert call["targetFunction"] == "dlsym"
    assert call["lookupIdentifier"] == "target_arm"
    assert call["argumentEvidence"][1]["value"] == "target_arm"
    assert call["basicBlockRva"] == 0x1014
    assert report["basicBlockCount"] == 3
    assert report["reachableBasicBlockCount"] == 2
    assert report["cfgConverged"] is True
    assert report["policy"]["crossBasicBlockValuePropagation"] is True


def test_arm32_cfg_join_drops_conflicting_argument_fact_fail_closed():
    def decoder(code: bytes, address: int, thumb: bool, max_instructions: int):
        return {
            "available": True,
            "version": "5.0",
            "instructions": [
                {
                    "address": 0x1000, "size": 4, "mnemonic": "ldr",
                    "opStr": "r1, [pc, #0xff8]",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": ["pc"], "regsWrite": ["r1"],
                    "operands": [
                        {"type": "REG", "reg": "r1", "access": 2},
                        {"type": "MEM", "access": 1,
                         "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8}},
                    ],
                },
                {
                    "address": 0x1004, "size": 4, "mnemonic": "ldr",
                    "opStr": "r4, [pc, #0xff8]",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": ["pc"], "regsWrite": ["r4"],
                    "operands": [
                        {"type": "REG", "reg": "r4", "access": 2},
                        {"type": "MEM", "access": 1,
                         "mem": {"base": "pc", "index": "", "scale": 1, "disp": 0xFF8}},
                    ],
                },
                {
                    "address": 0x1008, "size": 4, "mnemonic": "bne",
                    "opStr": "0x1014",
                    "isCall": False, "isJump": True, "isRet": False,
                    "hasImmediateTarget": True, "immediateTarget": 0x1014,
                    "regsRead": [], "regsWrite": ["pc"],
                    "operands": [{"type": "IMM", "imm": 0x1014, "access": 1}],
                },
                {
                    "address": 0x100C, "size": 4, "mnemonic": "mov",
                    "opStr": "r1, #0",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": [], "regsWrite": ["r1"],
                    "operands": [
                        {"type": "REG", "reg": "r1", "access": 2},
                        {"type": "IMM", "imm": 0, "access": 1},
                    ],
                },
                {
                    "address": 0x1010, "size": 4, "mnemonic": "b",
                    "opStr": "0x1018",
                    "isCall": False, "isJump": True, "isRet": False,
                    "hasImmediateTarget": True, "immediateTarget": 0x1018,
                    "regsRead": [], "regsWrite": ["pc"],
                    "operands": [{"type": "IMM", "imm": 0x1018, "access": 1}],
                },
                {
                    "address": 0x1014, "size": 4, "mnemonic": "nop",
                    "opStr": "",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": [], "regsWrite": [],
                    "operands": [],
                },
                {
                    "address": 0x1018, "size": 4, "mnemonic": "mov",
                    "opStr": "r0, #0",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": [], "regsWrite": ["r0"],
                    "operands": [
                        {"type": "REG", "reg": "r0", "access": 2},
                        {"type": "IMM", "imm": 0, "access": 1},
                    ],
                },
                {
                    "address": 0x101C, "size": 4, "mnemonic": "blx",
                    "opStr": "r4",
                    "isCall": True, "isJump": False, "isRet": False,
                    "hasImmediateTarget": False,
                    "regsRead": ["r4"], "regsWrite": ["lr"],
                    "operands": [{"type": "REG", "reg": "r4", "access": 1}],
                },
            ],
        }

    report = arm32_deep.analyze_elf(_arm32_flow_elf(), decoder=decoder)
    call = next(row for row in report["edges"] if row["instructionRva"] == 0x101C)
    assert call["targetFunction"] == "dlsym"
    assert "lookupIdentifier" not in call
    args = call.get("argumentEvidence") or []
    assert len(args) >= 2
    assert args[1] is None
    assert report["policy"]["joinPolicy"] == "IDENTICAL_FACTS_ONLY"


def _arm32_plt_elf() -> bytes:
    shstr, sh = _cstr_offsets([
        ".shstrtab", ".strtab", ".symtab", ".dynstr", ".dynsym",
        ".rel.plt", ".rodata", ".text", ".plt",
    ])
    strtab, st = _cstr_offsets(["plt_source"])
    dynstr, ds = _cstr_offsets(["dlsym"])

    symtab = bytearray(b"\0" * 16)
    symtab += struct.pack("<IIIBBH", st["plt_source"], 0x1000, 0x18, 0x12, 0, 8)

    dynsym = bytearray(b"\0" * 16)
    dynsym += struct.pack("<IIIBBH", ds["dlsym"], 0, 0, 0x12, 0, 0)

    rel = struct.pack("<II", 0x3000, (1 << 8) | 22)
    rodata = b"target_plt\0"
    text = b"\0" * 0x18
    plt = b"\0" * 0x08

    payloads = [
        b"", shstr, strtab, bytes(symtab), dynstr, bytes(dynsym),
        rel, rodata, text, plt,
    ]
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
        (sh[".dynstr"], 3, 0x2, 0x2800, offsets[4], len(dynstr), 0, 0, 1, 0),
        (sh[".dynsym"], 11, 0x2, 0x2900, offsets[5], len(dynsym), 4, 1, 4, 16),
        (sh[".rel.plt"], 9, 0x2, 0x2A00, offsets[6], len(rel), 5, 0, 4, 8),
        (sh[".rodata"], 1, 0x2, 0x2000, offsets[7], len(rodata), 0, 0, 1, 0),
        (sh[".text"], 1, 0x6, 0x1000, offsets[8], len(text), 0, 0, 4, 0),
        (sh[".plt"], 1, 0x6, 0x1100, offsets[9], len(plt), 0, 0, 4, 0),
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


def _arm_plt_decoder(code: bytes, address: int, thumb: bool, max_instructions: int):
    if address == 0x1100:
        assert thumb is False
        return {
            "available": True,
            "version": "5.0",
            "instructions": [
                {
                    "address": 0x1100, "size": 4, "mnemonic": "add",
                    "opStr": "ip, pc, #0x1ef8",
                    "isCall": False, "isJump": False, "isRet": False,
                    "regsRead": ["pc"], "regsWrite": ["ip"],
                    "operands": [
                        {"type": "REG", "reg": "ip", "access": 2},
                        {"type": "REG", "reg": "pc", "access": 1},
                        {"type": "IMM", "imm": 0x1EF8, "access": 1},
                    ],
                },
                {
                    "address": 0x1104, "size": 4, "mnemonic": "ldr",
                    "opStr": "pc, [ip]",
                    "isCall": False, "isJump": True, "isRet": False,
                    "hasImmediateTarget": False,
                    "regsRead": ["ip"], "regsWrite": ["pc"],
                    "operands": [
                        {"type": "REG", "reg": "pc", "access": 2},
                        {"type": "MEM", "access": 1,
                         "mem": {"base": "ip", "index": "", "scale": 1, "disp": 0}},
                    ],
                },
            ],
        }

    assert address == 0x1000
    return {
        "available": True,
        "version": "5.0",
        "instructions": [
            {
                "address": 0x1000, "size": 4, "mnemonic": "mov",
                "opStr": "r1, #0x2000",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": [], "regsWrite": ["r1"],
                "operands": [
                    {"type": "REG", "reg": "r1", "access": 2},
                    {"type": "IMM", "imm": 0x2000, "access": 1},
                ],
            },
            {
                "address": 0x1004, "size": 4, "mnemonic": "mov",
                "opStr": "r0, #0",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": [], "regsWrite": ["r0"],
                "operands": [
                    {"type": "REG", "reg": "r0", "access": 2},
                    {"type": "IMM", "imm": 0, "access": 1},
                ],
            },
            {
                "address": 0x1008, "size": 4, "mnemonic": "bl",
                "opStr": "0x1100",
                "isCall": True, "isJump": False, "isRet": False,
                "hasImmediateTarget": True, "immediateTarget": 0x1100,
                "regsRead": [], "regsWrite": ["lr"],
                "operands": [{"type": "IMM", "imm": 0x1100, "access": 1}],
            },
            {
                "address": 0x100C, "size": 4, "mnemonic": "mov",
                "opStr": "r5, r0",
                "isCall": False, "isJump": False, "isRet": False,
                "regsRead": ["r0"], "regsWrite": ["r5"],
                "operands": [
                    {"type": "REG", "reg": "r5", "access": 2},
                    {"type": "REG", "reg": "r0", "access": 1},
                ],
            },
            {
                "address": 0x1010, "size": 4, "mnemonic": "blx",
                "opStr": "r5",
                "isCall": True, "isJump": False, "isRet": False,
                "hasImmediateTarget": False,
                "regsRead": ["r5"], "regsWrite": ["lr"],
                "operands": [{"type": "REG", "reg": "r5", "access": 1}],
            },
        ],
    }


def test_arm32_resolves_relocation_backed_plt_veneer_and_dlsym_result():
    report = arm32_deep.analyze_elf(
        _arm32_plt_elf(),
        apk_name="fixture.apk",
        entry="lib/armeabi-v7a/libgame.so",
        decoder=_arm_plt_decoder,
    )

    assert report["pltImportTargetCount"] == 1
    direct = next(row for row in report["edges"] if row["instructionRva"] == 0x1008)
    assert direct["targetRva"] == 0x1100
    assert direct["targetFunction"] == "dlsym"
    assert direct["targetResolution"] == "ELF_RELOCATION_PLT"
    assert direct["lookupIdentifier"] == "target_plt"

    indirect = next(row for row in report["edges"] if row["instructionRva"] == 0x1010)
    assert indirect["targetFunction"] == "target_plt"
    assert indirect["targetResolution"] == "DLSYM_RESULT_FLOW"
    assert report["policy"]["armPltRelocationFlow"] is True


def _arm32_stripped_exidx_elf() -> bytes:
    shstr, sh = _cstr_offsets([".shstrtab", ".ARM.exidx", ".text"])
    text = bytearray(b"\0" * 0x20)
    struct.pack_into("<I", text, 0x00, 0xEB000002)  # BL 0x1010
    struct.pack_into("<I", text, 0x04, 0xE12FFF1E)  # BX LR
    struct.pack_into("<I", text, 0x10, 0xE12FFF1E)  # recovered target

    def prel31(place: int, target: int) -> int:
        return (target - place) & 0x7FFFFFFF

    exidx = (
        struct.pack("<II", prel31(0x3000, 0x1000), 1)
        + struct.pack("<II", prel31(0x3008, 0x1010), 1)
    )
    payloads = [b"", shstr, exidx, bytes(text)]
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
        (sh[".ARM.exidx"], 1, 0x2, 0x3000, offsets[2], len(exidx), 0, 0, 4, 8),
        (sh[".text"], 1, 0x6, 0x1000, offsets[3], len(text), 0, 0, 4, 0),
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


def test_arm32_stripped_elf_recovers_functions_from_exidx():
    def decoder(code: bytes, address: int, thumb: bool, max_instructions: int):
        return {"available": True, "version": "5.0", "instructions": []}

    report = arm32_deep.analyze_elf(
        _arm32_stripped_exidx_elf(),
        apk_name="stripped.apk",
        entry="lib/armeabi-v7a/libgame.so",
        decoder=decoder,
    )

    assert report["symbolFunctionCount"] == 0
    assert report["recoveredFunctionCount"] == 2
    assert report["functionCount"] == 2
    assert report["policy"]["symbolBoundedOnly"] is False
    assert report["policy"]["symbolOrExactUnwindBounded"] is True
    assert report["policy"]["unwindFunctionRecovery"] is True

    call = next(row for row in report["edges"] if row["instructionRva"] == 0x1000)
    assert call["targetRva"] == 0x1010
    assert call["targetResolution"] == "EXACT_UNWIND_START"
    assert call["targetBoundarySource"] == "ARM_EXIDX"
    assert call["functionBoundarySource"] == "ARM_EXIDX"
    assert call["recoveredFunctionBoundary"] is True
