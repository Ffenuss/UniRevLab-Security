from __future__ import annotations

import struct

from modkit.mobile import x86_deep


def _cstr_offsets(values: list[str]) -> tuple[bytes, dict[str, int]]:
    out = bytearray(b"\0")
    offsets: dict[str, int] = {}
    for value in values:
        offsets[value] = len(out)
        out += value.encode("ascii") + b"\0"
    return bytes(out), offsets


def _x64_flow_elf() -> bytes:
    shstr, sh = _cstr_offsets([
        ".shstrtab", ".strtab", ".symtab", ".dynstr", ".dynsym",
        ".rela.dyn", ".rodata", ".text",
    ])
    strtab, st = _cstr_offsets(["source"])
    dynstr, ds = _cstr_offsets(["dlsym"])

    symtab = bytearray(b"\0" * 24)
    symtab += struct.pack("<IBBHQQ", st["source"], 0x12, 0, 7, 0x1000, 0x20)

    dynsym = bytearray(b"\0" * 24)
    dynsym += struct.pack("<IBBHQQ", ds["dlsym"], 0x12, 0, 0, 0, 0)

    rela = struct.pack("<QQq", 0x4000, (1 << 32) | 7, 0)
    rodata = b"target_fn\0"
    text = b"\x90" * 0x20

    payloads = [
        b"", shstr, strtab, bytes(symtab), dynstr, bytes(dynsym),
        rela, rodata, text,
    ]
    offsets = [0] * len(payloads)
    blob = bytearray(b"\0" * 64)
    cursor = 64
    for idx in range(1, len(payloads)):
        cursor = (cursor + 7) & ~7
        if len(blob) < cursor:
            blob += b"\0" * (cursor - len(blob))
        offsets[idx] = cursor
        blob += payloads[idx]
        cursor += len(payloads[idx])

    shoff = (len(blob) + 7) & ~7
    if len(blob) < shoff:
        blob += b"\0" * (shoff - len(blob))

    headers = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (sh[".shstrtab"], 3, 0, 0, offsets[1], len(shstr), 0, 0, 1, 0),
        (sh[".strtab"], 3, 0, 0, offsets[2], len(strtab), 0, 0, 1, 0),
        (sh[".symtab"], 2, 0, 0, offsets[3], len(symtab), 2, 1, 8, 24),
        (sh[".dynstr"], 3, 0x2, 0x3000, offsets[4], len(dynstr), 0, 0, 1, 0),
        (sh[".dynsym"], 11, 0x2, 0x3100, offsets[5], len(dynsym), 4, 1, 8, 24),
        (sh[".rela.dyn"], 4, 0x2, 0x3200, offsets[6], len(rela), 5, 0, 8, 24),
        (sh[".rodata"], 1, 0x2, 0x2000, offsets[7], len(rodata), 0, 0, 1, 0),
        (sh[".text"], 1, 0x6, 0x1000, offsets[8], len(text), 0, 0, 16, 0),
    ]
    for row in headers:
        blob += struct.pack("<IIQQQQIIQQ", *row)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident), 3, 62, 1, 0x1000, 0, shoff, 0,
        64, 0, 0, 64, len(headers), 1,
    )
    blob[:64] = hdr
    return bytes(blob)


def _decoder(code: bytes, address: int, arch: str, max_instructions: int):
    assert arch == "x86_64"
    assert max_instructions >= 5
    if address != 0x1000:
        return {
            "available": True,
            "version": "5.0",
            "instructions": [],
        }

    return {
        "available": True,
        "version": "5.0",
        "instructions": [
            {
                "address": 0x1000,
                "size": 2,
                "mnemonic": "xor",
                "opStr": "edi, edi",
                "isCall": False,
                "isJump": False,
                "isRet": False,
                "regsRead": ["edi"],
                "regsWrite": ["edi"],
                "operands": [
                    {"type": "REG", "reg": "edi", "size": 4, "access": 3},
                    {"type": "REG", "reg": "edi", "size": 4, "access": 1},
                ],
            },
            {
                "address": 0x1002,
                "size": 7,
                "mnemonic": "lea",
                "opStr": "rsi, [rip + 0xff7]",
                "isCall": False,
                "isJump": False,
                "isRet": False,
                "regsRead": ["rip"],
                "regsWrite": ["rsi"],
                "operands": [
                    {"type": "REG", "reg": "rsi", "size": 8, "access": 2},
                    {
                        "type": "MEM", "size": 8, "access": 1,
                        "mem": {
                            "segment": "", "base": "rip", "index": "",
                            "scale": 1, "disp": 0xFF7,
                        },
                    },
                ],
            },
            {
                "address": 0x1009,
                "size": 6,
                "mnemonic": "call",
                "opStr": "qword ptr [rip + 0x2ff1]",
                "isCall": True,
                "isJump": False,
                "isRet": False,
                "hasImmediateTarget": False,
                "regsRead": ["rsp", "rip"],
                "regsWrite": ["rsp"],
                "operands": [
                    {
                        "type": "MEM", "size": 8, "access": 1,
                        "mem": {
                            "segment": "", "base": "rip", "index": "",
                            "scale": 1, "disp": 0x2FF1,
                        },
                    },
                ],
            },
            {
                "address": 0x100F,
                "size": 3,
                "mnemonic": "mov",
                "opStr": "rbx, rax",
                "isCall": False,
                "isJump": False,
                "isRet": False,
                "regsRead": ["rax"],
                "regsWrite": ["rbx"],
                "operands": [
                    {"type": "REG", "reg": "rbx", "size": 8, "access": 2},
                    {"type": "REG", "reg": "rax", "size": 8, "access": 1},
                ],
            },
            {
                "address": 0x1012,
                "size": 2,
                "mnemonic": "call",
                "opStr": "rbx",
                "isCall": True,
                "isJump": False,
                "isRet": False,
                "hasImmediateTarget": False,
                "regsRead": ["rbx", "rsp"],
                "regsWrite": ["rsp"],
                "operands": [
                    {"type": "REG", "reg": "rbx", "size": 8, "access": 1},
                ],
            },
        ],
    }


def test_x86_64_tracks_rip_relative_import_args_and_dlsym_result():
    report = x86_deep.analyze_elf(
        _x64_flow_elf(),
        apk_name="fixture.apk",
        entry="lib/x86_64/libgame.so",
        decoder=_decoder,
    )

    assert report["available"] is True
    assert report["operandDetailAvailable"] is True
    assert report["relocationSymbolCount"] == 1
    assert report["policy"]["x86_64SysVArgumentFlow"] is True
    assert report["policy"]["dlsymReturnFlow"] is True

    dlsym_call = next(
        row for row in report["edges"]
        if row["instructionRva"] == 0x1009
    )
    assert dlsym_call["targetFunction"] == "dlsym"
    assert dlsym_call["targetResolution"] == "ELF_RELOCATION_MEMORY"
    assert dlsym_call["relocationSlotRva"] == 0x4000
    assert dlsym_call["lookupIdentifier"] == "target_fn"
    assert dlsym_call["argumentEvidence"][1]["kind"] == "string"
    assert dlsym_call["argumentEvidence"][1]["address"] == 0x2000

    indirect = next(
        row for row in report["edges"]
        if row["instructionRva"] == 0x1012
    )
    assert indirect["targetFunction"] == "target_fn"
    assert indirect["targetResolution"] == "DLSYM_RESULT_FLOW"
    assert indirect["dynamicLookupCallRva"] == 0x1009

    finding = next(
        row for row in report["findings"]
        if row["instructionRva"] == 0x1012
    )
    assert finding["kind"] == "X86_DYNAMIC_LOOKUP_FLOW"
    assert finding["patchReady"] is False
    assert finding["automationExcluded"] is True


def test_x86_without_structured_operands_does_not_invent_indirect_target():
    def minimal_decoder(code: bytes, address: int, arch: str, max_instructions: int):
        return {
            "available": True,
            "version": "5.0",
            "instructions": [
                {
                    "address": 0x1000,
                    "size": 2,
                    "mnemonic": "call",
                    "opStr": "rax",
                    "isCall": True,
                    "isJump": False,
                    "isRet": False,
                    "hasImmediateTarget": False,
                    "regsRead": ["rax"],
                    "regsWrite": [],
                },
            ],
        }

    report = x86_deep.analyze_elf(_x64_flow_elf(), decoder=minimal_decoder)
    edge = next(row for row in report["edges"] if row["edgeKind"] == "indirect-call")
    assert edge["targetFunction"] is None
    assert edge["targetResolution"] == "INDIRECT_UNRESOLVED"
    assert report["operandDetailAvailable"] is False
