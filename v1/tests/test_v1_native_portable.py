from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from modkit.mobile import native_portable


def _cstr_offsets(values: list[str]) -> tuple[bytes, dict[str, int]]:
    out = bytearray(b"\0")
    offsets: dict[str, int] = {}
    for value in values:
        offsets[value] = len(out)
        out += value.encode("ascii") + b"\0"
    return bytes(out), offsets


def _elf32(machine: int, reloc_type: int) -> bytes:
    shstr, sh = _cstr_offsets([
        ".shstrtab", ".dynstr", ".dynsym", ".rel.plt", ".got.plt", ".dynamic", ".text",
    ])
    dynstr, ds = _cstr_offsets(["dlsym", "Java_com_example_Test", "libdl.so", "libgame.so"])

    dynsym = bytearray(b"\0" * 16)
    dynsym += struct.pack("<IIIBBH", ds["dlsym"], 0, 0, 0x12, 0, 0)
    dynsym += struct.pack("<IIIBBH", ds["Java_com_example_Test"], 0x1000, 8, 0x12, 0, 7)

    rel = struct.pack("<II", 0x3000, (1 << 8) | reloc_type)
    got = b"\0" * 16
    dynamic = (
        struct.pack("<iI", 1, ds["libdl.so"])
        + struct.pack("<iI", 14, ds["libgame.so"])
        + struct.pack("<iI", 0, 0)
    )
    text = b"\x00" * 16

    payloads = [b"", shstr, dynstr, bytes(dynsym), rel, got, dynamic, text]
    offsets = [0] * len(payloads)
    cursor = 52
    blob = bytearray(b"\0" * 52)
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
        (sh[".dynstr"], 3, 0x2, 0x2000, offsets[2], len(dynstr), 0, 0, 1, 0),
        (sh[".dynsym"], 11, 0x2, 0x2100, offsets[3], len(dynsym), 2, 1, 4, 16),
        (sh[".rel.plt"], 9, 0x2, 0x2200, offsets[4], len(rel), 3, 5, 4, 8),
        (sh[".got.plt"], 1, 0x3, 0x3000, offsets[5], len(got), 0, 0, 4, 0),
        (sh[".dynamic"], 6, 0x3, 0x3100, offsets[6], len(dynamic), 2, 0, 4, 8),
        (sh[".text"], 1, 0x6, 0x1000, offsets[7], len(text), 0, 0, 4, 0),
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
        bytes(ident), 3, machine, 1, 0x1000, 0, shoff, 0,
        52, 0, 0, 40, len(headers), 1,
    )
    blob[:52] = hdr
    return bytes(blob)


def _elf64_x86() -> bytes:
    shstr, sh = _cstr_offsets([
        ".shstrtab", ".dynstr", ".dynsym", ".rela.plt", ".got.plt", ".dynamic", ".text",
    ])
    dynstr, ds = _cstr_offsets(["dlsym", "Java_com_example_Test", "libdl.so", "libgame64.so"])

    dynsym = bytearray(b"\0" * 24)
    dynsym += struct.pack("<IBBHQQ", ds["dlsym"], 0x12, 0, 0, 0, 0)
    dynsym += struct.pack("<IBBHQQ", ds["Java_com_example_Test"], 0x12, 0, 7, 0x1000, 8)

    rela = struct.pack("<QQq", 0x4000, (1 << 32) | 7, 0)
    got = b"\0" * 24
    dynamic = (
        struct.pack("<qQ", 1, ds["libdl.so"])
        + struct.pack("<qQ", 14, ds["libgame64.so"])
        + struct.pack("<qQ", 0, 0)
    )
    text = b"\x90" * 16

    payloads = [b"", shstr, dynstr, bytes(dynsym), rela, got, dynamic, text]
    offsets = [0] * len(payloads)
    cursor = 64
    blob = bytearray(b"\0" * 64)
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
        (sh[".dynstr"], 3, 0x2, 0x2000, offsets[2], len(dynstr), 0, 0, 1, 0),
        (sh[".dynsym"], 11, 0x2, 0x2100, offsets[3], len(dynsym), 2, 1, 8, 24),
        (sh[".rela.plt"], 4, 0x2, 0x2200, offsets[4], len(rela), 3, 5, 8, 24),
        (sh[".got.plt"], 1, 0x3, 0x4000, offsets[5], len(got), 0, 0, 8, 0),
        (sh[".dynamic"], 6, 0x3, 0x4100, offsets[6], len(dynamic), 2, 0, 8, 16),
        (sh[".text"], 1, 0x6, 0x1000, offsets[7], len(text), 0, 0, 16, 0),
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


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_portable_native_reads_arm32_symbols_dynamic_and_rel_references(tmp_path: Path):
    apk = _apk(tmp_path / "arm32.apk", {
        "lib/armeabi-v7a/libgame.so": _elf32(40, 22),
    })
    report = native_portable.scan_apk_paths([apk])
    assert report["archCounts"] == {"arm": 1}
    assert report["policy"]["instructionDecoderUsed"] is False
    assert report["policy"]["heuristicByteCallsClaimed"] is False

    lib = report["libraries"][0]
    assert lib["bits"] == 32
    assert lib["arch"] == "arm"
    assert lib["abi"] == "armeabi-v7a"
    assert lib["needed"] == ["libdl.so"]
    assert lib["soname"] == "libgame.so"
    assert "dlsym" in lib["imports"]
    assert "Java_com_example_Test" in lib["exports"]
    ref = lib["interestingRelocationRefs"][0]
    assert ref["symbol"] == "dlsym"
    assert ref["typeName"] == "R_ARM_JUMP_SLOT"
    assert ref["offset"] == 0x3000

    finding = next(row for row in report["findings"] if row["kind"] == "PORTABLE_RELOCATION_SYMBOL_REF")
    assert finding["relocationBacked"] is True
    assert finding["patchReady"] is False
    assert finding["automationExcluded"] is True


def test_portable_native_reads_x86_64_rela_and_jni_export(tmp_path: Path):
    apk = _apk(tmp_path / "x64.apk", {
        "lib/x86_64/libgame.so": _elf64_x86(),
    })
    report = native_portable.scan_apk_paths([apk])
    lib = report["libraries"][0]
    assert lib["bits"] == 64
    assert lib["arch"] == "x86_64"
    assert lib["abi"] == "x86_64"
    assert lib["needed"] == ["libdl.so"]
    assert lib["soname"] == "libgame64.so"
    assert "dlsym" in lib["interestingImports"]
    assert "Java_com_example_Test" in lib["exports"]
    ref = lib["interestingRelocationRefs"][0]
    assert ref["typeName"] == "R_X86_64_JUMP_SLOT"
    assert ref["symbolUndefined"] is True
    assert ref["addend"] == 0
