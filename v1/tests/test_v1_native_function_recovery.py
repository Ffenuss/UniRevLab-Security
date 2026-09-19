from __future__ import annotations

import struct
from types import SimpleNamespace

from modkit.mobile import native_function_recovery as recovery
from modkit.mobile.native_portable import EM_ARM, EM_X86_64, Section


class FakeView:
    def __init__(self, *, machine: int, bits: int, sections: list[Section], payloads: dict[int, bytes]):
        self.machine = machine
        self.bits = bits
        self.sections = sections
        self.section_by_name = {row.name: row for row in sections}
        self._payloads = payloads

    def _slice(self, sec: Section) -> bytes:
        return self._payloads.get(sec.index, b"")


def _prel31(place: int, target: int) -> int:
    return (target - place) & 0x7FFFFFFF


def test_arm_exidx_recovers_exact_a32_and_thumb_starts():
    text = Section(1, ".text", 1, 0x6, 0x1000, 0, 0x100, 0, 0, 4)
    exidx = Section(2, ".ARM.exidx", 1, 0x2, 0x3000, 0x100, 16, 0, 0, 4)
    raw = (
        struct.pack("<II", _prel31(0x3000, 0x1000), 1)
        + struct.pack("<II", _prel31(0x3008, 0x1041), 1)
    )
    view = FakeView(machine=EM_ARM, bits=32, sections=[text, exidx], payloads={2: raw})

    rows = recovery.recover_function_starts(view)
    assert [row["rva"] for row in rows] == [0x1000, 0x1040]
    assert rows[0]["source"] == "ARM_EXIDX"
    assert rows[0]["confidence"] == "EXACT_UNWIND_START"
    assert rows[1]["thumb"] is True


def test_eh_frame_hdr_recovers_datarel_function_table():
    text = Section(1, ".text", 1, 0x6, 0x1000, 0, 0x100, 0, 0, 16)
    hdr = Section(2, ".eh_frame_hdr", 1, 0x2, 0x4000, 0x100, 28, 0, 0, 4)

    raw = bytearray([1, 0x1B, 0x03, 0x3B])
    raw += struct.pack("<i", 0x5000 - 0x4004)
    raw += struct.pack("<I", 2)
    raw += struct.pack("<ii", 0x1000 - 0x4000, 0x5000 - 0x4000)
    raw += struct.pack("<ii", 0x1040 - 0x4000, 0x5040 - 0x4000)

    view = FakeView(machine=EM_X86_64, bits=64, sections=[text, hdr], payloads={2: bytes(raw)})
    rows = recovery.recover_function_starts(view)

    assert [row["rva"] for row in rows] == [0x1000, 0x1040]
    assert all(row["source"] == "EH_FRAME_HDR" for row in rows)


def test_recovered_regions_do_not_split_existing_symbol_region():
    text = Section(1, ".text", 1, 0x6, 0x1000, 0, 0x100, 0, 0, 16)
    hdr = Section(2, ".eh_frame_hdr", 1, 0x2, 0x4000, 0x100, 28, 0, 0, 4)
    raw = bytearray([1, 0x1B, 0x03, 0x3B])
    raw += struct.pack("<i", 0x5000 - 0x4004)
    raw += struct.pack("<I", 2)
    raw += struct.pack("<ii", 0x1010 - 0x4000, 0x5000 - 0x4000)
    raw += struct.pack("<ii", 0x1080 - 0x4000, 0x5040 - 0x4000)
    view = FakeView(machine=EM_X86_64, bits=64, sections=[text, hdr], payloads={2: bytes(raw)})

    existing = [{
        "name": "known",
        "rva": 0x1000,
        "endRva": 0x1040,
        "size": 0x40,
        "section": text,
    }]
    rows = recovery.recovered_regions(view, existing, max_function_bytes=0x80)

    assert len(rows) == 1
    assert rows[0]["rva"] == 0x1080
    assert rows[0]["boundarySource"] == "EH_FRAME_HDR"
    assert rows[0]["recoveredBoundary"] is True
