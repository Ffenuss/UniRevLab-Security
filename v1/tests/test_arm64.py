"""AArch64 encoders — checked against hand-computed instruction words and a decoder."""

from __future__ import annotations

import pytest

from modkit.arch import arm64


def word(b: bytes) -> int:
    assert len(b) == 4
    return int.from_bytes(b, "little")


def test_movz_w0_zero():
    assert word(arm64.movz(0, 0, 0, wide=False)) == 0x52800000


def test_movz_x0_shifted():
    # MOVZ X0, #0x1234, LSL #16  ->  0xD2A24680
    assert word(arm64.movz(0, 0x1234, 16, wide=True)) == 0xD2A24680


def test_movk_matches_movz_pattern():
    assert word(arm64.movk(0, 0x1234, 16, wide=True)) == 0xF2A24680
    assert word(arm64.movk(0, 0x0001, 0, wide=False)) == 0x72800020


def test_ret_and_br():
    assert word(arm64.ret()) == 0xD65F03C0
    assert word(arm64.br(16)) == 0xD61F0200


def test_branch_immediate():
    assert word(arm64.b(0x10)) == 0x14000004
    assert word(arm64.bl(-4)) == 0x97FFFFFF   # imm26 = -1


def test_branch_range_is_enforced():
    with pytest.raises(ValueError):
        arm64.b(arm64.BRANCH_RANGE * 2)
    with pytest.raises(ValueError):
        arm64.b(6)


def decode_adrp(w: int, pc: int) -> int:
    lo = (w >> 29) & 3
    hi = (w >> 5) & 0x7FFFF
    imm = (hi << 2) | lo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def decode_add_imm(w: int) -> tuple[int, int, int]:
    return (w & 0x1F), (w >> 5) & 0x1F, (w >> 10) & 0xFFF


def test_adrp_add_roundtrip():
    pc, target = 0x1040, 0x1A2B40
    code = arm64.adrp(16, pc, target & ~0xFFF) + arm64.add_imm(16, 16, target & 0xFFF)
    page = decode_adrp(word(code[:4]), pc)
    rd, rn, imm12 = decode_add_imm(word(code[4:]))
    assert page + imm12 == target
    assert (rd, rn) == (16, 16)


def test_jump_abs_reaches_everywhere():
    code = arm64.jump_abs(0xFFFFF000, 0x10)
    assert len(code) == 12
    assert word(code[8:]) == 0xD61F0200  # br x16


def test_const_return_small_value():
    code = arm64.const_return(999, width=4)
    assert word(code[-4:]) == 0xD65F03C0
    assert ((word(code[:4]) >> 5) & 0xFFFF) == 999
    assert (word(code[:4]) & 0x80000000) == 0        # 32-bit MOVZ
    assert len(code) == 8


def test_const_return_wide_and_negative():
    code = arm64.const_return(-1, width=8)
    assert word(code[:4]) & 0x80000000                 # 64-bit MOVZ
    assert ((word(code[:4]) >> 5) & 0xFFFF) == 0xFFFF
    code4 = arm64.const_return(0x1_0000_0000, width=4)  # needs two chunks + ret
    assert len(code4) == arm64.const_return_size(0x1_0000_0000, width=4)


def test_const_return_size_matches_emission():
    for v in (0, 1, 0xFFFF, 0x10000, 0xFFFFFFFF, -1, 1 << 40):
        assert len(arm64.const_return(v, width=8)) == arm64.const_return_size(v, width=8)


def test_trampoline_prefers_short_branch():
    near = arm64.trampoline(0x2000, 0x1000)
    assert len(near) == 16
    assert word(near[:4]) & 0xFC000000 == 0x14000000
    far = arm64.trampoline(0x1_0000_0000, 0x1000)
    assert word(far[8:12]) == 0xD61F0200


def test_nop_and_ldr_str():
    assert word(arm64.nop()) == 0xD503201F
    assert word(arm64.ldr_imm(0, 1, 0x10, size=4)) == 0xB9401020
    assert word(arm64.str_imm(0, 1, 8, size=8)) == 0xF9000420
    assert word(arm64.ldr_imm(2, 31, 0, size=1)) == 0x394003E2
    with pytest.raises(ValueError):
        arm64.ldr_imm(0, 1, 40000)         # 40000/8 = 5000 > the 12-bit field
    with pytest.raises(ValueError):
        arm64.ldr_imm(0, 1, 5, size=4)     # misaligned for a 4-byte access


def test_disasm_labels_known_encodings():
    lines = arm64.disasm(arm64.ret() + arm64.movz(0, 0), base=0x40)
    assert lines[0].endswith("ret")
    assert "movz" in lines[1]
