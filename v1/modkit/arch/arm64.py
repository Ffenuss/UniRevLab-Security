"""Minimal AArch64 (arm64) encoder — enough to build trampolines and constant returns.

Everything here is intentionally little-endian raw bytes: `patch_plan.json` is fed to
the loader at runtime, and `modkit apply` can also write it straight into a copy of
libil2cpp.so for repackaged offline builds.
"""

from __future__ import annotations

import struct

PAGE = 0x1000
BRANCH_RANGE = 128 * 1024 * 1024  # ±128 MiB for B / BL

X0, X1, SP, X16, X17 = 0, 1, 31, 16, 17


def _u32(insn: int) -> bytes:
    return struct.pack("<I", insn & 0xFFFFFFFF)


def align_up(value: int, alignment: int = PAGE) -> int:
    return (value + alignment - 1) // alignment * alignment


# ------------------------------------------------------------------ mov / ret


def movz(rd: int, imm16: int, shift: int = 0, wide: bool = True) -> bytes:
    """MOVZ Xd/Wd, #imm16, LSL #shift (sf selects 64- vs 32-bit)."""
    hw = {0: 0, 16: 1, 32: 2, 48: 3}[shift]
    base = 0xD2800000 if wide else 0x52800000
    return _u32(base | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd)


def movk(rd: int, imm16: int, shift: int = 0, wide: bool = True) -> bytes:
    hw = {0: 0, 16: 1, 32: 2, 48: 3}[shift]
    base = 0xF2800000 if wide else 0x72800000
    return _u32(base | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd)


def mov_imm(rd: int = X0, value: int = 0, wide: bool = True) -> bytes:
    """Materialise an arbitrary 64-bit constant into `rd` using MOVZ/MOVK."""
    if value < 0:  # two's complement, e.g. -1 for bool `true` patches
        value &= (1 << 64) - 1
    parts = [(value >> s) & 0xFFFF for s in (0, 16, 32, 48)]
    if not wide:
        parts = parts[:2]
    first = True
    out = bytearray()
    if all(p == 0 for p in parts):
        return movz(rd, 0, wide=wide)
    for i, p in enumerate(parts):
        if p == 0:
            continue
        if first:
            out += movz(rd, p, 16 * i, wide=wide)
            first = False
        else:
            out += movk(rd, p, 16 * i, wide=wide)
    return bytes(out)


def ret() -> bytes:
    return _u32(0xD65F03C0)


def ret_reg(rn: int = 30) -> bytes:
    return _u32(0xD65F0000 | (rn << 5))


def br(rn: int = X16) -> bytes:
    return _u32(0xD61F0000 | (rn << 5))


def blr(rn: int = X16) -> bytes:
    return _u32(0xD63F0000 | (rn << 5))


def b(offset: int) -> bytes:
    """Unconditional branch, `offset` in bytes from the instruction itself."""
    if offset % 4:
        raise ValueError("branch offset must be 4-byte aligned")
    imm26 = offset >> 2
    if not (-2 ** 25 <= imm26 < 2 ** 25):
        raise ValueError("branch out of range, use jump_abs() instead")
    return _u32(0x14000000 | (imm26 & 0x03FFFFFF))


def bl(offset: int) -> bytes:
    imm26 = offset >> 2
    if not (-2 ** 25 <= imm26 < 2 ** 25):
        raise ValueError("call out of range")
    return _u32(0x94000000 | (imm26 & 0x03FFFFFF))


def adrp(rd: int, pc: int, target: int) -> bytes:
    imm = ((target >> 12) - (pc >> 12)) & 0x3FFFF
    lo, hi = imm & 0x3, (imm >> 2) & 0x7FFFF
    return _u32(0x90000000 | (hi << 5) | (lo << 29) | rd)


def add_imm(rd: int, rn: int, imm12: int, shift12: bool = False) -> bytes:
    if imm12 >= 1 << 12:
        raise ValueError("add immediate must fit in 12 bits")
    return _u32(0x91000000 | (int(shift12) << 22) | (imm12 << 10) | (rn << 5) | rd)


def _scaled(offset: int, size: int) -> int:
    """LDR/STR unsigned-offset encodings store offset/access-size in bits 21:10."""
    scale = max(size, 1)
    if offset % scale:
        raise ValueError(f"offset {offset} is not {scale}-byte aligned")
    imm12 = offset // scale
    if not 0 <= imm12 <= 4095:
        raise ValueError("unsigned offset out of range (0..4095 scaled)")
    return imm12


def ldr_imm(rd: int, rn: int, offset: int, size: int = 8) -> bytes:
    """Unsigned-offset LDR (immediate). size in bytes: 1,2,4,8."""
    enc = {1: 0x39400000, 2: 0x79400000, 4: 0xB9400000, 8: 0xF9400000}[size]
    return _u32(enc | (_scaled(offset, size) << 10) | (rn << 5) | rd)


def str_imm(rt: int, rn: int, offset: int, size: int = 4) -> bytes:
    enc = {1: 0x39000000, 2: 0x79000000, 4: 0xB9000000, 8: 0xF9000000}[size]
    return _u32(enc | (_scaled(offset, size) << 10) | (rn << 5) | rt)


def jump_abs(target: int, pc: int, scratch: int = X16) -> bytes:
    """Absolute indirect jump: adrp/add/br — reaches the whole 48-bit address space."""
    out = adrp(scratch, pc, target & ~0xFFF)
    out += add_imm(scratch, scratch, target & 0xFFF)
    out += br(scratch)
    return out


# ------------------------------------------------------------------ patch builders


def const_return(value: int, *, width: int = 4, reg: int = X0) -> bytes:
    """`mov <w|x>0, #value ; ret` — the classic "always return N" stub (8-24 bytes)."""
    wide = width >= 8
    body = mov_imm(reg, value, wide=wide)
    return body + ret()


def const_return_size(value: int, *, width: int = 4) -> int:
    """Bytes emitted by const_return(): one MOVZ/MOVK per non-zero 16-bit chunk + RET."""
    v = value & ((1 << 64) - 1)
    chunks = (0, 16, 32, 48) if width >= 8 else (0, 16)
    n = sum(1 for i in chunks if (v >> i) & 0xFFFF)
    return (max(n, 1) + 1) * 4


def nop(n: int = 4) -> bytes:
    return _u32(0xD503201F) * max(1, n // 4)


def trampoline(target: int, where: int) -> bytes:
    """16-byte at-most trampoline placed at `where` jumping to absolute `target`."""
    delta = target - where
    if -BRANCH_RANGE <= delta <= BRANCH_RANGE and delta % 4 == 0:
        ins = b(delta)
        return ins + nop(12)
    return jump_abs(target, where) + nop(4)


def save_restore_prologue(n_saved: int = 2) -> bytes:
    """`stp x29,x30,[sp,#-16]!` style frame, used by patch-in callbacks."""
    out = _u32(0xA9BF7BFD)  # stp fp, lr, [sp, #-16]!
    if n_saved > 2:
        out += _u32(0xA9BE53F3)  # stp x19, x20, [sp, #-32]!
    return out


def read_u32s(blob: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(blob) // 4}I", blob[: len(blob) // 4 * 4]))


def insn_mnemonic(word: int) -> str:
    """Very small decoder, only used for human-readable patch reports."""
    table = (
        (0xFC000000, 0x91000000, "add"),
        (0xFC000000, 0xF8200000, "stp"),
        (0x7FC00000, 0x6B000000, "subs"),
        (0xFC000000, 0xF9400000, "ldr"),
        (0xFC000000, 0xF9000000, "str"),
        (0xFC000000, 0x94000000, "bl"),
        (0xFC000000, 0x14000000, "b"),
        (0xFEFFFFFF, 0xD65F03C0, "ret"),
        (0xFFE0FC1F, 0xD2800000, "movz"),
        (0xFFE0FC1F, 0xF2800000, "movk"),
        (0x9F000000, 0x90000000, "adrp"),
        (0xFFC003E0, 0xF8400400, "ldr"),
        (0x7FE0FC00, 0x0B000000, "add"),
        (0x7FE0FC00, 0x4B000000, "sub"),
        (0x7E200000, 0x36000000, "tbz"),
        (0x7E000000, 0x37000000, "tbnz"),
        (0x7A000000, 0x54000000, "b.cond"),
    )
    for mask, pat, name in table:
        if word & mask == pat:
            return name
    return f".word 0x{word:08x}"


def disasm(blob: bytes, base: int = 0) -> list[str]:
    out = []
    for i, w in enumerate(read_u32s(blob)):
        out.append(f"+0x{i * 0x4:<4x} (0x{base + i * 4:x})  {w:08x}  {insn_mnemonic(w)}")
    return out
