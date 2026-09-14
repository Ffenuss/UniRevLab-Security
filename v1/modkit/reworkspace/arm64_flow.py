"""Conservative AArch64 control-flow evidence for IL2CPP static analysis.

Dev24 intentionally distinguishes exact indirect-call resolution from virtual/
interface dispatch *candidates*.  The decoder only recognizes small compiler
shapes whose data flow can be proven from nearby instructions; it does not
emulate target code or claim runtime execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any


@dataclass(slots=True)
class RegValue:
    kind: str
    value: int | None = None
    slot_rva: int | None = None
    base_reg: int | None = None
    offsets: tuple[int, ...] = ()
    source_rva: int | None = None


def _word(blob: bytes | memoryview, off: int) -> int:
    return struct.unpack_from('<I', blob, off)[0]


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def decode_b_target(word: int, pc: int) -> int | None:
    if word & 0xFC000000 not in {0x14000000, 0x94000000}:
        return None
    imm26 = _signed(word & 0x03FFFFFF, 26)
    return int(pc) + (imm26 << 2)


def _read_pointer(elf: Any, rva: int) -> int | None:
    try:
        off = elf.offset(int(rva), 8, False)
        return int(elf.ptr(off) or 0) or None
    except (ValueError, OSError, struct.error, AttributeError):
        return None


def _is_executable_rva(elf: Any, rva: int) -> bool:
    try:
        elf.offset(int(rva), 4, True)
        return True
    except (ValueError, OSError, struct.error):
        return False


def _load_insn(elf: Any, rva: int) -> int | None:
    try:
        off = elf.offset(int(rva), 4, True)
        return int(elf.unpack('<I', off)[0])
    except (ValueError, OSError, struct.error, AttributeError):
        return None


def _step_registers(elf: Any, regs: dict[int, RegValue], word: int, pc: int) -> dict | None:
    """Apply one supported instruction and return an indirect branch record if any."""
    # ADRP Xd, page
    if word & 0x9F000000 == 0x90000000:
        rd = word & 0x1F
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm21 = _signed((immhi << 2) | immlo, 21)
        regs[rd] = RegValue('address', (pc & ~0xFFF) + (imm21 << 12), source_rva=pc)
        return None

    # ADR Xd, label
    if word & 0x9F000000 == 0x10000000:
        rd = word & 0x1F
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm21 = _signed((immhi << 2) | immlo, 21)
        regs[rd] = RegValue('address', pc + imm21, source_rva=pc)
        return None

    # ADD Xd, Xn, #imm12{, LSL #12}; keep only 64-bit ADD (sf=1, op/sub=0, S=0).
    if word & 0xFF000000 == 0x91000000:
        rn, rd = (word >> 5) & 0x1F, word & 0x1F
        base = regs.get(rn)
        if base and base.value is not None:
            imm12 = (word >> 10) & 0xFFF
            shift = 12 if ((word >> 22) & 1) else 0
            regs[rd] = RegValue(base.kind, int(base.value) + (imm12 << shift),
                                slot_rva=base.slot_rva, base_reg=base.base_reg,
                                offsets=base.offsets, source_rva=base.source_rva or pc)
        else:
            regs.pop(rd, None)
        return None

    # MOVZ/MOVK Xd. Useful for compiler-generated absolute thunks in synthetic
    # fixtures and a few hand-written runtimes.
    if word & 0xFF800000 == 0xD2800000:  # MOVZ Xd
        rd = word & 0x1F
        shift = ((word >> 21) & 0x3) * 16
        regs[rd] = RegValue('constant', ((word >> 5) & 0xFFFF) << shift, source_rva=pc)
        return None
    if word & 0xFF800000 == 0xF2800000:  # MOVK Xd
        rd = word & 0x1F
        shift = ((word >> 21) & 0x3) * 16
        old = regs.get(rd)
        if old and old.value is not None:
            mask = 0xFFFF << shift
            value = (int(old.value) & ~mask) | (((word >> 5) & 0xFFFF) << shift)
            regs[rd] = RegValue(old.kind, value, slot_rva=old.slot_rva,
                                base_reg=old.base_reg, offsets=old.offsets,
                                source_rva=old.source_rva or pc)
        else:
            regs.pop(rd, None)
        return None

    # LDR Xt, literal
    if word & 0xFF000000 == 0x58000000:
        rt = word & 0x1F
        imm19 = _signed((word >> 5) & 0x7FFFF, 19)
        slot = pc + (imm19 << 2)
        ptr = _read_pointer(elf, slot)
        if ptr:
            regs[rt] = RegValue('memory-pointer', ptr, slot_rva=slot, source_rva=pc)
        else:
            regs[rt] = RegValue('literal-slot', None, slot_rva=slot, source_rva=pc)
        return None

    # LDR Xt, [Xn,#imm12*8], 64-bit unsigned offset.
    if word & 0xFFC00000 == 0xF9400000:
        rn, rt = (word >> 5) & 0x1F, word & 0x1F
        imm = ((word >> 10) & 0xFFF) * 8
        base = regs.get(rn)
        if base and base.value is not None:
            slot = int(base.value) + imm
            ptr = _read_pointer(elf, slot)
            if ptr:
                regs[rt] = RegValue('memory-pointer', ptr, slot_rva=slot, source_rva=pc)
            else:
                regs[rt] = RegValue('memory-slot', None, slot_rva=slot, source_rva=pc)
        elif rn == 0:
            regs[rt] = RegValue('object-field', None, base_reg=0, offsets=(imm,), source_rva=pc)
        elif base and base.kind in {'object-field', 'virtual-slot'}:
            regs[rt] = RegValue('virtual-slot', None, base_reg=base.base_reg,
                                offsets=tuple(base.offsets) + (imm,), source_rva=pc)
        else:
            regs.pop(rt, None)
        return None

    # BLR Xn
    if word & 0xFFFFFC1F == 0xD63F0000:
        rn = (word >> 5) & 0x1F
        value = regs.get(rn)
        if value and value.value is not None and _is_executable_rva(elf, value.value):
            return {
                'kind': 'arm64-indirect-blr-exact', 'callRva': pc,
                'targetRva': int(value.value), 'register': rn,
                'pointerSlotRva': value.slot_rva,
                'resolutionShape': value.kind,
                'sourceInstructionRva': value.source_rva,
            }
        if value and value.kind in {'object-field', 'virtual-slot'}:
            return {
                'kind': 'arm64-virtual-blr-candidate', 'callRva': pc,
                'targetRva': None, 'register': rn,
                'receiverRegister': value.base_reg,
                'offsetChain': list(value.offsets),
                'vtableSlotOffset': (value.offsets[-1] if len(value.offsets) >= 2 else None),
                'resolutionShape': value.kind,
                'sourceInstructionRva': value.source_rva,
            }
        return {'kind': 'arm64-indirect-blr-unresolved', 'callRva': pc, 'targetRva': None, 'register': rn}

    # BR Xn, useful for tail thunks.
    if word & 0xFFFFFC1F == 0xD61F0000:
        rn = (word >> 5) & 0x1F
        value = regs.get(rn)
        if value and value.value is not None and _is_executable_rva(elf, value.value):
            return {
                'kind': 'arm64-indirect-br-exact', 'branchRva': pc,
                'targetRva': int(value.value), 'register': rn,
                'pointerSlotRva': value.slot_rva,
                'resolutionShape': value.kind,
                'sourceInstructionRva': value.source_rva,
            }
        return None

    return None


def analyze_instruction_window(elf: Any, start_rva: int, raw: bytes | memoryview) -> list[dict]:
    """Resolve exact BLR/BR targets and record unresolved virtual dispatch shapes."""
    regs: dict[int, RegValue] = {}
    out: list[dict] = []
    for rel in range(0, len(raw) - 3, 4):
        pc = int(start_rva) + rel
        word = _word(raw, rel)
        # A direct control-flow transfer ends the simple straight-line dataflow.
        if word & 0xFC000000 in {0x14000000, 0x94000000}:
            if word & 0xFC000000 == 0x94000000:
                # BL preserves callee-saved X19-X29 only. Keep those, clear the
                # volatile register facts to avoid stale BLR attribution.
                regs = {r: v for r, v in regs.items() if 19 <= r <= 29}
                continue
            regs.clear()
            continue
        rec = _step_registers(elf, regs, word, pc)
        if rec:
            out.append(rec)
            if rec['kind'].startswith('arm64-indirect-blr') or rec['kind'].startswith('arm64-virtual'):
                regs = {r: v for r, v in regs.items() if 19 <= r <= 29}
        # RET ends a basic block.
        if word & 0xFFFFFC1F == 0xD65F0000:
            regs.clear()
    return out


def canonicalize_thunk(elf: Any, rva: int, *, max_hops: int = 4, max_bytes: int = 32) -> dict:
    """Follow conservative tail-thunk shapes to a canonical executable RVA."""
    current = int(rva or 0)
    chain = []
    seen = set()
    if current <= 0:
        return {'verified': False, 'canonicalRva': current, 'chain': [], 'reason': 'missing-rva'}
    for _ in range(max(1, int(max_hops))):
        if current in seen:
            return {'verified': False, 'canonicalRva': current, 'chain': chain, 'reason': 'thunk-loop'}
        seen.add(current)
        try:
            off = elf.offset(current, max_bytes, True)
            raw = bytes(elf.b[off:off + max_bytes])
        except (ValueError, OSError):
            return {'verified': bool(chain), 'canonicalRva': current, 'chain': chain,
                    'reason': 'target-not-readable'}
        # Skip NOP/BTI/PAC landing instructions, but only in a tiny prefix.
        wi = 0
        while wi < min(3, len(raw)//4):
            w = _word(raw, wi * 4)
            if w in {0xD503201F, 0xD503245F, 0xD503233F, 0xD503237F}:
                wi += 1
                continue
            break
        if wi >= len(raw)//4:
            break
        pc = current + wi * 4
        first = _word(raw, wi * 4)
        # B target tail thunk.
        if first & 0xFC000000 == 0x14000000:
            target = decode_b_target(first, pc)
            if target and _is_executable_rva(elf, target):
                chain.append({'fromRva': current, 'branchRva': pc, 'toRva': target,
                              'kind': 'arm64-b-thunk'})
                current = int(target)
                continue
        # Straight-line ADRP/ADD/BR or ADRP/LDR/BR or LDR-literal/BR.
        window = raw[wi * 4: min(len(raw), wi * 4 + 20)]
        regs: dict[int, RegValue] = {}
        followed = None
        for rel in range(0, len(window) - 3, 4):
            w = _word(window, rel)
            rec = _step_registers(elf, regs, w, pc + rel)
            if rec and rec.get('kind') == 'arm64-indirect-br-exact':
                followed = int(rec['targetRva'])
                chain.append({'fromRva': current, 'branchRva': rec.get('branchRva'),
                              'toRva': followed, 'kind': 'arm64-br-thunk',
                              'pointerSlotRva': rec.get('pointerSlotRva'),
                              'resolutionShape': rec.get('resolutionShape')})
                break
            # Any call before the BR makes it a real function, not a trivial thunk.
            if w & 0xFC000000 == 0x94000000:
                followed = None
                break
        if followed and _is_executable_rva(elf, followed):
            current = followed
            continue
        break
    return {
        'verified': bool(chain), 'canonicalRva': current, 'chain': chain,
        'hops': len(chain), 'reason': ('canonicalized' if chain else 'not-a-recognized-thunk'),
    }


def method_indirect_calls(elf: Any, method_rva: int, next_rva: int, *, max_bytes: int = 64 * 1024) -> dict:
    """Analyze one exact managed interval for BLR and virtual-dispatch evidence."""
    start = int(method_rva or 0); end = int(next_rva or 0)
    if start <= 0 or end <= start:
        return {'exact': [], 'virtualCandidates': [], 'unresolved': [], 'skipped': 'invalid-interval'}
    span = end - start
    if span > int(max_bytes):
        return {'exact': [], 'virtualCandidates': [], 'unresolved': [], 'skipped': 'interval-over-budget'}
    try:
        off = elf.offset(start, span, True)
        raw = memoryview(elf.b)[off:off + span]
    except ValueError:
        return {'exact': [], 'virtualCandidates': [], 'unresolved': [], 'skipped': 'outside-executable'}
    try:
        records = analyze_instruction_window(elf, start, raw)
    finally:
        raw.release()
    exact, virtual, unresolved = [], [], []
    for rec in records:
        if rec.get('kind') == 'arm64-indirect-blr-exact':
            canon = canonicalize_thunk(elf, rec['targetRva'])
            exact.append({**rec, 'rawTargetRva': rec['targetRva'],
                          'targetRva': canon['canonicalRva'], 'thunk': canon})
        elif rec.get('kind') == 'arm64-virtual-blr-candidate':
            virtual.append(rec)
        elif rec.get('kind') == 'arm64-indirect-blr-unresolved':
            unresolved.append(rec)
    return {'exact': exact, 'virtualCandidates': virtual, 'unresolved': unresolved,
            'scannedBytes': span, 'strategy': 'bounded-managed-interval-register-flow'}


def _segments(elf: Any):
    """Yield (vaddr,file_offset,file_size,flags) for mobile and workspace ELF types."""
    for seg in getattr(elf, 'segments', ()):
        if isinstance(seg, tuple):
            yield int(seg[0]), int(seg[1]), int(seg[2]), int(seg[3])
        else:
            yield int(seg.vaddr), int(seg.offset), int(seg.filesz), int(seg.flags)


def scan_blr_calls(elf: Any, *, target_rva: int | None = None,
                   target_metadata_slot: int | None = None,
                   max_scan_bytes: int = 256 * 1024 * 1024,
                   max_matches: int = 4096, window_instructions: int = 10) -> dict:
    """Scan executable PT_LOAD regions for locally provable BLR call shapes.

    Exact results require a nearby register materialization which resolves to an
    executable pointer. Object/vtable-derived BLR shapes are returned separately
    as candidates and never promoted to an exact target solely by metadata slot.
    """
    import re
    exact, virtual, unresolved = [], [], []
    scanned = 0
    truncated = False
    thunk_cache: dict[int, dict] = {}
    suffix = re.compile(re.escape(b'\x3f\xd6'))
    wanted = int(target_rva or 0)
    for va, off, size, flags in _segments(elf):
        if not (flags & 1) or size < 4 or scanned >= int(max_scan_bytes):
            continue
        take = min(size, int(max_scan_bytes) - scanned) & ~3
        raw = memoryview(elf.b)[off:off + take]
        try:
            for hit in suffix.finditer(raw):
                rel = hit.start() - 2
                if rel < 0 or (rel & 3):
                    continue
                word = _word(raw, rel)
                if word & 0xFFFFFC1F != 0xD63F0000:
                    continue
                begin = max(0, rel - max(1, int(window_instructions)) * 4)
                begin &= ~3
                recs = analyze_instruction_window(elf, va + begin, raw[begin:rel + 4])
                rec = next((x for x in reversed(recs) if int(x.get('callRva', -1)) == va + rel), None)
                if rec is None:
                    rec = {'kind': 'arm64-indirect-blr-unresolved', 'callRva': va + rel,
                           'targetRva': None, 'register': (word >> 5) & 0x1F}
                kind = rec.get('kind')
                if kind == 'arm64-indirect-blr-exact':
                    raw_target = int(rec.get('targetRva') or 0)
                    canon = thunk_cache.get(raw_target)
                    if canon is None:
                        canon = canonicalize_thunk(elf, raw_target)
                        thunk_cache[raw_target] = canon
                    item = {**rec, 'rawTargetRva': raw_target,
                            'targetRva': int(canon.get('canonicalRva') or raw_target),
                            'thunk': canon}
                    if not wanted or item['targetRva'] == wanted:
                        exact.append(item)
                elif kind == 'arm64-virtual-blr-candidate':
                    item = dict(rec)
                    if target_metadata_slot is not None:
                        item['targetMetadataSlot'] = int(target_metadata_slot)
                        item['slotCorrelationStatus'] = 'candidate-only-no-static-receiver-type'
                    virtual.append(item)
                else:
                    unresolved.append(rec)
                if len(exact) + len(virtual) + len(unresolved) >= int(max_matches):
                    truncated = True
                    break
            if truncated:
                break
        finally:
            raw.release()
        scanned += take
    return {
        'exact': exact, 'virtualCandidates': virtual, 'unresolved': unresolved,
        'scannedBytes': scanned, 'truncated': truncated,
        'strategy': 'local-register-flow-around-arm64-blr',
    }


def function_pointer_slots(elf: Any, target_rva: int, *, max_results: int = 256) -> list[dict]:
    """Find exact non-executable pointer slots which contain target/thunk RVA.

    These are data-reference facts useful for vtable/interface correlation. They
    do not by themselves identify which BLR callsite consumes the slot.
    """
    target = int(target_rva or 0)
    if target <= 0:
        return []
    out, seen = [], set()

    def add(slot_rva: int, value: int, source: str):
        key = (int(slot_rva), int(value))
        if key in seen:
            return
        seen.add(key)
        canon = canonicalize_thunk(elf, int(value))
        if int(canon.get('canonicalRva') or value) != target:
            return
        out.append({'slotRva': int(slot_rva), 'storedRva': int(value),
                    'canonicalRva': target, 'source': source,
                    'thunk': canon, 'kind': 'function-pointer-data-slot'})

    # Relocations are the strongest source because the loader will materialize
    # these pointers. Mobile Elf stores fileOffset -> relocated value.
    for off, value in getattr(elf, 'reloc', {}).items():
        if len(out) >= int(max_results):
            break
        try:
            slot_rva = int(elf.virtual(int(off)))
        except (ValueError, AttributeError):
            continue
        flags = None
        for va, _fo, size, fl in _segments(elf):
            if va <= slot_rva < va + size:
                flags = fl; break
        if flags is not None and not (flags & 1):
            add(slot_rva, int(value), 'elf-relocation')

    # Fallback to aligned raw QWORDs in non-executable file-backed PT_LOAD.
    needles = {target}
    for va, off, size, flags in _segments(elf):
        if flags & 1 or size < 8:
            continue
        for needle in tuple(needles):
            packed = struct.pack('<Q', needle)
            pos = int(off)
            end = int(off) + int(size)
            while len(out) < int(max_results):
                pos = elf.b.find(packed, pos, end)
                if pos < 0:
                    break
                rel = pos - int(off)
                if rel % 8 == 0:
                    add(va + rel, needle, 'aligned-qword')
                pos += 8
        if len(out) >= int(max_results):
            break
    out.sort(key=lambda x: (x['slotRva'], x['storedRva']))
    return out[:max_results]


def scan_bl_calls_via_thunk(elf: Any, target_rva: int, *, max_scan_bytes: int = 256 * 1024 * 1024,
                            max_matches: int = 4096, max_unique_targets: int = 65536) -> dict:
    """Find direct BL callsites whose immediate target is a verified tail thunk.

    Immediate BLs to ``target_rva`` are deliberately omitted; callers can merge
    this result with their existing exact direct-call scanner without duplicates.
    """
    import re
    target = int(target_rva or 0)
    if target <= 0:
        return {'calls': [], 'scannedBytes': 0, 'truncated': False, 'thunksChecked': 0}
    high_byte = re.compile(b'[\x94-\x97]')
    cache: dict[int, dict] = {}
    out = []
    scanned = 0
    truncated = False
    for va, off, size, flags in _segments(elf):
        if not (flags & 1) or size < 4 or scanned >= int(max_scan_bytes):
            continue
        take = min(size, int(max_scan_bytes) - scanned) & ~3
        raw = memoryview(elf.b)[off:off + take]
        try:
            for hit in high_byte.finditer(raw):
                rel = hit.start() - 3
                if rel < 0 or (rel & 3):
                    continue
                word = _word(raw, rel)
                if word & 0xFC000000 != 0x94000000:
                    continue
                call_rva = va + rel
                immediate = decode_b_target(word, call_rva)
                if immediate is None or immediate == target or not _is_executable_rva(elf, immediate):
                    continue
                if immediate not in cache:
                    if len(cache) >= int(max_unique_targets):
                        truncated = True
                        break
                    cache[immediate] = canonicalize_thunk(elf, immediate)
                canon = cache[immediate]
                if not canon.get('verified') or int(canon.get('canonicalRva') or 0) != target:
                    continue
                out.append({'callRva': call_rva, 'fileOffset': off + rel,
                            'targetRva': target, 'immediateTargetRva': immediate,
                            'kind': 'arm64-direct-bl-via-thunk', 'thunk': canon})
                if len(out) >= int(max_matches):
                    truncated = True
                    break
            if truncated:
                break
        finally:
            raw.release()
        scanned += take
    return {'calls': out, 'scannedBytes': scanned, 'truncated': truncated,
            'thunksChecked': len(cache), 'strategy': 'direct-bl-plus-tail-thunk-canonicalization'}
