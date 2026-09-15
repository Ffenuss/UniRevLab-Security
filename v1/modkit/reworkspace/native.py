"""Native/ELF workspace used by the Android UI and CLI.

The workspace is deliberately file-oriented: it never executes target code.  All
edits are made in memory and are only written to a new file when ``save`` is
called.  This makes it suitable for reviewing a patch before an APK rebuild.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from bisect import bisect_right
import hashlib
from pathlib import Path
import re
import struct
from typing import Any

from modkit.arch import arm64
from modkit.elf.reader import ElfFile

_BL_HIGH_BYTE = re.compile(b"[\x94-\x97]")


@dataclass(slots=True)
class NativeChange:
    rva: int
    file_offset: int
    old_hex: str
    new_hex: str
    source: str
    note: str = ""


def _check_cancel(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise RuntimeError("native scan cancelled")
    if checker is None and callable(cb) and cb():
        raise RuntimeError("native scan cancelled")


def direct_bl_calls(elf: ElfFile, target_rvas: list[int] | set[int] | None = None, *, limit: int = 4000,
                    max_scan_bytes: int = 256 * 1024 * 1024, cb: Any | None = None) -> list[dict]:
    """Bounded static ARM64 direct-call references for an already parsed ELF."""
    if not elf.is_arm64():
        return []
    _check_cancel(cb)
    wanted = {int(x) for x in (target_rvas or []) if int(x) > 0}
    funcs = [s for s in elf.all_symbols(functions_only=True) if s.name and s.value > 0 and s.shndx != 0]
    funcs.sort(key=lambda x: (x.value, x.name))
    starts = [s.value for s in funcs]
    target_names: dict[int, str] = {}
    for sym in funcs:
        target_names.setdefault(sym.value, sym.name)

    def caller_for(rva: int):
        if not starts:
            return None
        i = bisect_right(starts, rva) - 1
        if i < 0:
            return None
        sym = funcs[i]
        if sym.size and rva >= sym.value + sym.size:
            return None
        if not sym.size and i + 1 < len(funcs) and rva >= funcs[i + 1].value:
            return None
        return sym

    out = []
    scanned = 0
    exec_sections = [sec for sec in elf.sections if sec.is_exec and sec.size and sec.type == 1]
    # Stripped Android shared objects can omit the section table entirely.
    # Program headers are loader truth, so fall back to executable PT_LOAD
    # segments instead of silently losing all xref coverage.
    if exec_sections:
        scan_regions = [(sec.addr, sec.offset, sec.size) for sec in exec_sections]
    else:
        scan_regions = [(seg.vaddr, seg.offset, seg.filesz) for seg in elf.segments
                        if seg.is_exec and seg.filesz]
    for region_addr, region_offset, region_size in scan_regions:
        _check_cancel(cb)
        if scanned >= max_scan_bytes:
            break
        take = min(region_size, max_scan_bytes - scanned) & ~3
        raw = memoryview(elf.blob)[region_offset: region_offset + take]
        scanned += len(raw)
        try:
            # BL has bits[31:26] == 0b100101, so in little-endian encoding
            # the fourth byte is in 0x94..0x97.  A memoryview avoids copying a
            # 100+ MiB executable region when the ELF itself is mmap-backed.
            for hit_no, hit in enumerate(_BL_HIGH_BYTE.finditer(raw)):
                if (hit_no & 0x3FF) == 0:
                    _check_cancel(cb)
                rel = hit.start() - 3
                if rel < 0 or (rel & 3):
                    continue
                word = struct.unpack_from('<I', raw, rel)[0]
                if word & 0xFC000000 != 0x94000000:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                call_rva = region_addr + rel
                target = call_rva + (imm26 << 2)
                target_name = target_names.get(target)
                if wanted:
                    if target not in wanted:
                        continue
                elif target_name is None:
                    continue
                caller = caller_for(call_rva)
                out.append({
                    'callRva': call_rva,
                    'fileOffset': region_offset + rel,
                    'sourceRva': caller.value if caller else None,
                    'sourceFunction': caller.name if caller else None,
                    'targetRva': target,
                    'targetFunction': target_name,
                    'kind': 'arm64-direct-bl',
                })
                if len(out) >= max(1, int(limit)):
                    return out
        finally:
            raw.release()
    _check_cancel(cb)
    return out


def arm64_address_xrefs(elf: ElfFile, target_rvas: list[int] | set[int], *, limit: int = 2000,
                        max_scan_bytes: int = 64 * 1024 * 1024, cb: Any | None = None) -> list[dict]:
    """Find conservative ADRP+ADD address materializations for exact target RVAs.

    This recognizes the common compiler sequence used to take the address of a
    string/static object. It does not emulate arbitrary instructions or claim
    runtime data flow.
    """
    if not elf.is_arm64():
        return []
    _check_cancel(cb)
    wanted = {int(x) for x in target_rvas if int(x) > 0}
    if not wanted:
        return []
    funcs = [s for s in elf.all_symbols(functions_only=True) if s.name and s.value > 0 and s.shndx != 0]
    funcs.sort(key=lambda x: (x.value, x.name))
    starts = [s.value for s in funcs]

    def caller_for(rva: int):
        if not starts:
            return None
        i = bisect_right(starts, rva) - 1
        if i < 0:
            return None
        sym = funcs[i]
        if sym.size and rva >= sym.value + sym.size:
            return None
        if not sym.size and i + 1 < len(funcs) and rva >= funcs[i + 1].value:
            return None
        return sym

    out = []
    scanned = 0
    for sec in elf.sections:
        _check_cancel(cb)
        if not sec.is_exec or sec.type != 1 or not sec.size:
            continue
        if scanned >= max_scan_bytes:
            break
        take = min(sec.size, max_scan_bytes - scanned) & ~3
        raw = memoryview(elf.blob)[sec.offset: sec.offset + take]
        scanned += len(raw)
        try:
            # Do not materialize a Python list containing every instruction in
            # a large text section. Decode the ADRP candidate and its tiny ADD
            # look-ahead window directly from the mmap/bytes view.
            for rel in range(0, len(raw), 4):
                if (rel & 0x3FFF) == 0:
                    _check_cancel(cb)
                word = struct.unpack_from('<I', raw, rel)[0]
                if word & 0x9F000000 != 0x90000000:  # ADRP
                    continue
                rd = word & 0x1F
                immlo = (word >> 29) & 0x3
                immhi = (word >> 5) & 0x7FFFF
                imm21 = (immhi << 2) | immlo
                if imm21 & (1 << 20):
                    imm21 -= 1 << 21
                pc = sec.addr + rel
                page = (pc & ~0xFFF) + (imm21 << 12)
                for step in range(1, 5):
                    add_rel = rel + step * 4
                    if add_rel + 4 > len(raw):
                        break
                    w2 = struct.unpack_from('<I', raw, add_rel)[0]
                    if w2 & 0x7F000000 != 0x11000000:
                        continue
                    rn = (w2 >> 5) & 0x1F
                    rd2 = w2 & 0x1F
                    if rn != rd or rd2 != rd:
                        continue
                    imm12 = (w2 >> 10) & 0xFFF
                    shift = 12 if ((w2 >> 22) & 1) else 0
                    target = page + (imm12 << shift)
                    if target not in wanted:
                        continue
                    caller = caller_for(pc)
                    out.append({
                        'xrefRva': pc, 'addRva': sec.addr + add_rel,
                        'fileOffset': sec.offset + rel,
                        'sourceRva': caller.value if caller else None,
                        'sourceFunction': caller.name if caller else None,
                        'targetRva': target, 'register': rd,
                        'kind': 'arm64-adrp-add-xref',
                    })
                    if len(out) >= max(1, int(limit)):
                        return out
                    break
        finally:
            raw.release()
    _check_cancel(cb)
    return out


class NativeWorkspace:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.elf = ElfFile.open(self.path)
        self.original = self.elf.blob
        self.changes: list[NativeChange] = []

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.elf.blob).hexdigest()

    @property
    def original_sha256(self) -> str:
        return hashlib.sha256(self.original).hexdigest()

    def summary(self) -> dict:
        info = self.elf.info()
        info.update({
            "size": len(self.elf.blob),
            "sha256": self.sha256,
            "originalSha256": self.original_sha256,
            "soname": self.elf.soname(),
            "changes": len(self.changes),
        })
        return info

    def sections(self) -> list[dict]:
        out = []
        for s in self.elf.sections:
            flags = "".join(("R", "W" if s.flags & 1 else "-", "X" if s.is_exec else "-"))
            out.append({
                "name": s.name,
                "rva": s.addr,
                "fileOffset": s.offset,
                "size": s.size,
                "flags": flags,
                "type": s.type,
            })
        return out

    def symbols(self, query: str = "", limit: int = 500) -> list[dict]:
        q = query.casefold().strip()
        out = []
        for s in self.elf.symbols():
            if q and q not in s.name.casefold():
                continue
            off = self.elf.rva_to_off(s.value)
            out.append({
                "name": s.name,
                "rva": s.value,
                "fileOffset": off,
                "size": s.size,
                "function": s.is_function,
                "global": s.is_global,
            })
            if len(out) >= limit:
                break
        return out

    def strings(self, query: str = "", *, min_length: int = 5, limit: int = 500) -> list[dict]:
        q = query.casefold()
        rx = re.compile(rb"[\x20-\x7e]{%d,}" % max(2, min_length))
        out = []
        for m in rx.finditer(self.elf.blob):
            text = m.group().decode("utf-8", "replace")
            if q and q not in text.casefold():
                continue
            rva = self.elf.off_to_rva(m.start())
            if rva is None:
                continue
            out.append({"text": text, "rva": rva, "fileOffset": m.start()})
            if len(out) >= limit:
                break
        return out

    def search_hex(self, pattern: str, limit: int = 200) -> list[dict]:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", pattern)
        if not cleaned or len(cleaned) % 2:
            raise ValueError("HEX pattern must contain complete bytes")
        needle = bytes.fromhex(cleaned)
        return [
            {"rva": rva, "fileOffset": self.elf.rva_to_off(rva)}
            for rva in self.elf.search(needle, limit=limit)
        ]

    def hex_page(self, file_offset: int, length: int = 256, width: int = 16) -> list[dict]:
        if file_offset < 0 or length < 0:
            raise ValueError("negative offset/length")
        end = min(len(self.elf.blob), file_offset + min(length, 64 * 1024))
        rows = []
        for off in range(file_offset, end, width):
            chunk = self.elf.blob[off:min(end, off + width)]
            rows.append({
                "fileOffset": off,
                "rva": self.elf.off_to_rva(off),
                "hex": " ".join(f"{b:02X}" for b in chunk),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
            })
        return rows

    def disassemble(self, rva: int, size: int = 128) -> list[dict]:
        if not self.elf.is_arm64():
            raise ValueError("the built-in disassembler currently supports ARM64")
        size = max(4, min(size, 64 * 1024)) & ~3
        blob = self.elf.read_at_rva(rva, size)
        out = []
        for i, word in enumerate(arm64.read_u32s(blob)):
            cur = rva + i * 4
            off = self.elf.rva_to_off(cur)
            out.append({
                "rva": cur,
                "fileOffset": off,
                "bytes": struct.pack("<I", word).hex(" "),
                "asm": arm64.insn_mnemonic(word),
            })
        return out


    def direct_calls(self, target_rvas: list[int] | set[int] | None = None, *, limit: int = 4000, max_scan_bytes: int = 256 * 1024 * 1024) -> list[dict]:
        """Return bounded static ARM64 ``BL`` call references.

        This is a static direct-branch view, not a runtime call trace.
        """
        return direct_bl_calls(self.elf, target_rvas, limit=limit, max_scan_bytes=max_scan_bytes)

    def address_xrefs(self, target_rvas: list[int] | set[int], *, limit: int = 2000, max_scan_bytes: int = 64 * 1024 * 1024) -> list[dict]:
        return arm64_address_xrefs(self.elf, target_rvas, limit=limit, max_scan_bytes=max_scan_bytes)

    def _record(self, rva: int, data: bytes, source: str, note: str = "") -> NativeChange:
        old = self.elf.read_at_rva(rva, len(data))
        off = self.elf.rva_to_off(rva)
        if off is None:
            raise ValueError(f"RVA 0x{rva:x} is not file-backed")
        self.elf.write_at_rva(rva, data)
        change = NativeChange(rva, off, old.hex(), data.hex(), source, note)
        self.changes.append(change)
        return change

    def patch_hex(self, rva: int, data_hex: str, note: str = "") -> dict:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", data_hex)
        if not cleaned or len(cleaned) % 2:
            raise ValueError("HEX edit must contain complete bytes")
        return asdict(self._record(rva, bytes.fromhex(cleaned), "hex", note))

    def patch_asm(self, rva: int, asm: str, note: str = "") -> dict:
        """Small safe assembler for the instructions ModKit already emits.

        Supported: NOP, RET, MOV W0/X0,#imm, B/BL <absolute-rva>.  More complex
        assembly is intentionally left to a future Keystone-backed optional module.
        """
        line = " ".join(asm.strip().replace(",", " ").split())
        upper = line.upper()
        if upper == "NOP":
            data = arm64.nop(4)
        elif upper == "RET":
            data = arm64.ret()
        else:
            m = re.fullmatch(r"MOV\s+(W0|X0)\s+#?(0X[0-9A-F]+|-?\d+)", upper)
            if m:
                value = int(m.group(2), 0)
                data = arm64.mov_imm(0, value, wide=m.group(1) == "X0")
            else:
                m = re.fullmatch(r"(B|BL)\s+(0X[0-9A-F]+|\d+)", upper)
                if not m:
                    raise ValueError("supported ASM: NOP, RET, MOV W0/X0,#imm, B/BL <RVA>")
                target = int(m.group(2), 0)
                delta = target - rva
                data = arm64.bl(delta) if m.group(1) == "BL" else arm64.b(delta)
        return asdict(self._record(rva, data, "asm", note or asm))

    def undo(self) -> dict | None:
        if not self.changes:
            return None
        change = self.changes.pop()
        self.elf.write_at_rva(change.rva, bytes.fromhex(change.old_hex))
        return asdict(change)

    def change_log(self) -> list[dict]:
        return [asdict(c) for c in self.changes]

    def save(self, output: str | Path) -> dict:
        path = Path(output)
        path.write_bytes(self.elf.blob)
        return {"path": str(path), "sha256": self.sha256, "changes": self.change_log()}
