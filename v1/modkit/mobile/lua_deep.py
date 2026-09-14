"""Embedded static Lua bytecode recovery for APK assets.

Standard PUC Lua 5.1/5.2/5.3 chunks are parsed without executing target code. The
backend records prototype layout, constants, instructions and debug metadata. Lua
5.4, LuaJIT and non-standard/xLua/SLua containers are identified conservatively
and remain metadata/opaque evidence unless their on-disk format is proven.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-lua-bytecode-1.0"
ENGINE_ID = "lua.bytecode-embedded"
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_CHUNKS = 512
MAX_PROTOS = 20000
MAX_STORED_PROTOS = 1500
MAX_STORED_INSTRUCTIONS = 12000
MAX_STORED_CONSTANTS = 4000
MAX_DEBUG_ROWS = 4000
MAX_COUNT = 4_000_000
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")

_OPS = {
    0x51: (
        "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE","SETGLOBAL",
        "SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","DIV","MOD","POW","UNM",
        "NOT","LEN","CONCAT","JMP","EQ","LT","LE","TEST","TESTSET","CALL","TAILCALL","RETURN",
        "FORLOOP","FORPREP","TFORLOOP","SETLIST","CLOSE","CLOSURE","VARARG",
    ),
    0x52: (
        "MOVE","LOADK","LOADKX","LOADBOOL","LOADNIL","GETUPVAL","GETTABUP","GETTABLE","SETTABUP",
        "SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","DIV","MOD","POW","UNM","NOT",
        "LEN","CONCAT","JMP","EQ","LT","LE","TEST","TESTSET","CALL","TAILCALL","RETURN","FORLOOP",
        "FORPREP","TFORCALL","TFORLOOP","SETLIST","CLOSURE","VARARG","EXTRAARG",
    ),
    0x53: (
        "MOVE","LOADK","LOADKX","LOADBOOL","LOADNIL","GETUPVAL","GETTABUP","GETTABLE","SETTABUP",
        "SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","MOD","POW","DIV","IDIV","BAND",
        "BOR","BXOR","SHL","SHR","UNM","BNOT","NOT","LEN","CONCAT","JMP","EQ","LT","LE","TEST",
        "TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP","TFORCALL","TFORLOOP","SETLIST","CLOSURE",
        "VARARG","EXTRAARG",
    ),
}

_DOMAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("health", ("health", "hitpoint", "hit_point", "hp", "godmode", "immortal")),
    ("damage", ("damage", "dmg", "attack", "defense", "armor", "armour")),
    ("speed", ("movespeed", "move_speed", "attackspeed", "attack_speed", "timescale", "speed")),
    ("cooldown", ("cooldown", "cool_down", "recharge")),
    ("currency", ("currency", "diamond", "gem", "gold", "coin", "wallet", "balance")),
    ("level_xp", ("playerlevel", "player_level", "experience", "level", "xp")),
    ("inventory", ("inventory", "item", "reward", "loot", "drop")),
    ("movement", ("movement", "velocity", "gravity", "teleport", "jump")),
    ("mana_energy", ("mana", "stamina", "energy")),
)


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    installed = root / "installed-apks"
    if installed.is_dir():
        for path in sorted(installed.glob("*.apk")):
            if path not in paths:
                paths.append(path)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _id(apk: str, entry: str, extra: str = "") -> str:
    return hashlib.sha256(f"{apk}!{entry}!lua!{extra}".encode("utf-8", "replace")).hexdigest()[:20]


def _domain(values: Iterable[str]) -> str:
    text = " ".join(str(x) for x in values).casefold()
    compact = re.sub(r"[^a-z0-9_]", "", text)
    tokens = set(re.findall(r"[a-z0-9_]+", text))
    for name, aliases in _DOMAINS:
        for alias in aliases:
            if alias in tokens or alias.replace("_", "") in compact:
                return name
    return ""


def _printable(data: bytes, limit: int = 120) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in PRINTABLE.finditer(data[:8 * 1024 * 1024]):
        text = match.group().decode("utf-8", "replace").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text[:300])
            if len(out) >= limit:
                break
    return out


class ChunkError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.endian = "<"
        self.int_size = 4
        self.size_t = 8
        self.insn_size = 4
        self.integer_size = 8
        self.number_size = 8
        self.version = 0
        self.integral_numbers = False
        self.proto_total = 0
        self.instruction_total = 0
        self.constant_total = 0
        self.debug_total = 0
        self.stored_instructions = 0
        self.stored_constants = 0
        self.stored_debug = 0
        self.protos: list[dict[str, Any]] = []
        self.strings: list[str] = []
        self._string_seen: set[str] = set()

    def need(self, n: int) -> None:
        if n < 0 or self.pos + n > len(self.data):
            raise ChunkError("truncated Lua bytecode")

    def raw(self, n: int) -> bytes:
        self.need(n)
        out = self.data[self.pos:self.pos+n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.raw(1)[0]

    def uint(self, size: int) -> int:
        if size not in (1, 2, 4, 8):
            raise ChunkError(f"unsupported integer width {size}")
        return int.from_bytes(self.raw(size), "little" if self.endian == "<" else "big", signed=False)

    def sint(self, size: int) -> int:
        if size not in (1, 2, 4, 8):
            raise ChunkError(f"unsupported signed integer width {size}")
        return int.from_bytes(self.raw(size), "little" if self.endian == "<" else "big", signed=True)

    def count(self) -> int:
        value = self.sint(self.int_size)
        if value < 0 or value > MAX_COUNT:
            raise ChunkError(f"invalid Lua table count {value}")
        return value

    def number(self) -> int | float:
        raw = self.raw(self.number_size)
        if self.integral_numbers:
            return int.from_bytes(raw, "little" if self.endian == "<" else "big", signed=True)
        if self.number_size == 8:
            return struct.unpack(self.endian + "d", raw)[0]
        if self.number_size == 4:
            return struct.unpack(self.endian + "f", raw)[0]
        raise ChunkError(f"unsupported lua_Number width {self.number_size}")

    def integer(self) -> int:
        return self.sint(self.integer_size)

    def _remember_string(self, text: str) -> str:
        if text and text not in self._string_seen:
            self._string_seen.add(text)
            if len(self.strings) < 1000:
                self.strings.append(text[:500])
        return text

    def string(self) -> str | None:
        if self.version == 0x53:
            first = self.byte()
            if first == 0:
                return None
            size = self.uint(self.size_t) if first == 0xFF else first
            if size < 1 or size > MAX_ENTRY_BYTES:
                raise ChunkError(f"invalid Lua string size {size}")
            raw = self.raw(size - 1)
            return self._remember_string(raw.decode("utf-8", "replace"))
        size = self.uint(self.size_t)
        if size == 0:
            return None
        if size < 1 or size > MAX_ENTRY_BYTES:
            raise ChunkError(f"invalid Lua string size {size}")
        raw = self.raw(size)
        if raw[-1:] != b"\0":
            raise ChunkError("Lua 5.1/5.2 string is not NUL terminated")
        return self._remember_string(raw[:-1].decode("utf-8", "replace"))

    def header(self) -> dict[str, Any]:
        if self.raw(4) != b"\x1bLua":
            raise ChunkError("not a standard PUC Lua chunk")
        self.version = self.byte()
        fmt = self.byte()
        if self.version not in (0x51, 0x52, 0x53):
            raise ChunkError(f"standard Lua 0x{self.version:02x} header is recognized but deep parser supports 5.1-5.3")
        if self.version == 0x51:
            endian_flag = self.byte()
            if endian_flag not in (0, 1):
                raise ChunkError("invalid Lua 5.1 endian marker")
            self.endian = "<" if endian_flag == 1 else ">"
            self.int_size = self.byte(); self.size_t = self.byte(); self.insn_size = self.byte(); self.number_size = self.byte()
            self.integral_numbers = bool(self.byte()); self.integer_size = self.int_size
            if self.insn_size != 4:
                raise ChunkError("unsupported Lua instruction width")
            return {"version":"5.1","format":fmt,"endianness":"little" if self.endian == "<" else "big",
                    "intSize":self.int_size,"sizeT":self.size_t,"instructionSize":self.insn_size,"numberSize":self.number_size,
                    "integralNumbers":self.integral_numbers,"mainUpvalues":None}
        if self.version == 0x52:
            endian_flag = self.byte()
            if endian_flag not in (0, 1):
                raise ChunkError("invalid Lua 5.2 endian marker")
            self.endian = "<" if endian_flag == 1 else ">"
            self.int_size = self.byte(); self.size_t = self.byte(); self.insn_size = self.byte(); self.number_size = self.byte()
            self.integral_numbers = bool(self.byte()); self.integer_size = self.int_size
            if self.raw(6) != b"\x19\x93\r\n\x1a\n":
                raise ChunkError("Lua 5.2 validation tail mismatch")
            if self.insn_size != 4:
                raise ChunkError("unsupported Lua instruction width")
            return {"version":"5.2","format":fmt,"endianness":"little" if self.endian == "<" else "big",
                    "intSize":self.int_size,"sizeT":self.size_t,"instructionSize":self.insn_size,"numberSize":self.number_size,
                    "integralNumbers":self.integral_numbers,"mainUpvalues":None}
        if self.raw(6) != b"\x19\x93\r\n\x1a\n":
            raise ChunkError("Lua 5.3 validation data mismatch")
        self.int_size = self.byte(); self.size_t = self.byte(); self.insn_size = self.byte()
        self.integer_size = self.byte(); self.number_size = self.byte()
        raw_int = self.raw(self.integer_size); raw_num = self.raw(self.number_size)
        matched = None
        for endian in ("<", ">"):
            iv = int.from_bytes(raw_int, "little" if endian == "<" else "big", signed=True)
            try:
                nv = struct.unpack(endian + ("d" if self.number_size == 8 else "f"), raw_num)[0]
            except Exception:
                continue
            if iv == 0x5678 and abs(float(nv) - 370.5) < 0.001:
                matched = endian; break
        if matched is None:
            raise ChunkError("Lua 5.3 numeric format/endian probe failed")
        self.endian = matched
        main_nups = self.byte()
        if self.insn_size != 4:
            raise ChunkError("unsupported Lua instruction width")
        return {"version":"5.3","format":fmt,"endianness":"little" if self.endian == "<" else "big",
                "intSize":self.int_size,"sizeT":self.size_t,"instructionSize":self.insn_size,"integerSize":self.integer_size,
                "numberSize":self.number_size,"mainUpvalues":main_nups}

    def decode_instruction(self, word: int, pc: int) -> dict[str, Any]:
        opcode = word & 0x3F
        names = _OPS.get(self.version, ())
        name = names[opcode] if opcode < len(names) else f"OP_{opcode}"
        a = (word >> 6) & 0xFF; c = (word >> 14) & 0x1FF; b = (word >> 23) & 0x1FF
        bx = (word >> 14) & 0x3FFFF; sbx = bx - 131071; ax = (word >> 6) & 0x3FFFFFF
        return {"pc":pc,"word":f"0x{word:08x}","op":name,"A":a,"B":b,"C":c,"Bx":bx,"sBx":sbx,"Ax":ax}

    def constant(self) -> dict[str, Any]:
        tag = self.byte()
        if tag == 0:
            return {"type":"nil","value":None}
        if tag == 1:
            return {"type":"boolean","value":bool(self.byte())}
        if tag == 3:
            return {"type":"number","value":self.number()}
        if self.version == 0x53 and tag == 19:
            return {"type":"integer","value":self.integer()}
        if tag in (4, 20):
            return {"type":"string","value":self.string() or ""}
        raise ChunkError(f"unsupported Lua constant tag {tag}")

    def _debug(self, include_source: bool) -> tuple[str | None, list[int], list[dict[str, Any]], list[str]]:
        source = self.string() if include_source else None
        line_count = self.count(); line_info: list[int] = []
        for _ in range(line_count):
            value = self.sint(self.int_size); self.debug_total += 1
            if self.stored_debug < MAX_DEBUG_ROWS and len(line_info) < 512:
                line_info.append(value); self.stored_debug += 1
        local_count = self.count(); locals_rows: list[dict[str, Any]] = []
        for _ in range(local_count):
            name = self.string() or ""; start_pc = self.sint(self.int_size); end_pc = self.sint(self.int_size)
            self.debug_total += 1
            if self.stored_debug < MAX_DEBUG_ROWS and len(locals_rows) < 256:
                locals_rows.append({"name":name,"startPc":start_pc,"endPc":end_pc}); self.stored_debug += 1
        upname_count = self.count(); upvalue_names: list[str] = []
        for _ in range(upname_count):
            value = self.string() or ""; self.debug_total += 1
            if self.stored_debug < MAX_DEBUG_ROWS and len(upvalue_names) < 256:
                upvalue_names.append(value); self.stored_debug += 1
        return source, line_info, locals_rows, upvalue_names

    def prototype(self, parent_source: str | None, path: str, depth: int = 0) -> None:
        if depth > 64:
            raise ChunkError("Lua prototype nesting is too deep")
        self.proto_total += 1
        if self.proto_total > MAX_PROTOS:
            raise ChunkError("Lua prototype count exceeds safety limit")
        start = self.pos
        source = self.string() or parent_source if self.version in (0x51, 0x53) else None
        line_defined = self.sint(self.int_size); last_line = self.sint(self.int_size)
        declared_nups = self.byte() if self.version == 0x51 else None
        params = self.byte(); vararg = self.byte(); max_stack = self.byte()

        code_count = self.count(); self.instruction_total += code_count
        instructions: list[dict[str, Any]] = []; op_hist: dict[str, int] = {}
        for pc in range(code_count):
            decoded = self.decode_instruction(self.uint(self.insn_size), pc)
            op_hist[decoded["op"]] = op_hist.get(decoded["op"], 0) + 1
            if self.stored_instructions < MAX_STORED_INSTRUCTIONS and len(instructions) < 512:
                instructions.append(decoded); self.stored_instructions += 1

        const_count = self.count(); self.constant_total += const_count
        constants: list[dict[str, Any]] = []; semantic_values: list[str] = []
        for _ in range(const_count):
            item = self.constant()
            if item.get("type") == "string":
                semantic_values.append(str(item.get("value") or ""))
            if self.stored_constants < MAX_STORED_CONSTANTS and len(constants) < 256:
                constants.append(item); self.stored_constants += 1

        proto_count = 0; upvalues: list[dict[str, int]] = []
        if self.version == 0x51:
            proto_count = self.count()
            for i in range(proto_count):
                self.prototype(source, f"{path}.{i}", depth + 1)
            debug_source, line_info, locals_rows, upvalue_names = self._debug(False)
        elif self.version == 0x52:
            proto_count = self.count()
            for i in range(proto_count):
                self.prototype(None, f"{path}.{i}", depth + 1)
            up_count = self.count(); declared_nups = up_count
            for _ in range(up_count):
                instack, idx = self.byte(), self.byte()
                if len(upvalues) < 256:
                    upvalues.append({"inStack":instack,"index":idx})
            debug_source, line_info, locals_rows, upvalue_names = self._debug(True)
            source = debug_source
        else:
            up_count = self.count(); declared_nups = up_count
            for _ in range(up_count):
                instack, idx = self.byte(), self.byte()
                if len(upvalues) < 256:
                    upvalues.append({"inStack":instack,"index":idx})
            proto_count = self.count()
            for i in range(proto_count):
                self.prototype(source, f"{path}.{i}", depth + 1)
            debug_source, line_info, locals_rows, upvalue_names = self._debug(False)

        semantic_values.append(source or "")
        if len(self.protos) < MAX_STORED_PROTOS:
            self.protos.append({
                "path":path,"byteOffset":start,"source":source,"lineDefined":line_defined,"lastLineDefined":last_line,
                "parameters":params,"vararg":bool(vararg),"maxStack":max_stack,"upvalueCount":int(declared_nups or 0),
                "upvalues":upvalues,"childPrototypeCount":proto_count,"instructionCount":code_count,
                "instructions":instructions,"instructionTruncated":len(instructions) < code_count,"opcodeHistogram":op_hist,
                "constantCount":const_count,"constants":constants,"constantsTruncated":len(constants) < const_count,
                "lineInfoCount":len(line_info),"lineInfo":line_info,"localsCount":len(locals_rows),"locals":locals_rows,
                "upvalueNames":upvalue_names,"gameplayDomain":_domain(semantic_values),
            })


def parse_chunk(data: bytes) -> dict[str, Any]:
    reader = Reader(data); header = reader.header(); reader.prototype(None, "0")
    return {
        "status":"BYTECODE_DISASSEMBLED","recoveryLevel":"DISASSEMBLED_METADATA","header":header,
        "prototypeCount":reader.proto_total,"storedPrototypeCount":len(reader.protos),"instructionCount":reader.instruction_total,
        "constantCount":reader.constant_total,"debugRecordCount":reader.debug_total,"strings":reader.strings,
        "prototypes":reader.protos,"trailingBytes":len(data)-reader.pos,
        "truncated":len(reader.protos) < reader.proto_total or reader.stored_instructions < reader.instruction_total or reader.stored_constants < reader.constant_total,
    }


def _candidate(name: str, data: bytes) -> bool:
    low = name.casefold()
    if data.startswith((b"\x1bLua", b"\x1bLJ")):
        return True
    if low.endswith((".luac", ".luae")):
        return True
    if low.endswith(".lua"):
        return data.startswith(b"\x1b")
    return low.endswith((".bytes", ".bin", ".dat")) and ("/lua/" in "/" + low or "xlua" in low or "slua" in low)


def _opaque_report(data: bytes, entry: str) -> dict[str, Any]:
    low = entry.casefold(); markers: list[str] = []
    if "xlua" in low or b"xlua" in data[:1024].lower(): markers.append("xLua")
    if "slua" in low or b"slua" in data[:1024].lower(): markers.append("SLua")
    if data.startswith(b"\x1bLJ"):
        version = data[3] if len(data) > 3 else 0
        return {"status":"LUAJIT_HEADER_ONLY","recoveryLevel":"DISASSEMBLED_METADATA","runtime":"LuaJIT",
                "bytecodeVersion":version,"markers":markers+["luajit"],"strings":_printable(data),"structuralOnly":True}
    if data.startswith(b"\x1bLua") and len(data) > 4 and data[4] == 0x54:
        return {"status":"STANDARD_5_4_HEADER_ONLY","recoveryLevel":"DISASSEMBLED_METADATA","runtime":"Lua 5.4",
                "markers":markers+["lua-bytecode-5.4"],"strings":_printable(data),"structuralOnly":True,
                "blocker":"Lua 5.4 variable-length prototype layout is not promoted to decoded instructions by this parser"}
    return {"status":"OPAQUE_OR_ENCRYPTED","recoveryLevel":"OPAQUE","runtime":"Lua-compatible container",
            "markers":markers,"strings":_printable(data),"structuralOnly":True,
            "blocker":"No validated standard Lua bytecode header; encrypted/custom xLua/SLua containers are not guessed"}


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []; findings: list[dict[str, Any]] = []; errors: list[dict[str, str]] = []; apk_count = 0
    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    if len(chunks) >= MAX_CHUNKS:
                        break
                    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES:
                        continue
                    low = info.filename.casefold()
                    likely = low.endswith((".luac", ".luae", ".lua")) or "xlua" in low or "slua" in low or "/lua/" in "/" + low
                    if not likely:
                        continue
                    try:
                        data = zf.read(info)
                    except Exception as exc:
                        errors.append({"apk":apk.name,"entry":info.filename,"error":str(exc)}); continue
                    if not _candidate(info.filename, data):
                        continue
                    base = {"apk":apk.name,"entry":info.filename,"size":info.file_size}
                    try:
                        detail = parse_chunk(data) if data.startswith(b"\x1bLua") and len(data) > 4 and data[4] in (0x51,0x52,0x53) else _opaque_report(data, info.filename)
                    except Exception as exc:
                        detail = _opaque_report(data, info.filename); detail["status"] = "BYTECODE_PARSE_FAILED"; detail["parseError"] = str(exc)
                    row = {**base, **detail}; chunks.append(row)
                    findings.append({
                        "id":"lua-chunk:"+_id(apk.name,info.filename),"kind":"LUA_BYTECODE","title":f"Lua bytecode: {Path(info.filename).name}",
                        "category":"Runtime/Lua","status":row.get("status"),"family":"lua","engineId":ENGINE_ID,"apk":apk.name,
                        "entry":info.filename,"recoveryLevel":row.get("recoveryLevel"),"prototypeCount":int(row.get("prototypeCount") or 0),
                        "instructionCount":int(row.get("instructionCount") or 0),"markers":row.get("markers") or [],"strings":row.get("strings") or [],
                        "ownershipKind":"APP_OR_GAME","trustBoundary":"local","patchReady":False,"structuralOnly":True,
                        "evidenceRole":"embedded-lua-bytecode",
                    })
                    for proto in row.get("prototypes", [])[:500] if isinstance(row.get("prototypes"), list) else []:
                        source = str(proto.get("source") or Path(info.filename).name)
                        label = f"{source}:{proto.get('lineDefined',0)} [{proto.get('path')}]"; domain = str(proto.get("gameplayDomain") or "")
                        findings.append({
                            "id":"lua-proto:"+_id(apk.name,info.filename,str(proto.get("path"))),"kind":"LUA_PROTOTYPE","title":label,
                            "category":"Gameplay/Lua" if domain else "Runtime/Lua","status":"BYTECODE_STRUCTURAL","family":"lua","engineId":ENGINE_ID,
                            "apk":apk.name,"entry":info.filename,"prototypePath":proto.get("path"),"byteOffset":proto.get("byteOffset"),"source":source,
                            "lineDefined":proto.get("lineDefined"),"lastLineDefined":proto.get("lastLineDefined"),"instructionCount":proto.get("instructionCount"),
                            "constantCount":proto.get("constantCount"),"opcodeHistogram":proto.get("opcodeHistogram") or {},"gameplayDomain":domain,
                            "ownershipKind":"APP_OR_GAME","trustBoundary":"local","patchReady":False,"structuralOnly":True,
                            "evidenceRole":"embedded-lua-prototype",
                        })
        except Exception as exc:
            errors.append({"apk":apk.name,"error":str(exc)})
    out = {
        "schema":SCHEMA,"engineId":ENGINE_ID,"bundled":True,"manualImportRequired":False,"passive":True,"executesTargetCode":False,
        "available":bool(chunks),"apkCount":apk_count,"chunkCount":len(chunks),"findingCount":len(findings),"chunks":chunks,"findings":findings,
        "errors":errors[:100],"truncated":len(chunks)>=MAX_CHUNKS,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path)
