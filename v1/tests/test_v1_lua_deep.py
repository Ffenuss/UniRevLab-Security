from __future__ import annotations

import json
from pathlib import Path
import struct
import zipfile

from modkit.engines import build_default_registry
from modkit.mobile import embedded_pipeline, lua_deep


def _s51(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<Q", len(raw) + 1) + raw + b"\0"


def _s53(value: str) -> bytes:
    raw = value.encode("utf-8")
    assert len(raw) + 1 < 0xFF
    return bytes([len(raw) + 1]) + raw


def _code(op: int, a: int = 0, bx: int = 0) -> bytes:
    return struct.pack("<I", (op & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14))


def _lua51_chunk() -> bytes:
    out = bytearray(b"\x1bLua" + bytes([0x51, 0, 1, 4, 8, 4, 8, 0]))
    out += _s51("@player.lua")
    out += struct.pack("<ii", 1, 7)
    out += bytes([0, 0, 0, 2])
    out += struct.pack("<i", 2) + _code(1) + _code(30)
    out += struct.pack("<i", 1) + bytes([4]) + _s51("health")
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 2) + struct.pack("<ii", 1, 7)
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 0)
    return bytes(out)


def _lua52_chunk() -> bytes:
    out = bytearray(b"\x1bLua" + bytes([0x52, 0, 1, 4, 8, 4, 8, 0]) + b"\x19\x93\r\n\x1a\n")
    out += struct.pack("<ii", 2, 9)
    out += bytes([0, 0, 2])
    out += struct.pack("<i", 2) + _code(1) + _code(31)
    out += struct.pack("<i", 1) + bytes([4]) + _s51("damage")
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 0)
    out += _s51("@combat.lua")
    out += struct.pack("<i", 2) + struct.pack("<ii", 2, 9)
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 0)
    return bytes(out)


def _lua53_chunk() -> bytes:
    out = bytearray(b"\x1bLua" + bytes([0x53, 0]) + b"\x19\x93\r\n\x1a\n")
    out += bytes([4, 8, 4, 8, 8])
    out += struct.pack("<q", 0x5678) + struct.pack("<d", 370.5) + bytes([0])
    out += _s53("@economy.lua")
    out += struct.pack("<ii", 3, 11)
    out += bytes([0, 0, 2])
    out += struct.pack("<i", 2) + _code(1) + _code(38)
    out += struct.pack("<i", 1) + bytes([4]) + _s53("gold")
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 2) + struct.pack("<ii", 3, 11)
    out += struct.pack("<i", 0)
    out += struct.pack("<i", 0)
    return bytes(out)


def test_puc_lua_51_52_53_prototype_and_instruction_recovery():
    for blob, version, domain in (
        (_lua51_chunk(), "5.1", "health"),
        (_lua52_chunk(), "5.2", "damage"),
        (_lua53_chunk(), "5.3", "currency"),
    ):
        report = lua_deep.parse_chunk(blob)
        assert report["status"] == "BYTECODE_DISASSEMBLED"
        assert report["header"]["version"] == version
        assert report["prototypeCount"] == 1
        assert report["instructionCount"] == 2
        proto = report["prototypes"][0]
        assert proto["instructionCount"] == 2
        assert proto["constantCount"] == 1
        assert proto["gameplayDomain"] == domain
        assert proto["instructions"][0]["op"] == "LOADK"
        assert report["trailingBytes"] == 0


def test_xlua_nonstandard_container_stays_opaque(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/xlua/battle.luae", b"XLUAENC\x01\x02health\x00damage\x00")
    report = lua_deep.scan_apk_paths([apk], tmp_path / "lua-deep.json")
    assert report["available"] is True
    assert report["chunkCount"] == 1
    chunk = report["chunks"][0]
    assert chunk["status"] == "OPAQUE_OR_ENCRYPTED"
    assert chunk["recoveryLevel"] == "OPAQUE"
    assert "xLua" in chunk["markers"]
    assert chunk["structuralOnly"] is True


def test_embedded_pipeline_merges_lua_prototypes(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/lua/economy.luac", _lua53_chunk())
    result = embedded_pipeline.run_workspace(tmp_path, tmp_path / "artifact-families.json", tmp_path / "embedded-analysis.json")
    ids = {row.get("engineId") for row in result["runs"]}
    assert lua_deep.ENGINE_ID in ids
    assert result["luaReport"] == "lua-deep.json"
    artifacts = json.loads((tmp_path / "artifact-families.json").read_text(encoding="utf-8"))
    assert artifacts["deepLua"]["available"] is True
    assert any(row.get("kind") == "LUA_PROTOTYPE" and row.get("gameplayDomain") == "currency" for row in artifacts["artifacts"])


def test_lua_bytecode_engine_is_bundled():
    engine = build_default_registry().get("lua.bytecode-embedded")
    assert engine.bundled is True
    assert "puc-lua-5.3" in engine.capabilities
