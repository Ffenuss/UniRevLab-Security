from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modkit.mobile import lua_deep, lua_deep_cancellable


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0

    def progress(self, _text: str):
        pass


def test_lua_entry_read_checks_cancel_between_chunks(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("assets/lua/main.luac", b"L" * (3 * 1024 * 1024))
    with zipfile.ZipFile(apk) as zf:
        info = zf.getinfo("assets/lua/main.luac")
        with pytest.raises(lua_deep_cancellable.LuaScanCancelled):
            lua_deep_cancellable._read_entry(zf, info, CancelAfter(3))


def test_lua_reader_checks_cancel_during_long_inner_parse_progress():
    reader = lua_deep_cancellable.CancellableReader(b"\0" * (32 * 1024), CancelAfter(2))
    with pytest.raises(lua_deep_cancellable.LuaScanCancelled):
        for _ in range(5000):
            reader.raw(4)


def test_lua_cancel_does_not_publish_partial_report(tmp_path: Path):
    output = tmp_path / "lua-deep.json"
    with pytest.raises(lua_deep_cancellable.LuaScanCancelled):
        lua_deep_cancellable.scan_apk_paths([], output, CancelAfter(1))
    assert not output.exists()


def test_lua_adapter_keeps_canonical_schema_and_embedded_route():
    assert lua_deep_cancellable.SCHEMA == lua_deep.SCHEMA
    assert lua_deep_cancellable.ENGINE_ID == lua_deep.ENGINE_ID
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert 'lua_deep_cancellable.scan_workspace(root, root / "lua-deep.json", cb)' in source
    assert "except lua_deep_cancellable.LuaScanCancelled" in source
