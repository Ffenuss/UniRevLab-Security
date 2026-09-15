from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from modkit.mobile import embedded_pipeline, native_deep
from modkit.reworkspace.native import arm64_address_xrefs, direct_bl_calls


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0

    def progress(self, _text: str):
        pass


class _Section:
    type = 1
    is_exec = True
    size = 0
    addr = 0x1000
    offset = 0


class _Elf:
    def __init__(self, blob: bytes):
        self.blob = blob
        section = _Section()
        section.size = len(blob)
        self.sections = [section]
        self.segments = []

    def is_arm64(self):
        return True

    def all_symbols(self, functions_only=False):
        return []


def test_direct_bl_scan_checks_cancel_inside_scan_loop():
    blob = struct.pack("<I", 0x94000000) * 5000
    with pytest.raises(RuntimeError, match="cancelled"):
        direct_bl_calls(_Elf(blob), max_scan_bytes=len(blob), cb=CancelAfter(3))


def test_address_xref_scan_checks_cancel_inside_instruction_loop():
    blob = b"\x00" * (128 * 1024)
    with pytest.raises(RuntimeError, match="cancelled"):
        arm64_address_xrefs(_Elf(blob), {0x2000}, max_scan_bytes=len(blob), cb=CancelAfter(3))


def test_native_extraction_cancel_removes_partial_file(tmp_path: Path):
    apk = tmp_path / "game.apk"
    payload = b"A" * (3 * 1024 * 1024)
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("lib/arm64-v8a/libgame.so", payload)
    cache = tmp_path / "cache"
    with zipfile.ZipFile(apk) as zf:
        info = zf.getinfo("lib/arm64-v8a/libgame.so")
        with pytest.raises(native_deep.NativeScanCancelled):
            native_deep._extract(zf, info, apk, cache, CancelAfter(3))
    assert not list(cache.glob("*.part"))


def test_native_cancel_does_not_publish_partial_report(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libgame.so", b"not-an-elf")
    output = tmp_path / "native-deep.json"
    with pytest.raises(native_deep.NativeScanCancelled):
        native_deep.scan_apk_paths([apk], tmp_path / "cache", output, CancelAfter(1))
    assert not output.exists()


def test_embedded_pipeline_passes_callback_to_native_backend():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert 'native_deep.scan_workspace(root, root / "native-deep.json", cb)' in source
    assert "except native_deep.NativeScanCancelled" in source
    assert embedded_pipeline.Cancelled is not native_deep.NativeScanCancelled
