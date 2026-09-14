from __future__ import annotations

import json
from pathlib import Path
import zipfile

from modkit.elf.reader import ElfFile
from modkit.reworkspace.cache import CorrelationCache
from modkit.reworkspace.correlate import analyze_artifacts, correlate_apk
from modkit.reworkspace.schema import TYPED_CONTRACT
from modkit.selftest import fixtures


def test_typed_contract_keeps_external_re_schema_backward_compatible():
    result = analyze_artifacts({"assets/marker.txt": b"debug console"})
    assert result["schema"] == "modkit-re-1.2"
    assert result["typedContract"] == TYPED_CONTRACT
    assert set(result["inventory"]) == {"dex", "native", "other"}


def test_content_addressed_cache_roundtrip_and_disable(tmp_path, monkeypatch):
    source = tmp_path / "base.apk"
    source.write_bytes(b"same-content")
    cache = CorrelationCache(tmp_path / "cache", max_entries=2, max_bytes=16 * 1024 * 1024)
    key, fps = cache.identity([source])
    assert len(key) == 64 and fps[0].sha256
    cache.store(key, {"schema": "modkit-re-1.2", "findings": []})
    assert cache.load(key)["schema"] == "modkit-re-1.2"
    monkeypatch.setenv("MODKIT_DISABLE_RE_CACHE", "1")
    assert cache.load(key) is None


def test_elf_readonly_mmap_open_and_close(tmp_path):
    path = tmp_path / "libsample.so"
    path.write_bytes(fixtures.so_blob())
    elf = ElfFile.open_mmap(path)
    try:
        assert elf.is_arm64()
        assert "liblog.so" in elf.needed()
    finally:
        elf.close()


def test_large_elf_inside_plain_apk_uses_mapped_streaming_path(tmp_path):
    apk = tmp_path / "large.apk"
    large_so = fixtures.so_blob() + (b"\0" * (8 * 1024 * 1024))
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 128)
        z.writestr("lib/arm64-v8a/libsample.so", large_so)
    result = correlate_apk(apk)
    diag = result["streamingDiagnostics"]
    assert diag["mappedElfArtifacts"] == 1
    assert diag["mappedElfBytes"] == len(large_so)
    assert result["memoryModel"].endswith("mmap-large-elf")


def test_nested_apk_is_streamed_and_rolls_to_disk(tmp_path):
    nested = tmp_path / "base.apk"
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 128)
        z.writestr("assets/padding.bin", b"\0" * (9 * 1024 * 1024))
    outer = tmp_path / "target.apks"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(nested, "base.apk")
    result = correlate_apk(outer)
    diag = result["streamingDiagnostics"]
    assert diag["nestedApksStreamed"] == 1
    assert diag["nestedApksRolledToDisk"] == 1
    assert result["nestedApks"][0]["apk"] == "base.apk"
