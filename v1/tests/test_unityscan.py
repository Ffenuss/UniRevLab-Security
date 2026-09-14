import io
import json
import struct
import zipfile
from pathlib import Path

from modkit.mobile.unityscan import inspect_apk, scan_unityfs


def _c(s: str) -> bytes:
    return s.encode() + b"\0"


def _unityfs(payload: bytes, *, flags: int = 0x200) -> bytes:
    # One uncompressed storage block, one directory node.  Version 8 exercises
    # the 16-byte alignment used by modern UnityFS writers.
    info = bytearray(b"\0" * 16)
    info += struct.pack(">I", 1)
    info += struct.pack(">IIH", len(payload), len(payload), 0)
    info += struct.pack(">I", 1)
    info += struct.pack(">QQI", 0, len(payload), 0)
    info += _c("CAB-test")

    header = bytearray()
    header += _c("UnityFS")
    header += struct.pack(">I", 8)
    header += _c("5.x.x")
    header += _c("2022.3.62f3")
    size_pos = len(header)
    header += b"\0" * 8
    header += struct.pack(">III", len(info), len(info), flags)
    while len(header) % 16:
        header += b"\0"
    out = header + info
    if flags & 0x200:
        while len(out) % 16:
            out += b"\0"
    out += payload
    struct.pack_into(">Q", out, size_pos, len(out))
    return bytes(out)


def test_unityfs_v8_alignment_and_string_scan():
    raw = _unityfs(b"prefix\0Cheat Mode\0Canvas_CheatOverlay\0Developer Console\0")
    result = scan_unityfs(raw)
    assert result["format"] == "UnityFS"
    assert result["format_version"] == 8
    assert result["revision"] == "2022.3.62f3"
    assert result["serialized_files"] == ["CAB-test"]
    joined = "\n".join(result["matched_strings"])
    assert "Cheat Mode" in joined
    assert "Developer Console" in joined


def test_inspect_apk_extracts_il2cpp_inputs(tmp_path: Path):
    apk = tmp_path / "game.apk"
    metadata = b"metadata-fixture"
    library = b"\x7fELFfixture"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata)
        z.writestr("lib/arm64-v8a/libil2cpp.so", library)
    meta_out = tmp_path / "global-metadata.dat"
    so_out = tmp_path / "libil2cpp.so"
    report_out = tmp_path / "unity.json"
    result = inspect_apk(apk, meta_out, so_out, report_out)
    assert meta_out.read_bytes() == metadata
    assert so_out.read_bytes() == library
    assert result["summary"]["catalogs"] == 0
    assert json.loads(report_out.read_text())["schema"] == 1
