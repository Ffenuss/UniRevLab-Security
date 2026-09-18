from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from modkit.mobile import native_inventory


def _elf(bits: int, machine: int, e_type: int = 3) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 1 if bits == 32 else 2
    data[5] = 1
    data[6] = 1
    if bits == 32:
        struct.pack_into("<HHIIIIIHHHHHH", data, 16, e_type, machine, 1, 0x1000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
    else:
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, e_type, machine, 1, 0x1000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(data)


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_universal_native_inventory_covers_all_android_abis_and_asset_elf(tmp_path: Path):
    apk = _apk(tmp_path / "all-abis.apk", {
        "lib/arm64-v8a/liba.so": _elf(64, 183),
        "lib/armeabi-v7a/libb.so": _elf(32, 40),
        "lib/x86/libc.so": _elf(32, 3),
        "lib/x86_64/libd.so": _elf(64, 62),
        "assets/execML": _elf(64, 183),
    })
    report = native_inventory.scan_apk_paths([apk])
    assert report["findingCount"] == 5
    assert report["archCounts"] == {
        "aarch64": 2,
        "arm": 1,
        "x86": 1,
        "x86_64": 1,
    }
    rows = {row["entry"]: row for row in report["findings"]}
    assert rows["lib/arm64-v8a/liba.so"]["bits"] == 64
    assert rows["lib/arm64-v8a/liba.so"]["deepAnalysisAvailable"] is True
    assert rows["lib/armeabi-v7a/libb.so"]["bits"] == 32
    assert rows["lib/armeabi-v7a/libb.so"]["deepAnalysisAvailable"] is False
    assert rows["lib/x86/libc.so"]["arch"] == "x86"
    assert rows["lib/x86_64/libd.so"]["arch"] == "x86_64"
    assert rows["assets/execML"]["abi"] == "asset"
    assert all(row["patchReady"] is False for row in rows.values())
    assert all(row["automationExcluded"] is True for row in rows.values())


def test_universal_native_inventory_flags_path_header_abi_mismatch(tmp_path: Path):
    apk = _apk(tmp_path / "mismatch.apk", {
        "lib/arm64-v8a/libwrong.so": _elf(64, 62),
    })
    report = native_inventory.scan_apk_paths([apk])
    row = report["findings"][0]
    assert row["abi"] == "arm64-v8a"
    assert row["arch"] == "x86_64"
    assert row["pathAbiMatchesHeader"] is False
    assert row["deepAnalysisAvailable"] is False
