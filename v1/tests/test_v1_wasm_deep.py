from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import wasm_deep


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_wasm_deep_parses_sections_custom_names_and_exports(tmp_path: Path):
    custom = _name("name") + b"\x00"
    types = _uleb(1) + b"\x60\x00\x00"
    functions = _uleb(1) + _uleb(0)
    exports = (
        _uleb(3)
        + _name("getHealth") + b"\x00" + _uleb(0)
        + _name("applyDamage") + b"\x00" + _uleb(0)
        + _name("memory") + b"\x02" + _uleb(0)
    )
    code = _uleb(1) + _uleb(2) + b"\x00\x0b"
    wasm = (
        b"\x00asm\x01\x00\x00\x00"
        + _section(0, custom)
        + _section(1, types)
        + _section(3, functions)
        + _section(7, exports)
        + _section(10, code)
    )
    apk = _apk(tmp_path / "wasm.apk", {"assets/game.wasm": wasm})

    report = wasm_deep.scan_apk_paths([apk])
    assert report["moduleCount"] == 1
    assert report["validModuleCount"] == 1
    assert report["exportCount"] == 3
    assert report["policy"]["executesModules"] is False
    assert report["policy"]["claimsOriginalSource"] is False
    assert report["policy"]["instructionBodiesDisassembled"] is False

    module = report["modules"][0]
    assert module["version"] == 1
    assert module["malformed"] is False
    assert module["customSections"] == ["name"]
    section_names = [row["name"] for row in module["sections"]]
    assert section_names == ["custom", "type", "function", "export", "code"]

    exports_by_name = {row["name"]: row for row in module["exports"]}
    assert exports_by_name["getHealth"]["kind"] == "function"
    assert exports_by_name["applyDamage"]["kind"] == "function"
    assert exports_by_name["memory"]["kind"] == "memory"

    semantic = [row for row in report["findings"] if row["kind"] == "WEBASSEMBLY_EXPORT"]
    health = next(row for row in semantic if row["title"] == "getHealth")
    damage = next(row for row in semantic if row["title"] == "applyDamage")
    assert "health" in health["semanticDomains"]
    assert "damage" in damage["semanticDomains"]
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_invalid_wasm_extension_is_not_promoted_to_valid_module(tmp_path: Path):
    apk = _apk(tmp_path / "bad.apk", {"assets/bad.wasm": b"NOTWASM!"})
    report = wasm_deep.scan_apk_paths([apk])
    assert report["moduleCount"] == 1
    assert report["validModuleCount"] == 0
    assert report["findings"] == []
