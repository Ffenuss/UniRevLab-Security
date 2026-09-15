import json
import struct
from pathlib import Path

import pytest

from modkit.mobile.il2cpp_crosscheck import parse_metadata, parse_elf, run_crosscheck


def _metadata(path: Path):
    strings = b"SetHealth\x00Other\x00"
    string_offset = 64
    methods_offset = 96
    methods_size = 64  # two v29 Il2CppMethodDefinition rows at 32 bytes each
    blob = bytearray(methods_offset + methods_size)
    struct.pack_into("<Ii", blob, 0, 0xFAB11BAF, 29)
    struct.pack_into("<ii", blob, 24, string_offset, len(strings))
    struct.pack_into("<ii", blob, 48, methods_offset, methods_size)
    blob[string_offset:string_offset + len(strings)] = strings
    struct.pack_into("<I", blob, methods_offset, 0)
    struct.pack_into("<I", blob, methods_offset + 32, len(b"SetHealth\x00"))
    path.write_bytes(blob)


def _elf64(path: Path):
    blob = bytearray(64 + 56)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # ELF64
    blob[5] = 1  # little endian
    blob[6] = 1
    struct.pack_into("<Q", blob, 32, 64)  # e_phoff
    struct.pack_into("<H", blob, 54, 56)  # e_phentsize
    struct.pack_into("<H", blob, 56, 1)   # e_phnum
    # PT_LOAD, PF_R|PF_X, vaddr 0, executable range [0, 0x3000)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0, 0, 0, 0x3000, 0x3000, 0x1000)
    path.write_bytes(blob)


def test_metadata_parser_infers_v29_method_layout(tmp_path):
    path = tmp_path / "global-metadata.dat"
    _metadata(path)
    info, names = parse_metadata(path)
    assert info["sanityHex"] == "0xfab11baf"
    assert info["version"] == 29
    assert info["methodRecordSize"] == 32
    assert info["methodDefinitionCount"] == 2
    assert names == {"SetHealth", "Other"}


def test_elf_parser_records_executable_pt_load(tmp_path):
    path = tmp_path / "libil2cpp.so"
    _elf64(path)
    info = parse_elf(path)
    assert info["class"] == "ELF64"
    assert info["loadSegmentCount"] == 1
    assert info["executableSegmentCount"] == 1
    assert info["segments"][0]["executable"] is True


def test_crosscheck_confirms_structure_but_not_method_to_rva_association(tmp_path):
    metadata = tmp_path / "global-metadata.dat"
    library = tmp_path / "libil2cpp.so"
    methods = tmp_path / "analysis.methods.jsonl"
    output = tmp_path / "il2cpp-crosscheck.json"
    rows = tmp_path / "il2cpp-crosscheck.methods.jsonl"
    _metadata(metadata)
    _elf64(library)
    methods.write_text(
        json.dumps({"id": "m1", "method": "Player::SetHealth(int)", "rva": "0x1234"}) + "\n" +
        json.dumps({"id": "m2", "method": "Player::Missing()", "rva": "0x5000"}) + "\n",
        encoding="utf-8",
    )
    result = run_crosscheck(metadata, library, methods, output, rows)
    assert result["engine"] == "il2cpp.structural-crosscheck-embedded"
    assert result["counts"]["catalogRows"] == 2
    assert result["counts"]["rowsWithRva"] == 2
    assert result["counts"]["structuralBothPresent"] == 1
    assert result["counts"]["unresolved"] == 1
    assert result["confirmsMethodToRvaAssociation"] is False
    assert result["promotesBuildability"] is False
    written = [json.loads(line) for line in rows.read_text(encoding="utf-8").splitlines()]
    assert written[0]["status"] == "STRUCTURAL_BOTH_PRESENT"
    assert written[0]["associationConfirmed"] is False
    assert written[0]["promotesBuildability"] is False


def test_metadata_parser_rejects_wrong_sanity(tmp_path):
    path = tmp_path / "bad-metadata.dat"
    path.write_bytes(b"\x00" * 80)
    with pytest.raises(ValueError, match="sanity"):
        parse_metadata(path)
