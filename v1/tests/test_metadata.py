"""global-metadata.dat header + table reader (the schema-faithful fallback path)."""

from __future__ import annotations

import struct

import pytest

from modkit.metadata.header import MAGIC, SANITY, SCHEMAS, infer_regions, parse_header
from modkit.metadata.reader import MetadataFile
from modkit.selftest import fixtures


def test_fixture_header_is_recognised(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    info = meta.identify()
    assert info["magic_ok"]
    assert info["version"] == 27
    assert info["unity"] == "2020.3 - 2021.1"
    assert info["typedefs"] == len(fixtures.neon_drift())
    assert info["methods"] == sum(len(c.methods) for c in fixtures.neon_drift())
    assert info["fields"] == sum(len(c.fields) for c in fixtures.neon_drift())


def test_bad_magic_and_bad_sanity_are_rejected():
    with pytest.raises(ValueError, match="bad magic"):
        parse_header(b"not a metadata file........")
    blob = bytearray(fixtures.metadata_blob())
    struct.pack_into("<I", blob, len(MAGIC), 0xDEADBEEF)
    with pytest.raises(ValueError, match="sanity"):
        parse_header(bytes(blob))
    assert struct.unpack_from("<I", fixtures.metadata_blob(), len(MAGIC))[0] == SANITY


def test_truncated_file_raises():
    with pytest.raises(ValueError):
        parse_header(b"\x7fEL")


def test_string_table_and_images(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    names = set(meta.images())
    assert {"Assembly-CSharp.dll", "UnityEngine.dll", "mscorlib.dll"} == names
    assert "PlayerSave" in meta.strings()
    assert meta.string_at(0) == ""        # index 0 is the empty namespace marker


def test_type_and_method_records(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    tds = meta.type_defs()
    mds = meta.method_defs()
    assert len(tds) == len(fixtures.neon_drift())
    assert meta.string_at(tds[0].name_index) == "PlayerSave"
    assert meta.string_at(tds[0].namespace_index) == "NeonDrift.Save"
    first = [m for m in mds if m.declaring_type == 0]
    assert [meta.string_at(m.name_index) for m in first][:3] == [".ctor", "get_Gold", "set_Gold"]
    assert first[2].parameter_count == 1
    assert first[2].access == "public"


def test_string_literals_are_utf16(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    assert "save/v1" in meta.string_literals()


def test_build_program_names_only(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    prog = meta.build_program()
    cls = prog.lookup("NeonDrift.Play.Weapon")
    assert cls is not None, sorted(c.full_name for c in prog.classes)
    assert {m.name for m in cls.methods} >= {"get_Ammo", "set_Ammo", "Fire"}
    assert all(m.rva is None for m in cls.methods)      # RVAs live in the .so, not here


def test_unknown_version_falls_back_to_inference(inputs):
    blob = bytearray(fixtures.metadata_blob())
    struct.pack_into("<I", blob, 16 + 4, 99)             # rewrite the version field
    header = parse_header(bytes(blob))
    assert header.inferred and header.version == 99
    assert header.regions, "inference must still find regions"
    assert len(infer_regions(tuple(range(0, 8)), 4)) == 0


def test_cross_check_flags_a_stale_dump(inputs):
    meta = MetadataFile.open(inputs["metadata"])
    notes = meta.cross_check({"metadata_version": 31, "classes": 3, "methods": 5})
    assert any("v27 but dump.cs claims v31" in n for n in notes)
    assert any("types" in n for n in notes)
    assert meta.cross_check({"metadata_version": 27, "classes": 7, "methods": 30}) == []


def test_all_supported_schemas_have_even_pairs():
    for version, schema in SCHEMAS.items():
        lone = [n for n in schema if n.endswith("Count")]
        assert version >= 23
        assert len(lone) <= 1
