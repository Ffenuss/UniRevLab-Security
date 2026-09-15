import json
import struct
from pathlib import Path

from modkit.mobile.il2cpp_metadata_identity import parse_metadata_identities, build_identity_evidence


def _metadata_with_type(path: Path):
    strings = b"Player\x00Game\x00SetHealth\x00Other\x00"
    string_offset = 192
    methods_offset = 256
    methods_size = 64
    type_offset = 384
    type_size = 88
    blob = bytearray(type_offset + type_size)
    struct.pack_into("<Ii", blob, 0, 0xFAB11BAF, 29)
    struct.pack_into("<ii", blob, 24, string_offset, len(strings))
    struct.pack_into("<ii", blob, 48, methods_offset, methods_size)
    struct.pack_into("<Ii", blob, 160, type_offset, type_size)
    blob[string_offset:string_offset + len(strings)] = strings

    # v29 Il2CppMethodDefinition: nameIndex + declaringType, 32-byte rows.
    struct.pack_into("<Ii", blob, methods_offset, 12, 0)       # SetHealth
    struct.pack_into("<Ii", blob, methods_offset + 32, 22, 0)  # Other

    # v29+ compact Il2CppTypeDefinition (88 bytes): Player in namespace Game.
    struct.pack_into("<II", blob, type_offset, 0, 7)
    struct.pack_into("<i", blob, type_offset + 36, 0)  # methodStart
    struct.pack_into("<H", blob, type_offset + 64, 2)  # method_count
    path.write_bytes(blob)


def test_metadata_identity_parses_declaring_type_and_method_pairs(tmp_path):
    metadata = tmp_path / "metadata.bin"
    _metadata_with_type(metadata)
    parsed = parse_metadata_identities(metadata)
    assert parsed["metadata"]["version"] == 29
    assert parsed["typeLayout"] == "COMPACT_TYPEDEF_88"
    assert parsed["typeDefinitionCount"] == 1
    assert ("Game.Player", "SetHealth") in parsed["qualifiedMethods"]
    assert ("Player", "Other") in parsed["qualifiedMethods"]


def test_no_rva_rows_gain_identity_evidence_but_never_address_or_buildability(tmp_path):
    metadata = tmp_path / "metadata.bin"
    methods = tmp_path / "analysis.methods.jsonl"
    output = tmp_path / "il2cpp-metadata-identity.json"
    rows = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    _metadata_with_type(metadata)
    methods.write_text(
        "\n".join([
            json.dumps({"id": 1, "class": "Game.Player", "method": "SetHealth(int)", "rva": None}),
            json.dumps({"id": 2, "class": "Wrong.Type", "method": "Other()", "rva": 0}),
            json.dumps({"id": 3, "class": "Game.Player", "method": "Missing()"}),
            json.dumps({"id": 4, "class": "Game.Player", "method": "SetHealth(int)", "rva": "0x1234"}),
        ]) + "\n",
        encoding="utf-8",
    )
    result = build_identity_evidence(metadata, methods, output, rows)
    assert result["counts"]["catalogRows"] == 4
    assert result["counts"]["rowsWithoutRva"] == 3
    assert result["counts"]["qualifiedMethodConfirmedNoRva"] == 1
    assert result["counts"]["methodNamePresentNoRva"] == 1
    assert result["counts"]["unresolvedNoRva"] == 1
    assert result["addressResolver"] is False
    assert result["actionable"] is False
    assert result["promotesBuildability"] is False

    evidence = [json.loads(line) for line in rows.read_text(encoding="utf-8").splitlines()]
    by_id = {row["id"]: row for row in evidence}
    assert by_id[1]["status"] == "METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA"
    assert by_id[1]["metadataQualifiedMethodPresent"] is True
    assert by_id[1]["addressConfirmed"] is False
    assert by_id[1]["rva"] is None
    assert by_id[1]["actionable"] is False
    assert by_id[1]["buildable"] is False
    assert by_id[2]["status"] == "METADATA_METHOD_NAME_PRESENT_NO_RVA"
    assert by_id[3]["status"] == "UNRESOLVED_NO_RVA"
    assert 4 not in by_id
