import struct

import pytest

from modkit.mobile import il2cpp_crosscheck as base_crosscheck
from modkit.mobile import il2cpp_crosscheck_cancellable as crosscheck
from modkit.mobile import il2cpp_metadata_identity as base_identity
from modkit.mobile import il2cpp_metadata_identity_cancellable as identity


class _CancelAfter:
    def __init__(self, checks):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0


def _metadata_v31(method_count=1025):
    # Use a count not divisible by 8 so 36*n is not also divisible by the legacy
    # 32-byte candidate. Every MethodDefinition points at the same plausible name.
    record_size = 36
    strings = b"MethodName\0"
    string_offset = 176
    methods_offset = string_offset + len(strings)
    methods_size = record_size * method_count
    blob = bytearray(methods_offset + methods_size)
    struct.pack_into("<I", blob, 0, 0xFAB11BAF)
    struct.pack_into("<i", blob, 4, 31)
    struct.pack_into("<i", blob, 24, string_offset)
    struct.pack_into("<i", blob, 28, len(strings))
    struct.pack_into("<i", blob, 48, methods_offset)
    struct.pack_into("<i", blob, 52, methods_size)
    # Empty but in-bounds type table: identity parser falls back to token indexing.
    struct.pack_into("<I", blob, 160, methods_offset + methods_size)
    struct.pack_into("<i", blob, 164, 0)
    blob[string_offset:string_offset + len(strings)] = strings
    for index in range(method_count):
        pos = methods_offset + index * record_size
        struct.pack_into("<I", blob, pos, 0)  # nameIndex
        struct.pack_into("<i", blob, pos + 4, -1)  # declaringType
        struct.pack_into("<I", blob, pos + 24, 0x06000001 + index)  # token
    return bytes(blob)


def test_cancellable_crosscheck_metadata_parser_matches_base_without_cancel(tmp_path):
    metadata = tmp_path / "metadata.bin"
    metadata.write_bytes(_metadata_v31())

    expected = base_crosscheck.parse_metadata(metadata)
    actual = crosscheck.parse_metadata(metadata)

    assert actual == expected
    assert actual[0]["methodDefinitionCount"] == 1025
    assert "MethodName" in actual[1]


def test_crosscheck_metadata_method_loop_observes_delayed_cancel(tmp_path):
    metadata = tmp_path / "metadata.bin"
    metadata.write_bytes(_metadata_v31(4097))

    with pytest.raises(crosscheck.CrosscheckCancelled):
        crosscheck.parse_metadata(metadata, _CancelAfter(5))


def test_cancellable_identity_structural_parser_matches_base_without_cancel(tmp_path):
    metadata = tmp_path / "metadata.bin"
    metadata.write_bytes(_metadata_v31())

    expected = base_identity.parse_metadata_identities(metadata)
    actual = identity._parse_metadata_identities(metadata, identity._Gate(None))

    assert actual["metadata"] == expected["metadata"]
    assert actual["methodNames"] == expected["methodNames"]
    assert actual["qualifiedMethods"] == expected["qualifiedMethods"]
    assert actual["methodTokens"] == expected["methodTokens"]
    assert actual["typeLayout"] == expected["typeLayout"]


def test_identity_metadata_parser_observes_delayed_cancel(tmp_path):
    metadata = tmp_path / "metadata.bin"
    metadata.write_bytes(_metadata_v31(4097))

    with pytest.raises(identity.MetadataIdentityCancelled):
        identity._parse_metadata_identities(metadata, identity._Gate(_CancelAfter(8)))
