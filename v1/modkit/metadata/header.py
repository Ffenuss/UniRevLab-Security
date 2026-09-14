"""global-metadata.dat header layout.

`global-metadata.dat` starts with the 16-byte magic string ``globalmetadata\\0\\0``
followed by ``Il2CppGlobalMetadataHeader``: a sanity value (0xFAB11BAF), the format
version and a long list of ``int32 (offset, size)`` region pairs.

Region order is *not* stable across Unity releases, so this module keeps a small
schema table and additionally exposes a schema-free inference path
(:func:`infer_regions`) used when the version is unknown.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

MAGIC = b"globalmetadata\x00\x00"
SANITY = 0xFAB11BAF
HEADER_PREFIX = "<ii"  # sanity, version

# Regions we actually consume for a menu build; every other pair is skipped.
# Ordered exactly as Il2Cpp writes them.
_V23 = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParametersConstraints", "genericContainer", "fieldsDefaultValuesSizes",
    "typeDefinitions", "typeRefs", "orphanedMonoBehaviourFields",
    "images", "assemblies",
]

_V27 = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters", "constrainedData",
    "genericParametersConstraints", "genericContainer", "typeDefinitions", "typeRefs",
    "orphanedMonoBehaviourFields", "orphanedMonoBehaviourFieldsCount",
    "forwardedTypeDefs", "fieldDefaultValuesData", "images", "assemblies",
]

_V29 = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters", "constrainedData",
    "genericParametersConstraints", "genericContainer", "interfaceGenericConstraints",
    "typeDefinitions", "typeRefs", "orphanedMonoBehaviourFields", "forwardedTypeDefs",
    "fieldDefaultValuesData", "images", "assemblies",
]

# v31 (Unity 2022.3+) inserts the nullable-type table after genericContainer.
_V31 = [s for i, s in enumerate(_V29)]
_i = _V31.index("interfaceGenericConstraints") + 1
_V31[_i:_i] = ["nullableTypes"]

SCHEMAS: dict[int, list[str]] = {23: _V23, 24: _V23, 27: _V27, 29: _V29, 31: _V31}

# sizeof(Il2CppTypeDefinition) / (Il2CppMethodDefinition) / (Il2CppFieldDefinition) /
# (Il2CppStringLiteral) for the versions above.
RECORD_SIZES: dict[tuple[int, str], int] = {
    (27, "typeDefinitions"): 0x58, (29, "typeDefinitions"): 0x58, (31, "typeDefinitions"): 0x58,
    (27, "methods"): 0x20, (29, "methods"): 0x20, (31, "methods"): 0x20,
    (27, "fields"): 0x0C, (29, "fields"): 0x0C, (31, "fields"): 0x0C,
    (27, "stringLiteral"): 0x08, (29, "stringLiteral"): 0x08, (31, "stringLiteral"): 0x08,
    (27, "images"): 0x10, (29, "images"): 0x10, (31, "images"): 0x10,
    (27, "assemblies"): 0x28, (29, "assemblies"): 0x28, (31, "assemblies"): 0x28,
}

UNITY_BY_METADATA = {
    23: "2018.4 / 2019.x",
    24: "2019.4",
    27: "2020.3 - 2021.1",
    29: "2021.2 - 2021.3",
    31: "2022.x - 6000.x",
}


@dataclass(slots=True)
class Region:
    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(slots=True)
class HeaderInfo:
    version: int
    regions: list[Region]
    file_size: int
    inferred: bool = False

    def region(self, name: str) -> Region | None:
        for r in self.regions:
            if r.name == name:
                return r
        return None

    @property
    def unity(self) -> str:
        return UNITY_BY_METADATA.get(self.version, "unknown (dump.cs recommended)")

    def record_count(self, name: str, version: int | None = None) -> int:
        r = self.region(name)
        if r is None:
            return 0
        size = RECORD_SIZES.get((version or self.version, name))
        if size is None:
            for (v, n), s in RECORD_SIZES.items():
                if n == name and v == (version or self.version):
                    size = s
        if not size:
            for (v, n), s in RECORD_SIZES.items():
                if n == name:
                    size = s
                    break
        return r.size // size if size else 0


def parse_header(blob: bytes) -> HeaderInfo:
    """Read the metadata header. Raises ``ValueError`` on a bad file."""
    if len(blob) < 8:
        raise ValueError("global-metadata.dat is truncated (< 8 bytes)")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError(f"bad magic: expected {MAGIC!r}, got {blob[:16]!r}")
    sanity, version = struct.unpack_from(HEADER_PREFIX, blob, len(MAGIC))
    if sanity & 0xFFFFFFFF != SANITY:
        raise ValueError(f"bad sanity value 0x{sanity & 0xFFFFFFFF:08x} (want 0x{SANITY:08x})")

    file_size = len(blob)
    cur = len(MAGIC) + struct.calcsize(HEADER_PREFIX)
    n_ints = (file_size - cur) // 4
    words = struct.unpack_from(f"<{n_ints}i", blob, cur)

    if version in SCHEMAS:
        schema = SCHEMAS[version]
        regions, idx = [], 0
        for name in schema:
            if name.endswith("Count"):        # lone int, not an (offset,size) pair
                idx += 1
                continue
            if idx + 1 >= len(words):
                break
            off, size = words[idx], words[idx + 1]
            idx += 2
            if off < 0 or size < 0 or off + size > file_size:
                continue                       # region not present in this build
            regions.append(Region(name, off, size))
        return HeaderInfo(version, regions, file_size, inferred=False)

    return HeaderInfo(version, infer_regions(words, file_size), file_size, inferred=True)


def infer_regions(words: tuple[int, ...], file_size: int) -> list[Region]:
    """Schema-free region recovery for unknown metadata versions.

    Consecutive ``(offset, size)`` int32 pairs where both look like a valid region
    are collected and labelled by an entropy/shape heuristic; the caller can then
    re-label them (see ``MetadataFile.string_table``).
    """
    regions: list[Region] = []
    i = 0
    while i + 1 < len(words):
        off, size = words[i], words[i + 1]
        if 0 < off < file_size and 0 < size <= file_size - off and size % 4 == 0:
            regions.append(Region(f"region_{i:02d}", off, size))
            i += 2
            continue
        i += 1
    return regions


ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")


def score_string_table(blob: bytes, region: Region) -> float:
    """Ratio of printable-ASCII bytes in a region — high for the string table."""
    chunk = blob[region.offset: region.end]
    if not chunk:
        return 0.0
    printable = sum(1 for b in chunk if 0x20 <= b <= 0x7E or b == 0)
    covered = sum(len(m.group(0)) for m in ASCII_RUN.finditer(chunk))
    return 0.6 * (printable / len(chunk)) + 0.4 * (covered / len(chunk))
