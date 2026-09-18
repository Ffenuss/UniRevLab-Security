from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from modkit.mobile import dotnet_deep


def _metadata_blob() -> bytes:
    valid = (1 << 2) | (1 << 4) | (1 << 6) | (1 << 32)
    tables = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0))
    for count in (2, 3, 4, 1):
        tables += struct.pack("<I", count)

    strings = b"\0PlayerHealth\0TakeDamage\0Assembly-CSharp\0UnityEngine.CoreModule\0"
    user_strings = b"\0"

    streams = [
        ("#~", bytes(tables)),
        ("#Strings", strings),
        ("#US", user_strings),
    ]
    version = b"v4.0.30319\0"
    root = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
    root += version
    while len(root) % 4:
        root += b"\0"
    root += struct.pack("<HH", 0, len(streams))

    directory_size = 0
    for name, _payload in streams:
        name_bytes = name.encode("ascii") + b"\0"
        directory_size += 8 + ((len(name_bytes) + 3) & ~3)
    payload_offset = len(root) + directory_size

    directory = bytearray()
    payloads = bytearray()
    cursor = payload_offset
    for name, payload in streams:
        name_bytes = bytearray(name.encode("ascii") + b"\0")
        while len(name_bytes) % 4:
            name_bytes += b"\0"
        directory += struct.pack("<II", cursor, len(payload))
        directory += name_bytes
        payloads += payload
        cursor += len(payload)
    return b"MZ" + b"\0" * 126 + bytes(root + directory + payloads)


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_dotnet_cli_metadata_recovers_streams_counts_and_semantic_strings(tmp_path: Path):
    apk = _apk(tmp_path / "unity-mono.apk", {
        "assets/bin/Data/Managed/Assembly-CSharp.dll": _metadata_blob(),
    })
    report = dotnet_deep.scan_apk_paths([apk])
    assert report["assemblyCount"] == 1
    assert report["managedAssemblyCount"] == 1
    assert report["policy"]["claimsOriginalSource"] is False
    assert report["policy"]["nativeAotReconstructed"] is False
    assert report["policy"]["cilInstructionsDecoded"] is False

    assembly = report["assemblies"][0]
    assert assembly["flavor"] == "unity-mono"
    assert {"#~", "#Strings", "#US"}.issubset(set(assembly["metadataStreams"]))
    counts = assembly["tableRowCounts"]
    assert counts["TypeDef"] == 2
    assert counts["Field"] == 3
    assert counts["MethodDef"] == 4
    assert counts["Assembly"] == 1

    metadata = next(row for row in report["findings"] if row["kind"] == "DOTNET_MANAGED_METADATA")
    assert "PlayerHealth" in metadata["strings"]
    assert "TakeDamage" in metadata["strings"]
    semantic = [row for row in report["findings"] if row["kind"] == "DOTNET_METADATA_STRING"]
    assert any(row["title"] == "PlayerHealth" and "health" in row["semanticDomains"] for row in semantic)
    assert any(row["title"] == "TakeDamage" and "damage" in row["semanticDomains"] for row in semantic)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_dotnet_opaque_or_native_image_is_reported_without_fake_metadata(tmp_path: Path):
    apk = _apk(tmp_path / "nativeaot.apk", {
        "assemblies/App.dll": b"MZ" + b"\0" * 200,
    })
    report = dotnet_deep.scan_apk_paths([apk])
    assert report["assemblyCount"] == 1
    assert report["managedAssemblyCount"] == 0
    assert report["assemblies"][0]["status"] == "OPAQUE_OR_NATIVE_IMAGE"
    assert report["findings"] == []
