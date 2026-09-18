from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import deobfuscator


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_deobfuscator_profiles_minification_loaders_protection_and_opaque_assets(tmp_path: Path):
    descriptors = b"\n".join(f"Lp{i}/a;".encode() for i in range(48))
    dex = b" ".join([
        b"dex\n035\x00",
        descriptors,
        b"dalvik/system/DexClassLoader",
        b"dalvik/system/InMemoryDexClassLoader",
        b"TracerPid /proc/self/status android/os/Debug isDebuggerConnected",
        b"frida xposed magisk ro.kernel.qemu",
        b"getApkContentsSigners PlayIntegrity play/core/integrity MessageDigest",
    ])
    opaque = bytes(range(256)) * 32
    apk = _apk(tmp_path / "protected.apk", {
        "classes.dex": dex,
        "assets/shell.dex": b"dex secondary payload",
        "assets/protected.dat": opaque,
        "lib/arm64-v8a/libsecneo.so": b"\x7fELF secneo",
    })

    report = deobfuscator.scan_apk_paths([apk])
    kinds = {row["kind"] for row in report["findings"]}
    assert {
        "IDENTIFIER_MINIFICATION_HEURISTIC",
        "PACKER_OR_PROTECTOR_MARKERS",
        "EMBEDDED_CODE_PAYLOAD",
        "DYNAMIC_CODE_LOADING",
        "ANTI_DEBUG_MARKERS",
        "TOOLING_ROOT_EMULATOR_MARKERS",
        "INTEGRITY_SIGNATURE_MARKERS",
        "OPAQUE_HIGH_ENTROPY_ASSETS",
    }.issubset(kinds)

    assert report["descriptorCount"] >= 40
    assert report["suspiciousDescriptorRatio"] >= 0.9
    assert report["normalizedIdentifierCount"] >= 40
    assert all(row["stableAlias"].startswith("StructuralClass_") for row in report["normalizedIdentifiers"])
    assert all(row["semanticRecoveryClaimed"] is False for row in report["normalizedIdentifiers"])
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])
    assert report["policy"]["inventOriginalNames"] is False
    assert report["policy"]["treatEntropyAsEncryptionProof"] is False

    opaque_finding = next(row for row in report["findings"] if row["kind"] == "OPAQUE_HIGH_ENTROPY_ASSETS")
    assert opaque_finding["evidence"]["encryptionConfirmed"] is False
    stages = {row["stage"]: row for row in report["recoveryPlan"]}
    assert stages["identifier-normalization"]["originalNameRecovery"] == "NOT_CLAIMED_WITHOUT_MAPPING"
    assert stages["loader-unwrapping"]["executesTargetCode"] is False


def test_structural_aliases_are_deterministic_and_do_not_invent_semantics(tmp_path: Path):
    descriptors = [f"Lq{i}/a;".encode() for i in range(30)]
    first = _apk(tmp_path / "a.apk", {"classes.dex": b" ".join(descriptors)})
    second = _apk(tmp_path / "b.apk", {"classes.dex": b" ".join(reversed(descriptors))})

    one = deobfuscator.scan_apk_paths([first])
    two = deobfuscator.scan_apk_paths([second])
    aliases_one = {row["originalDescriptor"]: row["stableAlias"] for row in one["normalizedIdentifiers"]}
    aliases_two = {row["originalDescriptor"]: row["stableAlias"] for row in two["normalizedIdentifiers"]}
    assert aliases_one == aliases_two
    assert all("Player" not in alias and "Health" not in alias for alias in aliases_one.values())


def test_normal_descriptors_do_not_trigger_identifier_obfuscation(tmp_path: Path):
    descriptors = b" ".join(
        f"Lcom/example/game/PlayerController{i};".encode() for i in range(32)
    )
    apk = _apk(tmp_path / "normal.apk", {"classes.dex": descriptors})
    report = deobfuscator.scan_apk_paths([apk])
    kinds = {row["kind"] for row in report["findings"]}
    assert "IDENTIFIER_MINIFICATION_HEURISTIC" not in kinds
    assert report["normalizedIdentifierCount"] == 0
    assert report["recoveryPlan"][0]["stage"] == "generic-structure"
