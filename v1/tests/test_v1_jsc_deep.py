from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import jsc_deep


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_jsc_deep_distinguishes_source_bundle_and_binary_bytecode(tmp_path: Path):
    source = b"""
// react-native
function setHealth(value) { return value; }
const applyDamage = (value) => value;
var playerSpeed = (value) => value;
"""
    binary = bytes(range(1, 64)) * 8 + b"\x00PlayerHealth\x00WeaponDamage\x00"
    apk = _apk(tmp_path / "jsc.apk", {
        "assets/index.android.bundle": source,
        "assets/game.jsc": binary,
        "lib/arm64-v8a/libjsc.so": b"\x7fELF",
        "lib/arm64-v8a/libjscexecutor.so": b"\x7fELF",
    })

    report = jsc_deep.scan_apk_paths([apk])
    assert report["artifactCount"] == 2
    assert report["sourceLikeCount"] == 1
    assert report["binaryBytecodeCount"] == 1
    assert report["nativeLibraryCount"] == 2
    assert report["policy"]["claimsSourceFromBinaryJsc"] is False
    assert report["policy"]["versionSpecificBytecodeDecoded"] is False

    artifacts = {row["entry"]: row for row in report["artifacts"]}
    bundle = artifacts["assets/index.android.bundle"]
    compiled = artifacts["assets/game.jsc"]
    assert bundle["representation"] == "javascript-source-or-bundle"
    assert {row["name"] for row in bundle["functions"]} == {
        "setHealth", "applyDamage", "playerSpeed",
    }
    assert compiled["representation"] == "jsc-binary-bytecode"
    assert compiled["functions"] == []

    kinds = {row["kind"] for row in report["findings"]}
    assert "JSC_NATIVE_RUNTIME" in kinds
    assert "JSC_ARTIFACT" in kinds
    assert "JSC_SOURCE_FUNCTION" in kinds
    assert "JSC_SEMANTIC_STRING" in kinds

    semantic_functions = [row for row in report["findings"] if row["kind"] == "JSC_SOURCE_FUNCTION"]
    assert any("health" in row["semanticDomains"] for row in semantic_functions)
    assert any("damage" in row["semanticDomains"] for row in semantic_functions)
    assert any("speed" in row["semanticDomains"] for row in semantic_functions)
    semantic_strings = [row for row in report["findings"] if row["kind"] == "JSC_SEMANTIC_STRING"]
    assert any("health" in row["semanticDomains"] for row in semantic_strings)
    assert any("damage" in row["semanticDomains"] for row in semantic_strings)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_opaque_jsc_never_claims_source_recovery(tmp_path: Path):
    apk = _apk(tmp_path / "opaque.apk", {
        "assets/main.jsc": bytes(range(256)) * 4,
    })
    report = jsc_deep.scan_apk_paths([apk])
    row = report["artifacts"][0]
    assert row["sourceLike"] is False
    assert row["representation"] == "jsc-binary-bytecode"
    assert row["functionCount"] == 0
