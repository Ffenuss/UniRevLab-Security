import hashlib
import json
from pathlib import Path

from modkit.mobile.package_target import build_output_plan, build_target_manifest, verify_target_manifest


def _split(path: Path, index: int):
    data = path.read_bytes()
    return {"index": index, "name": path.name, "path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "dexCount": 0, "nativeCount": 1}


def test_package_target_uses_library_owning_split_and_requires_whole_set_signing(tmp_path):
    base = tmp_path / "000-base.apk"
    arm64 = tmp_path / "001-split_config.arm64_v8a.apk"
    base.write_bytes(b"base")
    arm64.write_bytes(b"arm64")
    scan = {
        "splits": [_split(base, 0), _split(arm64, 1)],
        "selected": {
            "metadata": {"splitIndex": 0, "split": base.name, "entry": "assets/global-metadata.dat"},
            "library": {"splitIndex": 1, "split": arm64.name, "entry": "lib/arm64-v8a/libil2cpp.so", "abi": "arm64-v8a"},
        },
        "fullIl2cppPair": True,
        "pairConfidence": "HIGH",
    }
    target = json.loads(build_target_manifest(scan, "dev.test", "Test", "1.0", 7, 2, []))
    assert target["buildMode"] == "apk-set"
    assert target["requiresWholeSetSigning"] is True
    assert target["scanCompleteness"] == "COMPLETE"
    assert target["patchOwner"]["splitIndex"] == 1
    assert target["patchOwner"]["path"] == str(arm64)
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is True
    assert verify["countOk"] is True
    assert verify["patchOwnerOk"] is True


def test_package_target_marks_copy_errors_partial_and_detects_tamper(tmp_path):
    base = tmp_path / "000-base.apk"
    base.write_bytes(b"base")
    scan = {"splits": [_split(base, 0)], "selected": {}, "fullIl2cppPair": False}
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=2, copy_errors_json=["split missing"]))
    assert target["scanCompleteness"] == "PARTIAL"
    base.write_bytes(b"changed")
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["scanComplete"] is False
    assert verify["countOk"] is False
    assert verify["splits"][0]["reason"] == "sha256-mismatch"


def test_verify_target_manifest_rejects_partial_even_when_present_members_match(tmp_path):
    base = tmp_path / "000-base.apk"
    base.write_bytes(b"base")
    scan = {"splits": [_split(base, 0)], "selected": {}, "fullIl2cppPair": False}
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=2, copy_errors_json=["missing split"]))
    verify = json.loads(verify_target_manifest(target))
    assert verify["splits"][0]["ok"] is True
    assert verify["ok"] is False
    assert verify["scanComplete"] is False
    assert verify["countOk"] is False


def test_verify_target_manifest_rejects_full_il2cpp_pair_without_patch_owner(tmp_path):
    base = tmp_path / "000-base.apk"
    base.write_bytes(b"base")
    scan = {"splits": [_split(base, 0)], "selected": {}, "fullIl2cppPair": True}
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=1, copy_errors_json=[]))
    assert target["patchOwner"] is None
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["patchOwnerOk"] is False


def test_verify_target_manifest_rejects_owner_path_or_sha_not_bound_to_member(tmp_path):
    base = tmp_path / "000-base.apk"
    arm64 = tmp_path / "001-arm64.apk"
    base.write_bytes(b"base")
    arm64.write_bytes(b"arm64")
    scan = {
        "splits": [_split(base, 0), _split(arm64, 1)],
        "selected": {"library": {"splitIndex": 1, "entry": "lib/arm64-v8a/libil2cpp.so", "abi": "arm64-v8a"}},
        "fullIl2cppPair": True,
    }
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=2, copy_errors_json=[]))
    target["patchOwner"]["path"] = str(base)
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["patchOwnerOk"] is False

    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=2, copy_errors_json=[]))
    target["patchOwner"]["sha256"] = "0" * 64
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["patchOwnerOk"] is False


def test_verify_target_manifest_rejects_duplicate_member_identity(tmp_path):
    base = tmp_path / "000-base.apk"
    other = tmp_path / "001-other.apk"
    base.write_bytes(b"base")
    other.write_bytes(b"other")
    target = json.loads(build_target_manifest({"splits": [_split(base, 0), _split(other, 1)]}, "dev.test", expected_apk_count=2, copy_errors_json=[]))
    target["splits"][1]["index"] = 0
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["splits"][1]["reason"] == "duplicate-or-invalid-index"


def test_build_output_plan_is_fail_closed_and_marks_exact_owner(tmp_path):
    base = tmp_path / "000-base.apk"
    arm = tmp_path / "001-split_config.arm64_v8a.apk"
    base.write_bytes(b"base")
    arm.write_bytes(b"arm")
    scan = {
        "splits": [
            {"index": 0, "name": base.name, "path": str(base), "size": 4, "sha256": hashlib.sha256(base.read_bytes()).hexdigest()},
            {"index": 1, "name": arm.name, "path": str(arm), "size": 3, "sha256": hashlib.sha256(arm.read_bytes()).hexdigest()},
        ],
        "selected": {"library": {"splitIndex": 1, "split": arm.name, "entry": "lib/arm64-v8a/libil2cpp.so", "abi": "arm64-v8a"}},
        "fullIl2cppPair": True,
    }
    target = json.loads(build_target_manifest(scan, "dev.test", "Test", "1", 1, 2, "[]"))
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is True
    assert plan["requiresWholeSetSigning"] is True
    assert [x["role"] for x in plan["entries"]] == ["unchanged-resign", "patched-owner"]
    target["scanCompleteness"] = "PARTIAL"
    blocked = json.loads(build_output_plan(target))
    assert blocked["ready"] is False
    assert "partial-scan" in blocked["blockers"]


def test_build_target_manifest_malformed_numeric_scan_is_partial_not_exception(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    scan = {
        "splits": [{
            "index": "not-an-index",
            "name": base.name,
            "path": str(base),
            "size": "bad-size",
            "sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
            "dexCount": "bad-dex",
            "nativeCount": "bad-native",
        }],
        "selected": {"library": {"splitIndex": "bad-owner"}},
        "fullIl2cppPair": True,
    }
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=1, copy_errors_json=[]))
    assert target["scanCompleteness"] == "PARTIAL"
    assert target["patchOwner"] is None
    assert target["normalizationErrors"]
    assert "split[0]:invalid-index" in target["normalizationErrors"]
    assert "selected-library:invalid-split-index" in target["normalizationErrors"]
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["splits"][0]["reason"] == "invalid-index"


def test_verify_target_manifest_malformed_external_indices_fail_closed(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    target = json.loads(build_target_manifest({"splits": [_split(base, 0)]}, "dev.test", expected_apk_count=1, copy_errors_json=[]))
    target["splits"][0]["index"] = {"hostile": "shape"}
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["splits"][0]["reason"] == "invalid-index"
    assert verify["fingerprintOk"] is True  # fingerprinting stays deterministic and non-throwing


def test_verify_target_manifest_malformed_patch_owner_index_fail_closed(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    scan = {
        "splits": [_split(base, 0)],
        "selected": {"library": {"splitIndex": 0, "entry": "lib/arm64-v8a/libil2cpp.so"}},
        "fullIl2cppPair": True,
    }
    target = json.loads(build_target_manifest(scan, "dev.test", expected_apk_count=1, copy_errors_json=[]))
    target["patchOwner"]["splitIndex"] = [0]
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["patchOwnerOk"] is False


def test_build_output_plan_rejects_malformed_or_duplicate_indexes_without_raising(tmp_path):
    base = tmp_path / "base.apk"
    other = tmp_path / "other.apk"
    base.write_bytes(b"base")
    other.write_bytes(b"other")
    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0), _split(other, 1)]},
        "dev.test", expected_apk_count=2, copy_errors_json=[]))
    target["splits"][0]["index"] = "bad"
    target["splits"][1]["index"] = "bad-too"
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "invalid-split-index" in plan["blockers"]
    assert plan["entries"] == []


def test_verify_target_manifest_invalid_json_returns_fail_closed_report():
    verify = json.loads(verify_target_manifest("{not-json"))
    assert verify["ok"] is False
    assert verify["schemaOk"] is False
    assert verify["countOk"] is False


def test_build_output_plan_rejects_malformed_counts_without_raising(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))

    target["expectedApkCount"] = {"hostile": "shape"}
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "invalid-expected-apk-count" in plan["blockers"]

    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))
    target["copiedApkCount"] = ["1"]
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "invalid-copied-apk-count" in plan["blockers"]


def test_build_output_plan_rejects_duplicate_member_path_and_name(tmp_path):
    base = tmp_path / "base.apk"
    other = tmp_path / "other.apk"
    base.write_bytes(b"base")
    other.write_bytes(b"other")
    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0), _split(other, 1)]},
        "dev.test", expected_apk_count=2, copy_errors_json=[],
    ))

    target["splits"][1]["path"] = target["splits"][0]["path"]
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "duplicate-split-path" in plan["blockers"]

    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0), _split(other, 1)]},
        "dev.test", expected_apk_count=2, copy_errors_json=[],
    ))
    target["splits"][1]["name"] = target["splits"][0]["name"]
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "duplicate-split-name" in plan["blockers"]


def test_build_output_plan_requires_exact_patch_owner_identity(tmp_path):
    base = tmp_path / "base.apk"
    arm = tmp_path / "arm.apk"
    base.write_bytes(b"base")
    arm.write_bytes(b"arm")
    scan = {
        "splits": [_split(base, 0), _split(arm, 1)],
        "selected": {
            "library": {
                "splitIndex": 1,
                "split": arm.name,
                "entry": "lib/arm64-v8a/libil2cpp.so",
                "abi": "arm64-v8a",
            },
        },
        "fullIl2cppPair": True,
    }
    target = json.loads(build_target_manifest(
        scan, "dev.test", expected_apk_count=2, copy_errors_json=[],
    ))
    target["patchOwner"]["path"] = str(base)
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "patch-owner-identity-mismatch" in plan["blockers"]

    target = json.loads(build_target_manifest(
        scan, "dev.test", expected_apk_count=2, copy_errors_json=[],
    ))
    target["patchOwner"]["sha256"] = "0" * 64
    plan = json.loads(build_output_plan(target))
    assert plan["ready"] is False
    assert "patch-owner-identity-mismatch" in plan["blockers"]


def test_verify_target_manifest_rejects_forged_complete_error_state(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))

    target["copyErrors"] = ["split copy failed"]
    target["scanCompleteness"] = "COMPLETE"
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["copyErrors"] == ["split copy failed"]

    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))
    target["normalizationErrors"] = {"unexpected": "object"}
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["normalizationErrorsValid"] is False


def test_verify_target_manifest_rejects_build_mode_and_target_id_drift(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"base")
    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))

    target["buildMode"] = "apk-set"
    target["requiresWholeSetSigning"] = True
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["buildModeOk"] is False
    assert verify["signingModeOk"] is False

    target = json.loads(build_target_manifest(
        {"splits": [_split(base, 0)]},
        "dev.test", expected_apk_count=1, copy_errors_json=[],
    ))
    target["targetId"] = "0" * 24
    verify = json.loads(verify_target_manifest(target))
    assert verify["ok"] is False
    assert verify["targetIdOk"] is False
