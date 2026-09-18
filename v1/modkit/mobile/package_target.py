from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-package-target-1.1"


def _load(value: str | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _load_list(value: str | list[Any] | None) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _parse_int(value: Any, default: int = 0) -> tuple[int, bool]:
    try:
        if isinstance(value, bool):
            raise ValueError("boolean is not an integer field")
        return int(value), True
    except (TypeError, ValueError, OverflowError):
        return int(default), False


def _safe_int(value: Any, default: int = 0) -> int:
    return _parse_int(value, default)[0]


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text)


def _split_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    value, valid = _parse_int(row.get("index", 0), 0)
    return (0 if valid else 1, value, str(row.get("index") or ""))


def _fingerprint(package_name: str, version_code: int, splits: list[dict[str, Any]]) -> str:
    """Build a deterministic aggregate identity without trusting external numeric types.

    Numeric split metadata is validated by callers.  Fingerprinting itself must never
    raise on malformed external JSON because verification should return ``ok=false``
    rather than crashing the Android caller.
    """
    h = hashlib.sha256()
    h.update(package_name.encode("utf-8", "replace"))
    h.update(b"\0")
    h.update(str(version_code).encode("ascii", "replace"))
    for split in sorted(splits, key=_split_sort_key):
        h.update(b"\0")
        h.update(str(split.get("name") or "").encode("utf-8", "replace"))
        h.update(b"\0")
        h.update(str(split.get("sha256") or "").encode("ascii", "replace"))
    return h.hexdigest()


def build_target_manifest(
    scan_json: str | dict[str, Any],
    package_name: str,
    label: str = "",
    version_name: str | None = None,
    version_code: int | str | None = None,
    expected_apk_count: int | str | None = None,
    copy_errors_json: str | list[Any] | None = None,
) -> str:
    """Normalize Installed Scanner output into the stable package-target contract.

    This contract is deliberately independent from the Android UI. Downstream
    build/preflight code can therefore identify the exact APK which owns
    libil2cpp.so instead of silently falling back to base.apk. Malformed external
    numeric fields are retained only in a fail-closed normalized form and force the
    target to PARTIAL rather than raising into the Android service.
    """
    scan = _load(scan_json)
    copy_errors = _load_list(copy_errors_json)
    normalization_errors: list[str] = []
    splits: list[dict[str, Any]] = []
    for position, row in enumerate(scan.get("splits") or []):
        if not isinstance(row, dict):
            normalization_errors.append(f"split[{position}]:not-object")
            continue
        index, index_ok = _parse_int(row.get("index", len(splits)), -1)
        size, size_ok = _parse_int(row.get("size", 0), -1)
        dex_count, dex_ok = _parse_int(row.get("dexCount", 0), -1)
        native_count, native_ok = _parse_int(row.get("nativeCount", 0), -1)
        if not index_ok or index < 0:
            normalization_errors.append(f"split[{position}]:invalid-index")
            index = -1
        if not size_ok or size < 0:
            normalization_errors.append(f"split[{position}]:invalid-size")
            size = -1
        if not dex_ok or dex_count < 0:
            normalization_errors.append(f"split[{position}]:invalid-dex-count")
            dex_count = -1
        if not native_ok or native_count < 0:
            normalization_errors.append(f"split[{position}]:invalid-native-count")
            native_count = -1
        splits.append({
            "index": index,
            "name": str(row.get("name") or ""),
            "path": str(row.get("path") or ""),
            "size": size,
            "sha256": str(row.get("sha256") or ""),
            "dexCount": dex_count,
            "nativeCount": native_count,
        })

    if expected_apk_count is not None:
        expected, expected_ok = _parse_int(expected_apk_count, -1)
    else:
        expected, expected_ok = len(splits), True
    if not expected_ok or expected <= 0:
        normalization_errors.append("invalid-expected-apk-count")
        expected = -1

    if version_code is not None:
        vcode, vcode_ok = _parse_int(version_code, 0)
    else:
        vcode, vcode_ok = 0, True
    if not vcode_ok or vcode < 0:
        normalization_errors.append("invalid-version-code")
        vcode = 0

    selected = scan.get("selected") if isinstance(scan.get("selected"), dict) else {}
    library = selected.get("library") if isinstance(selected.get("library"), dict) else None
    metadata = selected.get("metadata") if isinstance(selected.get("metadata"), dict) else None
    patch_owner = None
    if library is not None:
        idx, idx_ok = _parse_int(library.get("splitIndex", -1), -1)
        if not idx_ok or idx < 0:
            normalization_errors.append("selected-library:invalid-split-index")
        else:
            owner = next((row for row in splits if row["index"] == idx), None)
            if owner is not None:
                patch_owner = {
                    "kind": "libil2cpp",
                    "splitIndex": idx,
                    "split": owner["name"],
                    "path": owner["path"],
                    "sha256": owner["sha256"],
                    "entry": str(library.get("entry") or ""),
                    "abi": str(library.get("abi") or ""),
                }
            else:
                normalization_errors.append("selected-library:split-not-found")

    complete = (
        bool(splits)
        and expected > 0
        and not copy_errors
        and not normalization_errors
        and len(splits) == expected
    )
    fingerprint = _fingerprint(package_name, vcode, splits)
    manifest = {
        "schema": SCHEMA,
        "packageName": package_name,
        "label": label,
        "versionName": version_name,
        "versionCode": vcode,
        "targetId": fingerprint[:24],
        "fingerprintSha256": fingerprint,
        "scanCompleteness": "COMPLETE" if complete else "PARTIAL",
        "expectedApkCount": expected,
        "copiedApkCount": len(splits),
        "copyErrors": copy_errors,
        "normalizationErrors": normalization_errors,
        "buildMode": "apk-set" if len(splits) > 1 else "single-apk",
        "requiresWholeSetSigning": len(splits) > 1,
        "fullIl2cppPair": bool(scan.get("fullIl2cppPair")),
        "pairConfidence": scan.get("pairConfidence", "NONE"),
        "pairValidation": scan.get("pairValidation") or {},
        "targetProfile": scan.get("targetProfile") or {},
        "applicationDiscoverySummary": ((scan.get("applicationDiscovery") or {}).get("summary") or {}),
        "selected": {"metadata": metadata, "library": library},
        "patchOwner": patch_owner,
        "splits": splits,
    }
    return json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))


def verify_target_manifest(target_json: str | dict[str, Any]) -> str:
    target = _load(target_json)
    rows = []
    schema_ok = target.get("schema") == SCHEMA
    ok = schema_ok
    seen_indexes: set[int] = set()
    seen_paths: set[str] = set()
    seen_names: set[str] = set()
    raw_splits_value = target.get("splits")
    splits_valid = isinstance(raw_splits_value, list)
    raw_splits = raw_splits_value if splits_valid else []
    if not splits_valid:
        ok = False

    for position, split in enumerate(raw_splits):
        if not isinstance(split, dict):
            rows.append({"index": -1, "name": "", "path": "", "ok": False, "reason": "invalid-split-record"})
            ok = False
            continue
        index, index_valid = _parse_int(split.get("index", -1), -1)
        name = str(split.get("name") or "")
        path_text = str(split.get("path") or "")
        expected = str(split.get("sha256") or "")
        row = {"index": index, "name": name, "path": path_text}
        if not index_valid or index < 0:
            row.update({"ok": False, "reason": "invalid-index"})
            ok = False
            rows.append(row)
            continue
        if not name:
            row.update({"ok": False, "reason": "invalid-name"})
            ok = False
            rows.append(row)
            continue
        if name in seen_names:
            row.update({"ok": False, "reason": "duplicate-name"})
            ok = False
            rows.append(row)
            continue
        seen_names.add(name)
        if not path_text:
            row.update({"ok": False, "reason": "invalid-path"})
            ok = False
            rows.append(row)
            continue
        path = Path(path_text)
        canonical = str(path.resolve(strict=False))
        if index in seen_indexes:
            row.update({"ok": False, "reason": "duplicate-or-invalid-index"})
            ok = False
            rows.append(row)
            continue
        seen_indexes.add(index)
        if canonical in seen_paths:
            row.update({"ok": False, "reason": "duplicate-path"})
            ok = False
            rows.append(row)
            continue
        seen_paths.add(canonical)
        if not _is_sha256(expected):
            row.update({"ok": False, "reason": "invalid-fingerprint", "expectedSha256": expected})
            ok = False
        elif not path.is_file():
            row.update({"ok": False, "reason": "missing"})
            ok = False
        else:
            h = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            row.update({"actualSha256": actual, "expectedSha256": expected, "ok": actual == expected})
            if not row["ok"]:
                row["reason"] = "sha256-mismatch"
                ok = False
        rows.append(row)

    scan_complete = target.get("scanCompleteness") == "COMPLETE"
    normalization_raw = target.get("normalizationErrors", [])
    normalization_errors_valid = isinstance(normalization_raw, list)
    normalization_errors = normalization_raw if normalization_errors_valid else []
    copy_errors_raw = target.get("copyErrors", [])
    copy_errors_valid = isinstance(copy_errors_raw, list)
    copy_errors = copy_errors_raw if copy_errors_valid else []
    if not scan_complete or not normalization_errors_valid or normalization_errors or not copy_errors_valid or copy_errors:
        ok = False

    expected_count, expected_valid = _parse_int(target.get("expectedApkCount"), -1)
    copied_count, copied_valid = _parse_int(target.get("copiedApkCount"), -1)
    count_ok = (
        expected_valid and copied_valid
        and expected_count > 0
        and copied_count == expected_count
        and len(rows) == expected_count
    )
    if not count_ok:
        ok = False

    expected_mode = "apk-set" if len(rows) > 1 else "single-apk"
    build_mode_ok = target.get("buildMode") == expected_mode
    expected_whole_set = len(rows) > 1
    signing_flag = target.get("requiresWholeSetSigning")
    signing_mode_ok = isinstance(signing_flag, bool) and signing_flag == expected_whole_set
    if not build_mode_ok or not signing_mode_ok:
        ok = False

    owner = target.get("patchOwner") if isinstance(target.get("patchOwner"), dict) else None
    full_pair = bool(target.get("fullIl2cppPair"))
    owner_ok = True
    if full_pair and owner is None:
        owner_ok = False
        ok = False
    if owner is not None:
        owner_index, owner_index_valid = _parse_int(owner.get("splitIndex", -1), -1)
        if not owner_index_valid or owner_index < 0:
            owner_ok = False
            ok = False
        else:
            owner_row = next((row for row in rows if row.get("index") == owner_index), None)
            owner_ok = bool(owner_row and owner_row.get("ok"))
            if not owner_ok:
                ok = False
            else:
                matched_split = None
                for split in raw_splits:
                    if not isinstance(split, dict):
                        continue
                    split_index, split_index_valid = _parse_int(split.get("index", -1), -1)
                    if split_index_valid and split_index == owner_index:
                        matched_split = split
                        break
                if matched_split is None:
                    owner_ok = False
                else:
                    owner_ok = (
                        str(owner.get("path") or "") == str(matched_split.get("path") or "")
                        and str(owner.get("split") or "") == str(matched_split.get("name") or "")
                        and _is_sha256(owner.get("sha256"))
                        and str(owner.get("sha256") or "") == str(matched_split.get("sha256") or "")
                    )
                if not owner_ok:
                    ok = False

    package_name = str(target.get("packageName") or "")
    version_code, version_code_valid = _parse_int(target.get("versionCode", 0), 0)
    if not version_code_valid or version_code < 0:
        version_code = 0
        ok = False
    split_rows = [x for x in raw_splits if isinstance(x, dict)]
    actual_fingerprint = _fingerprint(package_name, version_code, split_rows)
    expected_fingerprint = str(target.get("fingerprintSha256") or "")
    fingerprint_ok = _is_sha256(expected_fingerprint) and actual_fingerprint == expected_fingerprint
    expected_target_id = actual_fingerprint[:24]
    target_id_ok = str(target.get("targetId") or "") == expected_target_id
    if not fingerprint_ok or not target_id_ok:
        ok = False

    return json.dumps({
        "schema": "modkit-package-target-verify-1.1",
        "ok": ok and bool(rows),
        "schemaOk": schema_ok,
        "splitsValid": splits_valid,
        "targetId": target.get("targetId"),
        "targetIdOk": target_id_ok,
        "scanCompleteness": target.get("scanCompleteness", "PARTIAL"),
        "scanComplete": scan_complete,
        "normalizationErrors": normalization_errors,
        "normalizationErrorsValid": normalization_errors_valid,
        "copyErrors": copy_errors,
        "copyErrorsValid": copy_errors_valid,
        "expectedApkCount": expected_count,
        "copiedApkCount": copied_count,
        "memberCount": len(rows),
        "countOk": count_ok,
        "buildModeOk": build_mode_ok,
        "signingModeOk": signing_mode_ok,
        "fullIl2cppPair": full_pair,
        "patchOwnerOk": owner_ok,
        "fingerprintOk": fingerprint_ok,
        "actualFingerprintSha256": actual_fingerprint,
        "expectedFingerprintSha256": expected_fingerprint,
        "splits": rows,
    }, ensure_ascii=False, separators=(",", ":"))

def build_output_plan(target_json: str | dict[str, Any]) -> str:
    """Return the deterministic APK/APK-set build plan used by Android.

    This makes the owning-split contract independently testable without an
    Android device or signer and keeps PARTIAL or malformed targets fail-closed.
    The plan performs structural checks only; byte re-hashing remains in
    verify_target_manifest so callers do not scan large APK members twice here.
    """
    target = _load(target_json)
    raw_splits_value = target.get("splits")
    raw_splits = raw_splits_value if isinstance(raw_splits_value, list) else []
    splits = [x for x in raw_splits if isinstance(x, dict)]
    owner = target.get("patchOwner") if isinstance(target.get("patchOwner"), dict) else None
    blockers: list[str] = []

    if target.get("schema") != SCHEMA:
        blockers.append("invalid-schema")
    if not isinstance(raw_splits_value, list):
        blockers.append("invalid-splits")
    if len(splits) != len(raw_splits):
        blockers.append("invalid-split-record")
    if not splits:
        blockers.append("no-splits")
    if target.get("scanCompleteness") != "COMPLETE":
        blockers.append("partial-scan")

    normalization_errors = target.get("normalizationErrors", [])
    if not isinstance(normalization_errors, list):
        blockers.append("invalid-normalization-errors")
    elif normalization_errors:
        blockers.append("normalization-errors")
    copy_errors = target.get("copyErrors", [])
    if not isinstance(copy_errors, list):
        blockers.append("invalid-copy-errors")
    elif copy_errors:
        blockers.append("copy-errors")

    expected_count, expected_valid = _parse_int(target.get("expectedApkCount"), -1)
    copied_count, copied_valid = _parse_int(target.get("copiedApkCount"), -1)
    if not expected_valid or expected_count <= 0:
        blockers.append("invalid-expected-apk-count")
    if not copied_valid or copied_count < 0:
        blockers.append("invalid-copied-apk-count")
    if expected_valid and copied_valid and (
        expected_count <= 0 or copied_count != expected_count or len(raw_splits) != expected_count
    ):
        blockers.append("apk-count-mismatch")

    expected_mode = "apk-set" if len(raw_splits) > 1 else "single-apk"
    if target.get("buildMode") != expected_mode:
        blockers.append("build-mode-mismatch")
    expected_whole_set = len(raw_splits) > 1
    signing_flag = target.get("requiresWholeSetSigning")
    if not isinstance(signing_flag, bool) or signing_flag != expected_whole_set:
        blockers.append("signing-mode-mismatch")

    version_code, version_code_valid = _parse_int(target.get("versionCode", 0), 0)
    if not version_code_valid or version_code < 0:
        blockers.append("invalid-version-code")
        version_code = 0
    actual_fingerprint = _fingerprint(
        str(target.get("packageName") or ""),
        version_code,
        splits,
    )
    expected_fingerprint = str(target.get("fingerprintSha256") or "")
    if not _is_sha256(expected_fingerprint) or expected_fingerprint != actual_fingerprint:
        blockers.append("fingerprint-mismatch")
    if str(target.get("targetId") or "") != actual_fingerprint[:24]:
        blockers.append("target-id-mismatch")

    if target.get("fullIl2cppPair") and owner is None:
        blockers.append("missing-patch-owner")

    owner_index = -1
    if owner is not None:
        owner_index, owner_index_valid = _parse_int(owner.get("splitIndex", -1), -1)
        if not owner_index_valid or owner_index < 0:
            blockers.append("invalid-patch-owner-index")
            owner_index = -1

    normalized: list[tuple[int, dict[str, Any]]] = []
    seen_indexes: set[int] = set()
    seen_paths: set[str] = set()
    seen_names: set[str] = set()
    for row in splits:
        idx, idx_valid = _parse_int(row.get("index", -1), -1)
        if not idx_valid or idx < 0:
            blockers.append("invalid-split-index")
            continue
        if idx in seen_indexes:
            blockers.append("duplicate-split-index")
            continue
        seen_indexes.add(idx)

        name = str(row.get("name") or "")
        path = str(row.get("path") or "")
        sha = str(row.get("sha256") or "")
        identity_ok = True
        if not name:
            blockers.append("invalid-split-name")
            identity_ok = False
        elif name in seen_names:
            blockers.append("duplicate-split-name")
            identity_ok = False
        else:
            seen_names.add(name)
        if not path:
            blockers.append("invalid-split-path")
            identity_ok = False
        else:
            canonical = str(Path(path).resolve(strict=False))
            if canonical in seen_paths:
                blockers.append("duplicate-split-path")
                identity_ok = False
            else:
                seen_paths.add(canonical)
        if not _is_sha256(sha):
            blockers.append("invalid-split-sha256")
            identity_ok = False
        if identity_ok:
            normalized.append((idx, row))

    if owner is not None and owner_index >= 0:
        owner_row = next((row for idx, row in normalized if idx == owner_index), None)
        if owner_row is None:
            blockers.append("patch-owner-not-member")
        else:
            if (
                str(owner.get("path") or "") != str(owner_row.get("path") or "")
                or str(owner.get("split") or "") != str(owner_row.get("name") or "")
                or not _is_sha256(owner.get("sha256"))
                or str(owner.get("sha256") or "") != str(owner_row.get("sha256") or "")
            ):
                blockers.append("patch-owner-identity-mismatch")

    entries = []
    for idx, row in sorted(normalized, key=lambda pair: pair[0]):
        entries.append({
            "index": idx,
            "name": str(row.get("name") or ""),
            "path": str(row.get("path") or ""),
            "sha256": str(row.get("sha256") or ""),
            "role": "patched-owner" if idx == owner_index else "unchanged-resign",
        })

    blockers = list(dict.fromkeys(blockers))
    return json.dumps({
        "schema": "modkit-package-build-plan-1.1",
        "ready": not blockers,
        "blockers": blockers,
        "mode": expected_mode,
        "requiresWholeSetSigning": expected_whole_set,
        "patchOwnerIndex": owner_index,
        "actualFingerprintSha256": actual_fingerprint,
        "entries": entries,
    }, ensure_ascii=False, separators=(",", ":"))

