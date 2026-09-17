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
    raw_splits = target.get("splits") if isinstance(target.get("splits"), list) else []
    for position, split in enumerate(raw_splits):
        if not isinstance(split, dict):
            rows.append({"index": -1, "name": "", "path": "", "ok": False, "reason": "invalid-split-record"})
            ok = False
            continue
        index, index_valid = _parse_int(split.get("index", -1), -1)
        path = Path(str(split.get("path") or ""))
        expected = str(split.get("sha256") or "")
        row = {"index": index, "name": str(split.get("name") or ""), "path": str(path)}
        if not index_valid or index < 0:
            row.update({"ok": False, "reason": "invalid-index"})
            ok = False
            rows.append(row)
            continue
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
        if not path.is_file():
            row.update({"ok": False, "reason": "missing"})
            ok = False
        else:
            h = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            row.update({"actualSha256": actual, "expectedSha256": expected, "ok": bool(expected and actual == expected)})
            if not row["ok"]:
                row["reason"] = "sha256-mismatch" if expected else "missing-fingerprint"
                ok = False
        rows.append(row)

    scan_complete = target.get("scanCompleteness") == "COMPLETE"
    normalization_errors = target.get("normalizationErrors") if isinstance(target.get("normalizationErrors"), list) else []
    if not scan_complete or normalization_errors:
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
                owner_path = str(owner.get("path") or "")
                owner_sha = str(owner.get("sha256") or "")
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
                        owner_path == str(matched_split.get("path") or "")
                        and bool(owner_sha)
                        and owner_sha == str(matched_split.get("sha256") or "")
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
    fingerprint_ok = bool(expected_fingerprint and actual_fingerprint == expected_fingerprint)
    if not fingerprint_ok:
        ok = False
    return json.dumps({
        "schema": "modkit-package-target-verify-1.1",
        "ok": ok and bool(rows),
        "schemaOk": schema_ok,
        "targetId": target.get("targetId"),
        "scanCompleteness": target.get("scanCompleteness", "PARTIAL"),
        "scanComplete": scan_complete,
        "normalizationErrors": normalization_errors,
        "expectedApkCount": expected_count,
        "copiedApkCount": copied_count,
        "memberCount": len(rows),
        "countOk": count_ok,
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
    """
    target = _load(target_json)
    splits = [x for x in (target.get("splits") or []) if isinstance(x, dict)] if isinstance(target.get("splits"), list) else []
    owner = target.get("patchOwner") if isinstance(target.get("patchOwner"), dict) else None
    blockers: list[str] = []
    if target.get("schema") != SCHEMA:
        blockers.append("invalid-schema")
    if not splits:
        blockers.append("no-splits")
    if target.get("scanCompleteness") != "COMPLETE":
        blockers.append("partial-scan")
    if target.get("normalizationErrors"):
        blockers.append("normalization-errors")
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
    for row in splits:
        idx, idx_valid = _parse_int(row.get("index", -1), -1)
        if not idx_valid or idx < 0:
            blockers.append("invalid-split-index")
            continue
        if idx in seen_indexes:
            blockers.append("duplicate-split-index")
            continue
        seen_indexes.add(idx)
        normalized.append((idx, row))

    if owner is not None and owner_index >= 0 and owner_index not in seen_indexes:
        blockers.append("patch-owner-not-member")

    entries = []
    for idx, row in sorted(normalized, key=lambda pair: pair[0]):
        entries.append({
            "index": idx,
            "name": str(row.get("name") or ""),
            "path": str(row.get("path") or ""),
            "role": "patched-owner" if idx == owner_index else "unchanged-resign",
        })
    blockers = list(dict.fromkeys(blockers))
    return json.dumps({
        "schema": "modkit-package-build-plan-1.0",
        "ready": not blockers,
        "blockers": blockers,
        "mode": "apk-set" if len(entries) > 1 else "single-apk",
        "requiresWholeSetSigning": len(entries) > 1,
        "patchOwnerIndex": owner_index,
        "entries": entries,
    }, ensure_ascii=False, separators=(",", ":"))
