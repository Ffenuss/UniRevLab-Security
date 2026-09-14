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
    return json.loads(value)


def _load_list(value: str | list[Any] | None) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    parsed = json.loads(value)
    return parsed if isinstance(parsed, list) else []


def _fingerprint(package_name: str, version_code: int, splits: list[dict[str, Any]]) -> str:
    h = hashlib.sha256()
    h.update(package_name.encode("utf-8", "replace"))
    h.update(b"\0")
    h.update(str(version_code).encode("ascii", "replace"))
    for split in sorted(splits, key=lambda row: int(row.get("index", 0))):
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

    This contract is deliberately independent from the Android UI.  Downstream
    build/preflight code can therefore identify the exact APK which owns
    libil2cpp.so instead of silently falling back to base.apk.
    """
    scan = _load(scan_json)
    copy_errors = _load_list(copy_errors_json)
    splits: list[dict[str, Any]] = []
    for row in scan.get("splits") or []:
        if not isinstance(row, dict):
            continue
        splits.append({
            "index": int(row.get("index", len(splits))),
            "name": str(row.get("name") or ""),
            "path": str(row.get("path") or ""),
            "size": int(row.get("size") or 0),
            "sha256": str(row.get("sha256") or ""),
            "dexCount": int(row.get("dexCount") or 0),
            "nativeCount": int(row.get("nativeCount") or 0),
        })

    try:
        expected = int(expected_apk_count) if expected_apk_count is not None else len(splits)
    except (TypeError, ValueError):
        expected = len(splits)
    try:
        vcode = int(version_code) if version_code is not None else 0
    except (TypeError, ValueError):
        vcode = 0

    selected = scan.get("selected") if isinstance(scan.get("selected"), dict) else {}
    library = selected.get("library") if isinstance(selected.get("library"), dict) else None
    metadata = selected.get("metadata") if isinstance(selected.get("metadata"), dict) else None
    patch_owner = None
    if library is not None:
        idx = int(library.get("splitIndex", -1))
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

    complete = not copy_errors and len(splits) == expected
    manifest = {
        "schema": SCHEMA,
        "packageName": package_name,
        "label": label,
        "versionName": version_name,
        "versionCode": vcode,
        "targetId": _fingerprint(package_name, vcode, splits)[:24],
        "fingerprintSha256": _fingerprint(package_name, vcode, splits),
        "scanCompleteness": "COMPLETE" if complete else "PARTIAL",
        "expectedApkCount": expected,
        "copiedApkCount": len(splits),
        "copyErrors": copy_errors,
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
    ok = True
    for split in target.get("splits") or []:
        if not isinstance(split, dict):
            continue
        path = Path(str(split.get("path") or ""))
        expected = str(split.get("sha256") or "")
        row = {"index": int(split.get("index", -1)), "name": str(split.get("name") or ""), "path": str(path)}
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
    owner = target.get("patchOwner") if isinstance(target.get("patchOwner"), dict) else None
    if owner is not None and not any(row.get("ok") and row.get("index") == int(owner.get("splitIndex", -1)) for row in rows):
        ok = False
    package_name = str(target.get("packageName") or "")
    try:
        version_code = int(target.get("versionCode") or 0)
    except (TypeError, ValueError):
        version_code = 0
    actual_fingerprint = _fingerprint(package_name, version_code, [x for x in target.get("splits") or [] if isinstance(x, dict)])
    expected_fingerprint = str(target.get("fingerprintSha256") or "")
    fingerprint_ok = bool(expected_fingerprint and actual_fingerprint == expected_fingerprint)
    if not fingerprint_ok:
        ok = False
    return json.dumps({
        "schema": "modkit-package-target-verify-1.0",
        "ok": ok and bool(rows),
        "targetId": target.get("targetId"),
        "scanCompleteness": target.get("scanCompleteness", "PARTIAL"),
        "fingerprintOk": fingerprint_ok,
        "actualFingerprintSha256": actual_fingerprint,
        "expectedFingerprintSha256": expected_fingerprint,
        "splits": rows,
    }, ensure_ascii=False, separators=(",", ":"))


def build_output_plan(target_json: str | dict[str, Any]) -> str:
    """Return the deterministic APK/APK-set build plan used by Android.

    This makes the owning-split contract independently testable without an
    Android device or signer and keeps PARTIAL targets fail-closed.
    """
    target = _load(target_json)
    splits = [x for x in target.get("splits") or [] if isinstance(x, dict)]
    owner = target.get("patchOwner") if isinstance(target.get("patchOwner"), dict) else None
    blockers: list[str] = []
    if not splits:
        blockers.append("no-splits")
    if target.get("scanCompleteness") != "COMPLETE":
        blockers.append("partial-scan")
    if target.get("fullIl2cppPair") and owner is None:
        blockers.append("missing-patch-owner")
    owner_index = int(owner.get("splitIndex", -1)) if owner else -1
    entries = []
    for row in sorted(splits, key=lambda x: int(x.get("index", 0))):
        idx = int(row.get("index", 0))
        entries.append({
            "index": idx,
            "name": str(row.get("name") or ""),
            "path": str(row.get("path") or ""),
            "role": "patched-owner" if idx == owner_index else "unchanged-resign",
        })
    return json.dumps({
        "schema": "modkit-package-build-plan-1.0",
        "ready": not blockers,
        "blockers": blockers,
        "mode": "apk-set" if len(entries) > 1 else "single-apk",
        "requiresWholeSetSigning": len(entries) > 1,
        "patchOwnerIndex": owner_index,
        "entries": entries,
    }, ensure_ascii=False, separators=(",", ":"))
