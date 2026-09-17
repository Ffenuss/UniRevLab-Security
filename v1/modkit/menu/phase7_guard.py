"""Second Phase-7 freshness gate for Menu preflight/build.

The Android build guard verifies the prepare audit immediately before handing work to
the legacy WorkerService.  This module repeats the immutable-input checks from inside
the Python preflight itself, closing the handoff window: a MenuSpec or owning APK which
changes after the Java guard cannot become a different signed payload.

Non-AutoMod/legacy MenuSpecs remain compatible.  The guard activates only when a
sibling ``menu-native-recovery.json`` explicitly declares ``phase7PlanRequired``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_AUDIT = "menu-native-recovery.json"
_SCHEMA = "modkit-automod-phase7-prepare-gate-1.0"


class Phase7PreflightError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Phase7PreflightError(f"Phase 7 audit is unreadable: {path.name}") from exc
    if not isinstance(value, dict):
        raise Phase7PreflightError(f"Phase 7 audit root must be an object: {path.name}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _workspace(source_apk: str | Path) -> tuple[Path, dict[str, Any]] | tuple[None, None]:
    source = Path(source_apk)
    candidates = [source.parent]
    if source.parent != source.parent.parent:
        candidates.append(source.parent.parent)
    seen: set[Path] = set()
    for root in candidates:
        try:
            key = root.resolve()
        except OSError:
            key = root
        if key in seen:
            continue
        seen.add(key)
        audit_path = root / _AUDIT
        if not audit_path.is_file():
            continue
        audit = _load(audit_path)
        if "phase7PlanRequired" not in audit:
            raise Phase7PreflightError("Phase 7 audit missing phase7PlanRequired policy")
        if audit.get("phase7PlanRequired"):
            return root, audit

        # Explicit legacy opt-out remains supported only for workspaces which do not
        # contain Phase-7 AutoMod artifacts.  Otherwise a truncated/tampered audit
        # could turn an AutoMod workspace into an unguarded legacy one.
        if (root / "automod-plan.json").exists() or (root / "simple-catalog.json").exists():
            raise Phase7PreflightError("Phase 7 artifacts present while audit disables Phase 7")
    return None, None


def _fingerprint(rows: Any, role: str) -> dict[str, Any] | None:
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("role") == role:
            return row
    return None


def _verify_file(rows: Any, role: str, path: Path) -> None:
    expected = _fingerprint(rows, role)
    if not isinstance(expected, dict):
        raise Phase7PreflightError(f"Phase 7 audit missing fingerprint: {role}")
    sha = str(expected.get("sha256") or "")
    size = expected.get("size")
    if len(sha) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in sha):
        raise Phase7PreflightError(f"Phase 7 audit has invalid fingerprint: {role}")
    if not path.is_file():
        raise Phase7PreflightError(f"Phase 7 input missing: {role}")
    try:
        expected_size = int(size)
    except (TypeError, ValueError):
        raise Phase7PreflightError(f"Phase 7 audit has invalid size: {role}") from None
    if expected_size != path.stat().st_size:
        raise Phase7PreflightError(f"Phase 7 input size changed: {role}")
    if _sha256(path).casefold() != sha.casefold():
        raise Phase7PreflightError(f"Phase 7 input SHA-256 changed: {role}")


def verify_preflight_workspace(source_apk: str | Path) -> dict[str, Any]:
    """Verify a completed Phase-7 audit when one owns this workspace.

    Returns a compact status for diagnostics.  Absence of a Phase-7 audit is not an
    error because legacy/non-IL2CPP Menu Builder flows intentionally remain supported.
    """
    root, audit = _workspace(source_apk)
    if root is None or audit is None:
        return {"required": False, "verified": False}
    if not audit.get("completed"):
        raise Phase7PreflightError("Phase 7 prepare audit is incomplete")
    if audit.get("freshnessPolicy") != "EXACT_INPUT_SHA256":
        raise Phase7PreflightError("Phase 7 input freshness policy missing")
    if audit.get("phase7FreshnessPolicy") != "EXACT_PLAN_AND_CATALOG_SHA256":
        raise Phase7PreflightError("Phase 7 plan/catalog freshness policy missing")
    gate = audit.get("phase7Gate") if isinstance(audit.get("phase7Gate"), dict) else {}
    if gate.get("schema") != _SCHEMA or not gate.get("validated"):
        raise Phase7PreflightError("Phase 7 executable-control gate is not validated")
    if not gate.get("methodIdentityRequiredForBoundRva"):
        raise Phase7PreflightError("Phase 7 method identity gate is missing")
    if int(gate.get("rejectedControlCount", -1)) != 0:
        raise Phase7PreflightError("Phase 7 audit contains rejected executable controls")
    if gate.get("runtimeEvidencePromotesBuildability") or gate.get("reviewEvidencePromotesBuildability"):
        raise Phase7PreflightError("Phase 7 audit illegally promotes non-control evidence")

    inputs = audit.get("inputFingerprints")
    outputs = audit.get("outputFingerprints")
    source = Path(source_apk)
    for role, path in (
        ("metadata", root / "metadata.bin"),
        ("library", root / "library.so"),
        ("catalog", root / "analysis.methods.jsonl"),
        ("sourceApk", source),
        ("phase7Plan", root / "automod-plan.json"),
        ("simpleCatalog", root / "simple-catalog.json"),
    ):
        _verify_file(inputs, role, path)
    _verify_file(outputs, "menuSpec", root / "menu-spec.json")
    return {
        "required": True,
        "verified": True,
        "schema": gate.get("schema"),
        "validatedMenuControlCount": int(gate.get("validatedMenuControlCount") or 0),
        "identityBoundRvaCount": int(gate.get("identityBoundRvaCount") or 0),
        "freshnessPolicy": audit.get("phase7FreshnessPolicy"),
    }
