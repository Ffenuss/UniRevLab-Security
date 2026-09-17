"""Technical callable preflight for review-only Menu Builder candidates.

A numeric IL2CPP setter may have a proven signature, exact RVA and executable ELF
mapping while still lacking a defensible UI value range.  This module records that
stronger state without inventing min/max/default values and without creating an
executable binding.  The temporary slider policy used below exists only so the
existing binary validator can validate the exact call target; it is never persisted
into MENU-SPEC and never promotes buildability.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import zipfile
from typing import Any

from modkit.menu.builder import MenuControl, MenuSpec, validate_bindings
from modkit.reworkspace.signature import rodroid_signature_contract

SCHEMA = "modkit-menu-callable-preflight-1.0"


def _load(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _write(path: str | Path, value: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(destination)


def _control(row: dict[str, Any]) -> MenuControl:
    allowed = MenuControl.__dataclass_fields__
    payload = {key: value for key, value in row.items() if key in allowed}
    return MenuControl(**payload)


def _gate(control: MenuControl, min_confidence: float) -> tuple[dict[str, Any] | None, str | None]:
    if control.binding is not None:
        return None, "already-bound"
    if control.suggested_binding != "number_setter":
        return None, "not-numeric-setter"
    if not control.evidence_signature or not control.evidence_rva or control.evidence_rva <= 0:
        return None, "missing-signature-or-rva"
    contract = rodroid_signature_contract(control.evidence_signature)
    if not contract.get("autoBindingSafe") or contract.get("bindingSuggestion") != "number_setter":
        return None, "signature-contract-mismatch"
    suggested_type = str(contract.get("suggestedControlType") or "")
    if suggested_type not in {"slider_int", "slider_float"}:
        return None, "numeric-control-type-unsupported"
    if control.call_abi != "il2cpp":
        return None, "not-il2cpp-signature-evidence"
    if control.evidence_confidence is None or float(control.evidence_confidence) < float(min_confidence):
        return None, "confidence-below-threshold"
    evidence_static = control.evidence_is_static if control.evidence_is_static is not None else control.is_static
    if bool(contract.get("isStatic")) != bool(evidence_static):
        return None, "signature-staticness-mismatch"
    if contract.get("managedValueType") not in {"System.Int32", "System.Single"}:
        return None, "runtime-value-abi-unsupported"
    if control.value_type not in {"auto", contract.get("managedValueType")}:
        return None, "managed-value-type-mismatch"

    verification = control.method_verification or {}
    if verification:
        if not verification.get("addressConfirmed"):
            return None, "method-address-not-structurally-confirmed"
        if not verification.get("abiConfirmed"):
            return None, "method-abi-not-structurally-confirmed"
        if not evidence_static and not verification.get("executableReady"):
            return None, "method-instance-resolver-not-structurally-confirmed"
    if control.semantic_verified is False:
        return None, control.semantic_blocker or "semantic-xref-verification-required"
    if control.context_verified is False:
        return None, control.context_blocker or "method-local-context-verification-required"
    if not evidence_static:
        if control.resolver_kind not in {"out_ptr_bool", "return_ptr"} or not control.resolver_rva or control.resolver_rva <= 0:
            return None, "instance-resolver-not-confirmed"
        if not control.resolver_verified:
            return None, "instance-resolver-type-not-verified"
        resolver_contract = rodroid_signature_contract(control.resolver_signature)
        if resolver_contract.get("resolverSuggestion") != control.resolver_kind:
            return None, "instance-resolver-signature-mismatch"
    return contract, None


def verify_numeric_callable(control: MenuControl, source_apk: str | Path, *, target_sha256: str = "",
                            source_apk_sha256: str = "", min_confidence: float = 0.85) -> dict[str, Any]:
    """Verify a numeric setter as callable without selecting a value policy.

    The returned ``verified`` flag means signature/ABI/identity/ELF checks passed.
    ``parameterPolicyRequired`` means the control still has no analyst/contract
    supplied slider range and therefore remains non-executable.
    """
    contract, blocker = _gate(control, min_confidence)
    base = {
        "schema": SCHEMA,
        "id": control.id,
        "title": control.title,
        "suggestedBinding": control.suggested_binding,
        "evidenceRva": control.evidence_rva,
        "targetSo": control.suggested_target_so or control.target_so,
        "verified": False,
        "parameterPolicyRequired": True,
        "bindingCreated": False,
        "policyInferred": False,
    }
    if blocker or contract is None:
        return {**base, "blocker": blocker}

    suggested_type = str(contract.get("suggestedControlType"))
    has_reviewed_range = (
        control.type == suggested_type
        and control.min_value is not None and control.max_value is not None
        and float(control.min_value) < float(control.max_value)
    )
    data = asdict(control)
    data.update({
        "type": suggested_type,
        "rva": int(control.evidence_rva),
        "binding": "number_setter",
        "target_so": control.suggested_target_so or control.target_so,
        "is_static": bool(control.evidence_is_static if control.evidence_is_static is not None else control.is_static),
        "value_type": str(contract.get("managedValueType")),
    })
    # Validation-only placeholder. It satisfies MenuControl's slider invariant so
    # validate_bindings can exercise the exact ELF/RVA/resolver gates. It is not
    # written back to the source MenuSpec and is explicitly reported as inferred=false.
    if not has_reviewed_range:
        data.update({"min_value": 0.0, "max_value": 1.0, "default": 0.0})
    candidate = MenuControl(**data)
    validation_spec = MenuSpec(
        title="Callable preflight",
        controls=[candidate],
        target_sha256=target_sha256,
        source_apk_sha256=source_apk_sha256,
    )
    try:
        validation = validate_bindings(validation_spec, source_apk)
    except Exception as exc:
        return {**base, "blocker": "binary-preflight-exception", "error": str(exc),
                "parameterPolicyRequired": not has_reviewed_range}
    blocks = [row for row in validation.get("issues", []) if row.get("severity") == "BLOCK"]
    verified = not blocks and int(validation.get("validatedBindings") or 0) == 1
    check = (validation.get("checks") or [None])[0]
    return {
        **base,
        "verified": verified,
        "parameterPolicyRequired": not has_reviewed_range,
        "blocker": None if verified else "elf-preflight-block",
        "suggestedType": suggested_type,
        "managedValueType": contract.get("managedValueType"),
        "signature": contract.get("signature"),
        "isStatic": candidate.is_static,
        "resolverRva": candidate.resolver_rva,
        "resolverKind": candidate.resolver_kind,
        "elfVerification": check,
        "issues": validation.get("issues", []),
    }


def augment_preflight(menu_spec_path: str | Path, preflight_path: str | Path, source_apk: str | Path,
                      *, min_confidence: float = 0.85) -> dict[str, Any]:
    """Annotate menu-preflight with technical callable state and split readiness.

    This function is intentionally idempotent. It never changes MENU-SPEC, never
    supplies numeric ranges, and never changes a review-only control into a binding.
    """
    menu = _load(menu_spec_path)
    preflight = _load(preflight_path)
    if not menu or not preflight:
        raise ValueError("callable preflight requires menu-spec.json and menu-preflight.json")

    controls: list[MenuControl] = []
    for row in menu.get("controls") or []:
        if not isinstance(row, dict):
            continue
        try:
            controls.append(_control(row))
        except Exception:
            continue
    target_sha = str(menu.get("targetSha256") or "")
    source_sha = str(menu.get("sourceApkSha256") or "")
    records: list[dict[str, Any]] = []
    verified = 0
    pending = 0
    rejected = 0
    by_id: dict[str, dict[str, Any]] = {}
    for control in controls:
        if control.binding is not None or control.suggested_binding != "number_setter":
            continue
        record = verify_numeric_callable(
            control, source_apk, target_sha256=target_sha,
            source_apk_sha256=source_sha, min_confidence=min_confidence,
        )
        records.append(record)
        by_id[control.id] = record
        if record.get("verified"):
            verified += 1
            if record.get("parameterPolicyRequired"):
                pending += 1
        else:
            rejected += 1

    counts = preflight.get("counts") if isinstance(preflight.get("counts"), dict) else {}
    counts["callableVerified"] = verified
    counts["callableVerifiedRangePending"] = pending
    counts["callableRejected"] = rejected
    preflight["counts"] = counts
    preflight["callablePreflight"] = {
        "schema": SCHEMA,
        "minConfidence": min_confidence,
        "verifiedCount": verified,
        "rangePolicyPendingCount": pending,
        "rejectedCount": rejected,
        "records": records,
        "createsBindings": False,
        "infersParameterPolicy": False,
    }

    for row in preflight.get("controls") or []:
        if not isinstance(row, dict):
            continue
        record = by_id.get(str(row.get("id") or ""))
        if not record:
            continue
        row["callableVerification"] = record
        row["callableVerified"] = bool(record.get("verified"))
        row["parameterPolicyRequired"] = bool(record.get("parameterPolicyRequired"))
        if record.get("verified") and record.get("parameterPolicyRequired"):
            row["state"] = "callable-verified-range-pending"

    issues = [row for row in (preflight.get("issues") or []) if isinstance(row, dict)
              and row.get("code") not in {"CALLABLE_VERIFIED_RANGE_PENDING", "NATIVE_PAYLOAD_HOST_REQUIRED"}]
    if pending:
        issues.append({
            "severity": "WARN",
            "code": "CALLABLE_VERIFIED_RANGE_PENDING",
            "message": f"{pending} numeric setter(s) passed signature/ABI/ELF preflight but remain non-executable until a value range/default policy is explicitly supplied.",
        })

    bound = int(counts.get("bound") or 0)
    probes = int(counts.get("probeReadOnly") or 0)
    blocked = bool(preflight.get("blocked"))
    host_candidates: list[str] = []
    host_available = False if (bound or probes) else True
    source = Path(source_apk)
    if bound or probes:
        try:
            with zipfile.ZipFile(source) as archive:
                host_candidates = [name for name in archive.namelist()
                                   if name.startswith("lib/arm64-v8a/") and name.endswith(".so")]
            host_available = bool(host_candidates)
        except Exception as exc:
            host_available = False
            issues.append({"severity": "BLOCK", "code": "NATIVE_PAYLOAD_HOST_SCAN_FAILED", "message": str(exc)})
        if not host_available:
            issues.append({
                "severity": "BLOCK", "code": "NATIVE_PAYLOAD_HOST_REQUIRED",
                "message": "Runtime spec is valid, but the selected APK has no arm64 native host. Select the owning native split APK before packaging a runtime payload.",
            })
    preflight["issues"] = issues
    preflight["payloadHostAvailable"] = host_available
    preflight["payloadHostCandidates"] = host_candidates[:32]

    ready_modification = bound > 0 and not blocked and host_available
    ready_probe_payload = probes > 0 and not blocked and host_available
    preflight["readyForModificationPayload"] = ready_modification
    preflight["readyForProbePayload"] = ready_probe_payload
    preflight["readyForProbeSpec"] = probes > 0 and not blocked
    preflight["readyForPayload"] = ready_modification or ready_probe_payload
    actionable = int(counts.get("actionableReview") or 0)
    preflight["readyForAutoBuild"] = bool(preflight["readyForPayload"] and actionable == 0 and pending == 0)
    preflight["parameterPolicyPending"] = pending
    preflight["callableVerifiedNotBuildable"] = verified > 0 and bound == 0
    _write(preflight_path, preflight)
    return preflight


def augment_preflight_json(menu_spec_path: str | Path, preflight_path: str | Path,
                           source_apk: str | Path, min_confidence: float = 0.85) -> str:
    """Chaquopy-safe adapter which returns canonical JSON rather than ``dict.__str__``."""
    result = augment_preflight(
        menu_spec_path, preflight_path, source_apk, min_confidence=float(min_confidence)
    )
    return json.dumps(result, ensure_ascii=False)
