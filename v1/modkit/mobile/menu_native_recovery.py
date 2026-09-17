"""AutoMod Menu preparation with exact CodeGenModule count disambiguation.

The legacy engine's ``Elf.modules`` intentionally returns nothing when more than one
structurally plausible CodeGenModule record references an image name. For the AutoMod
prepare path we have stronger metadata: each managed image has a contiguous MethodDef
RID domain 1..N. This adapter temporarily narrows module resolution to candidates with
that exact N and then invokes the unchanged Deep Resolver -> Menu -> ELF preflight
pipeline. All existing ABI, semantic, instance-resolver and APK ELF gates remain in
force; this adapter only removes a false module ambiguity.

Phase 7 adds a second fail-closed boundary: immediately before prepare the current
AutoMod plan is rebuilt from the Evidence Graph, and every executable MenuSpec control
produced by the legacy autopilot must map to an RVA explicitly admitted by that plan.
When the Evidence Graph also carries an exact metadata MethodDef id, the generated
control must preserve that same method identity; sharing an RVA alone is not enough.
Runtime/read-only and review evidence therefore cannot become executable controls via
a legacy prepare path.

The patch of ``engine.Elf.modules`` exists only inside one locked call and is restored
in ``finally``. No target bytes are modified here. Adapter decisions are persisted as
provenance so a prepared menu can be audited without treating recovery as build proof.
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

from modkit.mobile import engine
from modkit.mobile.il2cpp_no_rva_native import _metadata_token_domains, _resolve_modules_expected

SCHEMA = "modkit-menu-native-recovery-adapter-1.0"
PHASE7_GATE_SCHEMA = "modkit-automod-phase7-prepare-gate-1.0"
_LOCK = threading.RLock()


def _expected_counts(metadata_path: str | Path, cb=None) -> tuple[dict[str, int], dict[str, int]]:
    meta = engine.Metadata(metadata_path)
    try:
        return _metadata_token_domains(meta, cb)
    finally:
        meta.close()


def _fingerprint(role: str, path: str | Path, cb=None) -> dict[str, Any]:
    file = Path(path)
    engine.check(cb)
    if not file.is_file():
        raise FileNotFoundError(str(file))
    size = file.stat().st_size
    sha256 = engine.digest(file, cb)
    engine.check(cb)
    return {"role": role, "name": file.name, "size": size, "sha256": sha256}


def _write_audit(path: str | Path | None, audit: dict[str, Any]) -> None:
    if path is None:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")
    temp.write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(destination)


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _upsert_fingerprint(rows: list[dict[str, Any]], row: dict[str, Any]) -> list[dict[str, Any]]:
    role = str(row.get("role") or "")
    out = [item for item in rows if not isinstance(item, dict) or str(item.get("role") or "") != role]
    out.append(row)
    return out


def _bind_phase7_freshness(root: str | Path, cb=None) -> dict[str, Any]:
    """Finish the Phase 7 audit entirely in Python with exact current SHA bindings.

    Android keeps an idempotent verifier/binder for backward compatibility, but a
    pure-Python ``prepare_workspace`` must be independently complete.  Otherwise the
    same prepare result is considered fresh only after crossing the Java bridge.
    """
    workspace = Path(root)
    audit_path = workspace / "menu-native-recovery.json"
    audit = _load_json(audit_path)
    if not audit.get("completed"):
        raise ValueError("AutoMod Phase 7: native-recovery audit is not completed")
    gate = audit.get("phase7Gate") if isinstance(audit.get("phase7Gate"), dict) else {}
    if not gate.get("validated") or int(gate.get("rejectedControlCount") or 0) != 0:
        raise ValueError("AutoMod Phase 7: executable-control identity gate is not validated")

    inputs = audit.get("inputFingerprints") if isinstance(audit.get("inputFingerprints"), list) else []
    outputs = audit.get("outputFingerprints") if isinstance(audit.get("outputFingerprints"), list) else []
    inputs = _upsert_fingerprint(inputs, _fingerprint("phase7Plan", workspace / "automod-plan.json", cb))
    inputs = _upsert_fingerprint(inputs, _fingerprint("simpleCatalog", workspace / "simple-catalog.json", cb))
    outputs = _upsert_fingerprint(outputs, _fingerprint("menuSpec", workspace / "menu-spec.json", cb))
    outputs = _upsert_fingerprint(outputs, _fingerprint("menuPreflight", workspace / "menu-preflight.json", cb))
    audit["inputFingerprints"] = inputs
    audit["outputFingerprints"] = outputs
    audit["phase7FreshnessPolicy"] = "EXACT_PLAN_AND_CATALOG_SHA256"
    _write_audit(audit_path, audit)
    engine.check(cb)
    return audit


def _number(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        try:
            return int(text, 16 if text.startswith("0x") else 10)
        except ValueError:
            return None
    return None


def _candidate_method_id(row: dict[str, Any]) -> int | None:
    for key in ("locator", "resolvedLocator", "nativeRvaRecovery"):
        source = row.get(key) if isinstance(row.get(key), dict) else {}
        for name in ("metadataMethodId", "methodId", "methodIndex", "id"):
            method_id = _number(source.get(name))
            if method_id is not None and method_id >= 0:
                return method_id
    return None


def _control_method_id(control: dict[str, Any]) -> int | None:
    for name in ("metadataMethodId", "methodId", "methodIndex"):
        method_id = _number(control.get(name))
        if method_id is not None and method_id >= 0:
            return method_id
    verification = control.get("method_verification") if isinstance(control.get("method_verification"), dict) else {}
    for name in ("metadataMethodId", "methodId", "methodIndex"):
        method_id = _number(verification.get(name))
        if method_id is not None and method_id >= 0:
            return method_id
    finding = str(control.get("finding_id") or control.get("findingId") or "")
    match = re.fullmatch(r"deep\.method\.(\d+)", finding)
    if match:
        return int(match.group(1))
    return None


def _phase7_allowed_bindings(plan: dict[str, Any]) -> tuple[set[int], dict[int, set[int]]]:
    policy = plan.get("phase7Policy") if isinstance(plan.get("phase7Policy"), dict) else {}
    if not policy.get("refinedCatalogRequiresControlCandidate"):
        raise ValueError("AutoMod Phase 7 policy missing: rebuild the Evidence Graph plan")
    candidates = plan.get("candidates") if isinstance(plan.get("candidates"), list) else []
    allowed: set[int] = set()
    methods_by_rva: dict[int, set[int]] = {}
    executable_rows = 0
    for row in candidates:
        if not isinstance(row, dict) or not bool(row.get("executableControl")):
            continue
        executable_rows += 1
        method_id = _candidate_method_id(row)
        row_rvas: set[int] = set()
        for key in ("locator", "resolvedLocator", "nativeRvaRecovery"):
            source = row.get(key) if isinstance(row.get(key), dict) else {}
            rva = _number(source.get("rva"))
            if rva is None:
                rva = _number(source.get("rvaHex"))
            if rva is not None and rva > 0:
                allowed.add(rva)
                row_rvas.add(rva)
        for rva in row_rvas:
            bucket = methods_by_rva.setdefault(rva, set())
            if method_id is not None:
                bucket.add(method_id)
    declared = int(plan.get("executableControlCount") or 0)
    if declared <= 0 or executable_rows <= 0:
        raise ValueError("AutoMod Phase 7: no quality-gated executable controls")
    if declared != executable_rows:
        raise ValueError("AutoMod Phase 7: executable control count mismatch")
    if not allowed:
        raise ValueError("AutoMod Phase 7: executable controls have no exact native RVA")
    return allowed, methods_by_rva


def _phase7_allowed_rvas(plan: dict[str, Any]) -> set[int]:
    allowed, _ = _phase7_allowed_bindings(plan)
    return allowed


def _validate_phase7_menu(root: str | Path, plan: dict[str, Any], allowed_rvas: set[int], cb=None,
                          allowed_methods_by_rva: dict[int, set[int]] | None = None) -> dict[str, Any]:
    workspace = Path(root)
    audit_path = workspace / "menu-native-recovery.json"
    menu_path = workspace / "menu-spec.json"
    audit = _load_json(audit_path)
    menu = _load_json(menu_path)
    controls = menu.get("controls") if isinstance(menu.get("controls"), list) else []
    if allowed_methods_by_rva is None:
        _, allowed_methods_by_rva = _phase7_allowed_bindings(plan)
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, control in enumerate(controls):
        engine.check(cb)
        if not isinstance(control, dict):
            continue
        rva = _number(control.get("rva"))
        binding = control.get("binding")
        visual = str(control.get("type") or "").casefold()
        probe = control.get("probe_kind") or control.get("probeKind")
        executable = bool(binding) and rva is not None and rva > 0 and visual != "label" and not probe
        if not executable:
            continue
        method_id = _control_method_id(control)
        expected_methods = allowed_methods_by_rva.get(rva, set())
        row = {
            "index": index,
            "id": control.get("id"),
            "title": control.get("title"),
            "findingId": control.get("finding_id") or control.get("findingId"),
            "metadataMethodId": method_id,
            "rva": rva,
            "rvaHex": f"0x{rva:x}",
            "binding": binding,
        }
        reason = None
        if rva not in allowed_rvas:
            reason = "rva-not-allowed"
        elif expected_methods and method_id is None:
            reason = "method-identity-missing"
        elif expected_methods and method_id not in expected_methods:
            reason = "method-identity-mismatch"
        if reason is None:
            accepted.append(row)
        else:
            rejected.append({**row, "reason": reason, "expectedMetadataMethodIds": sorted(expected_methods)})

    identity_bound = {rva: sorted(ids) for rva, ids in allowed_methods_by_rva.items() if ids}
    gate = {
        "schema": PHASE7_GATE_SCHEMA,
        "validated": not rejected,
        "planSchema": plan.get("schema"),
        "policySchema": (plan.get("phase7Policy") or {}).get("schema") if isinstance(plan.get("phase7Policy"), dict) else None,
        "executableControlCount": int(plan.get("executableControlCount") or 0),
        "allowedRvaCount": len(allowed_rvas),
        "identityBoundRvaCount": len(identity_bound),
        "methodIdentityRequiredForBoundRva": True,
        "validatedMenuControlCount": len(accepted),
        "rejectedControlCount": len(rejected),
        "allowedRvas": [f"0x{value:x}" for value in sorted(allowed_rvas)],
        "allowedMethodIdsByRva": {f"0x{rva:x}": ids for rva, ids in sorted(identity_bound.items())},
        "accepted": accepted,
        "rejected": rejected,
        "runtimeEvidencePromotesBuildability": False,
        "reviewEvidencePromotesBuildability": False,
    }
    audit["phase7PlanRequired"] = True
    audit["phase7Gate"] = gate
    if rejected:
        audit["completed"] = False
        audit["errorType"] = "Phase7ExecutableControlRejected"
        audit["error"] = "Generated MenuSpec contains executable controls outside the current Evidence Graph identity allowlist"
    _write_audit(audit_path, audit)
    engine.check(cb)
    if rejected:
        raise ValueError("AutoMod Phase 7 blocked executable control outside current Evidence Graph allowlist")
    return gate


def _strict_modules_factory(original, expected_counts: dict[str, int], audit: dict[str, Any]):
    def strict_modules(self, image_names):
        wanted = {str(name) for name in image_names if str(name)}
        expected = {name: int(expected_counts[name]) for name in wanted if int(expected_counts.get(name, 0)) > 0}
        resolved: dict[str, tuple[int, int]] = {}
        stats: dict[str, Any] = {"requested": 0, "resolved": 0, "ambiguous": 0, "noString": 0, "noCandidate": 0, "modules": {}}
        if expected:
            resolved, stats = _resolve_modules_expected(self, expected, getattr(self, "cb", None))
        fallback_names = wanted - set(expected)
        fallback: dict[str, tuple[int, int]] = {}
        if fallback_names:
            fallback = original(self, fallback_names)
            for name, table in fallback.items():
                resolved.setdefault(name, table)
        call = {
            "requestedImages": sorted(wanted),
            "exactCountImages": sorted(expected),
            "exactCountResolved": int(stats.get("resolved") or 0),
            "exactCountAmbiguous": int(stats.get("ambiguous") or 0),
            "exactCountNoCandidate": int(stats.get("noCandidate") or 0),
            "fallbackImages": sorted(fallback_names),
            "fallbackResolvedImages": sorted(fallback),
            "returnedModules": sorted(resolved),
            "moduleResolution": stats.get("modules") if isinstance(stats.get("modules"), dict) else {},
        }
        audit["calls"] = int(audit.get("calls") or 0) + 1
        history = audit.setdefault("history", [])
        if isinstance(history, list):
            history.append(call)
        audit["last"] = call
        return resolved
    return strict_modules


def prepare(metadata_path: str | Path, library_path: str | Path, catalog_path: str | Path,
            deep_dir: str | Path, source_apk: str | Path, menu_json_path: str | Path,
            project_dir: str | Path, output_report: str | Path | None = None,
            output_preflight: str | Path | None = None, dump_dir: str | Path | None = None,
            title: str = "ModKit Autopilot Menu", max_deep: int = 24,
            target_controls: int = 12, cb=None, audit_path: str | Path | None = None):
    """Run the normal autopilot with stronger, fail-closed module disambiguation."""
    input_fingerprints = [
        _fingerprint("metadata", metadata_path, cb),
        _fingerprint("library", library_path, cb),
        _fingerprint("catalog", catalog_path, cb),
        _fingerprint("sourceApk", source_apk, cb),
    ]
    expected, non_contiguous = _expected_counts(metadata_path, cb)
    audit: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": "EXACT_METADATA_TOKEN_DOMAIN_CODEGENMODULE_ADAPTER",
        "freshnessPolicy": "EXACT_INPUT_SHA256",
        "inputFingerprints": input_fingerprints,
        "outputFingerprints": [],
        "contiguousTokenDomains": len(expected),
        "nonContiguousTokenDomains": len(non_contiguous),
        "calls": 0,
        "history": [],
        "completed": False,
        "normalBindingRequired": True,
        "preflightRequired": True,
        "modifiesTarget": False,
        "addressRecoveryPromotesBuildability": False,
        "promotesBuildability": False,
        "phase7PlanRequired": True,
        "inputs": {
            "metadata": Path(metadata_path).name,
            "library": Path(library_path).name,
            "catalog": Path(catalog_path).name,
            "sourceApk": Path(source_apk).name,
        },
    }
    original = engine.Elf.modules
    strict = _strict_modules_factory(original, expected, audit)
    with _LOCK:
        engine.Elf.modules = strict
        try:
            result = engine.menu_autopilot_prepare(
                str(metadata_path), str(library_path), str(catalog_path), str(deep_dir),
                str(source_apk), str(menu_json_path), str(project_dir),
                str(output_report) if output_report else None,
                str(output_preflight) if output_preflight else None,
                str(dump_dir) if dump_dir else None,
                str(title), int(max_deep), int(target_controls), cb,
            )
            outputs = [_fingerprint("menuSpec", menu_json_path, cb)]
            if output_preflight is not None:
                outputs.append(_fingerprint("menuPreflight", output_preflight, cb))
            audit["outputFingerprints"] = outputs
            audit["completed"] = True
            return result
        except Exception as exc:
            audit["errorType"] = type(exc).__name__
            audit["error"] = str(exc)
            raise
        finally:
            engine.Elf.modules = original
            _write_audit(audit_path, audit)


def prepare_workspace(workspace: str | Path, source_apk: str | Path, cb=None):
    root = Path(workspace)
    deep = root / "analysis-deep"
    deep.mkdir(parents=True, exist_ok=True)
    dump = root / "rodroid"

    from modkit.mobile import automod_cancellable
    plan = automod_cancellable.build_workspace_plan(root, root / "automod-plan.json", cb)
    allowed_rvas, allowed_methods_by_rva = _phase7_allowed_bindings(plan)

    result = prepare(
        root / "metadata.bin",
        root / "library.so",
        root / "analysis.methods.jsonl",
        deep,
        source_apk,
        root / "menu-spec.json",
        root / "menu-project",
        root / "menu-autopilot.json",
        root / "menu-preflight.json",
        dump if dump.is_dir() else None,
        "ModKit Autopilot Menu",
        24,
        12,
        cb=cb,
        audit_path=root / "menu-native-recovery.json",
    )
    _validate_phase7_menu(root, plan, allowed_rvas, cb, allowed_methods_by_rva)
    _bind_phase7_freshness(root, cb)
    return result
