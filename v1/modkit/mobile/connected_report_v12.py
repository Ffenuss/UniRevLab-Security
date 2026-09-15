"""Connected report 1.2: base report plus read-only runtime and IL2CPP corroboration.

The v1.1 report builder remains available for compatibility. This wrapper enriches its
finding rows without changing their actionable/buildable state or method-link status.
Runtime procfs layout, IL2CPP metadata/ELF structural checks, and no-RVA metadata
identity are corroboration only; none of them can create an executable patch binding.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile.connected_report import build_connected_report as _build_base

SCHEMA = "modkit-connected-report-1.2"
_IL2CPP_CROSSCHECK_SCHEMA = "modkit-il2cpp-crosscheck-1.0"
_METADATA_IDENTITY_SCHEMA = "modkit-il2cpp-metadata-identity-1.1"


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    rows.append(value)
    except Exception:
        return []
    return rows


def _fresh(outputs: list[Path], inputs: list[Path]) -> bool:
    """True only when every generated output is at least as new as every input."""
    if not outputs or not inputs:
        return False
    try:
        if any(not path.is_file() for path in outputs) or any(not path.is_file() for path in inputs):
            return False
        newest_input = max(path.stat().st_mtime_ns for path in inputs)
        oldest_output = min(path.stat().st_mtime_ns for path in outputs)
        return oldest_output >= newest_input
    except OSError:
        return False


def _norm_hex(value: Any) -> str:
    if value in (None, "", 0, "0", "0x0"):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip().lower()
    try:
        return f"0x{int(text, 0):x}"
    except Exception:
        return text


def _safe_runtime(row: dict[str, Any]) -> dict[str, Any] | None:
    if str(row.get("runtimeEvidence") or "") != "PROCFS_MODULE_LAYOUT":
        return None
    if bool(row.get("promotesBuildability")):
        return None
    return {
        "evidence": "PROCFS_MODULE_LAYOUT",
        "modulePath": row.get("modulePath"),
        "moduleBasename": row.get("moduleBasename"),
        "loadBaseHex": row.get("loadBaseHex"),
        "rvaHex": row.get("rvaHex"),
        "runtimeVaHex": row.get("runtimeVaHex"),
        "mapped": bool(row.get("mapped")),
        "mappingPerms": row.get("mappingPerms"),
        "matchMode": row.get("matchMode"),
        "promotesBuildability": False,
    }


def _runtime_indexes(runtime: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_rva: dict[str, list[dict[str, Any]]] = {}
    rows = runtime.get("correlations") if isinstance(runtime.get("correlations"), list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        safe = _safe_runtime(row)
        if safe is None:
            continue
        card_id = row.get("id")
        if card_id not in (None, ""):
            by_id[str(card_id)] = safe
        rva = _norm_hex(row.get("rvaHex") if row.get("rvaHex") is not None else row.get("rva"))
        if rva:
            by_rva.setdefault(rva, []).append(safe)
    return by_id, by_rva


def _safe_il2cpp(row: dict[str, Any]) -> dict[str, Any] | None:
    if bool(row.get("promotesBuildability")) or bool(row.get("associationConfirmed")):
        return None
    status = str(row.get("status") or "UNRESOLVED")
    return {
        "engine": "il2cpp.structural-crosscheck-embedded",
        "status": status,
        "methodName": row.get("methodName"),
        "rvaHex": _norm_hex(row.get("rvaHex") if row.get("rvaHex") is not None else row.get("rva")),
        "metadataMethodNamePresent": bool(row.get("metadataMethodNamePresent")),
        "executableElfRangePresent": bool(row.get("executableElfRangePresent")),
        "elfRangeMode": row.get("elfRangeMode"),
        "segmentIndex": row.get("segmentIndex"),
        "associationConfirmed": False,
        "promotesBuildability": False,
    }


def _il2cpp_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rank = {
        "STRUCTURAL_BOTH_PRESENT": 3,
        "ELF_EXECUTABLE_RVA_CONFIRMED": 2,
        "METADATA_METHOD_NAME_CONFIRMED": 1,
        "UNRESOLVED": 0,
    }
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        safe = _safe_il2cpp(row)
        if safe is None:
            continue
        rva = str(safe.get("rvaHex") or "")
        if not rva:
            continue
        previous = out.get(rva)
        if previous is None or rank.get(str(safe.get("status")), -1) > rank.get(str(previous.get("status")), -1):
            out[rva] = safe
    return out


def _ensure_il2cpp_crosscheck(root: Path) -> dict[str, Any]:
    metadata = root / "metadata.bin"
    library = root / "library.so"
    methods = root / "analysis.methods.jsonl"
    summary_path = root / "il2cpp-crosscheck.json"
    rows_path = root / "il2cpp-crosscheck.methods.jsonl"
    existing = _json(summary_path)
    inputs = [metadata, library, methods]
    inputs_available = all(path.is_file() for path in inputs)

    if inputs_available:
        outputs = [summary_path] if existing.get("error") else [summary_path, rows_path]
        current_schema = existing.get("schema") == _IL2CPP_CROSSCHECK_SCHEMA
        if existing and (current_schema or existing.get("error")) and _fresh(outputs, inputs):
            result = dict(existing)
            result["freshnessVerified"] = True
            result["sourceInputsAvailable"] = True
            return result
        try:
            summary_path.unlink(missing_ok=True)
            rows_path.unlink(missing_ok=True)
            from modkit.mobile.il2cpp_crosscheck import run_crosscheck
            result = run_crosscheck(metadata, library, methods, summary_path, rows_path)
            result = dict(result)
            result["freshnessVerified"] = True
            result["sourceInputsAvailable"] = True
            return result
        except Exception as exc:
            failure = {
                "schema": "modkit-il2cpp-crosscheck-error-1.0",
                "engine": "il2cpp.structural-crosscheck-embedded",
                "error": str(exc),
                "freshnessVerified": True,
                "sourceInputsAvailable": True,
                "promotesBuildability": False,
                "confirmsMethodToRvaAssociation": False,
            }
            try:
                summary_path.write_text(json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            return failure

    if existing:
        result = dict(existing)
        result["freshnessVerified"] = False
        result["sourceInputsAvailable"] = False
        return result
    return {}


def _ensure_metadata_identity(root: Path) -> dict[str, Any]:
    metadata = root / "metadata.bin"
    methods = root / "analysis.methods.jsonl"
    summary_path = root / "il2cpp-metadata-identity.json"
    rows_path = root / "il2cpp-metadata-identity.methods.jsonl"
    existing = _json(summary_path)
    inputs = [metadata, methods]
    inputs_available = all(path.is_file() for path in inputs)

    if inputs_available:
        outputs = [summary_path] if existing.get("error") else [summary_path, rows_path]
        current_schema = existing.get("schema") == _METADATA_IDENTITY_SCHEMA
        if existing and (current_schema or existing.get("error")) and _fresh(outputs, inputs):
            result = dict(existing)
            result["freshnessVerified"] = True
            result["sourceInputsAvailable"] = True
            return result
        try:
            summary_path.unlink(missing_ok=True)
            rows_path.unlink(missing_ok=True)
            from modkit.mobile.il2cpp_metadata_identity import build_workspace_identity
            result = build_workspace_identity(root, summary_path)
            result = dict(result)
            result["freshnessVerified"] = True
            result["sourceInputsAvailable"] = True
            return result
        except Exception as exc:
            failure = {
                "schema": "modkit-il2cpp-metadata-identity-error-1.1",
                "engine": "il2cpp.metadata-identity-embedded",
                "error": str(exc),
                "freshnessVerified": True,
                "sourceInputsAvailable": True,
                "addressResolver": False,
                "actionable": False,
                "promotesBuildability": False,
            }
            try:
                summary_path.write_text(json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            return failure

    if existing:
        result = dict(existing)
        result["freshnessVerified"] = False
        result["sourceInputsAvailable"] = False
        return result
    return {}


def _safe_identity(row: dict[str, Any]) -> dict[str, Any] | None:
    if bool(row.get("promotesBuildability")) or bool(row.get("actionable")) or bool(row.get("buildable")):
        return None
    if row.get("rva") not in (None, "", 0, "0", "0x0") or bool(row.get("addressConfirmed")):
        return None
    status = str(row.get("status") or "UNRESOLVED_NO_RVA")
    if status in {"UNRESOLVED_NO_RVA", "METADATA_TOKEN_CONFLICT_NO_RVA"} or bool(row.get("metadataTokenConflict")):
        return None
    return {
        "engine": "il2cpp.metadata-identity-embedded",
        "status": status,
        "class": row.get("class"),
        "methodName": row.get("methodName"),
        "metadataMethodNamePresent": bool(row.get("metadataMethodNamePresent")),
        "metadataQualifiedMethodPresent": bool(row.get("metadataQualifiedMethodPresent")),
        "metadataToken": row.get("metadataToken"),
        "metadataTokenConfirmed": bool(row.get("metadataTokenConfirmed")),
        "metadataTokenConflict": False,
        "metadataResolvedClass": row.get("metadataResolvedClass"),
        "metadataResolvedMethodName": row.get("metadataResolvedMethodName"),
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }


def _safe_identity_conflict(row: dict[str, Any]) -> dict[str, Any] | None:
    if str(row.get("status") or "") != "METADATA_TOKEN_CONFLICT_NO_RVA" and not bool(row.get("metadataTokenConflict")):
        return None
    if bool(row.get("promotesBuildability")) or bool(row.get("actionable")) or bool(row.get("buildable")):
        return None
    return {
        "engine": "il2cpp.metadata-identity-embedded",
        "status": "METADATA_TOKEN_CONFLICT_NO_RVA",
        "class": row.get("class"),
        "methodName": row.get("methodName"),
        "metadataToken": row.get("metadataToken"),
        "metadataTokenConfirmed": False,
        "metadataTokenConflict": True,
        "metadataResolvedClass": row.get("metadataResolvedClass"),
        "metadataResolvedMethodName": row.get("metadataResolvedMethodName"),
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }


def _identity_indexes(rows: list[dict[str, Any]]) -> tuple[
    dict[str, dict[str, Any]],
    dict[tuple[str, str], list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, dict[str, Any]],
]:
    by_id: dict[str, dict[str, Any]] = {}
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    conflicts_by_id: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row_id = raw.get("id")
        conflict = _safe_identity_conflict(raw)
        if conflict is not None:
            if row_id not in (None, ""):
                conflicts_by_id[str(row_id)] = conflict
            continue
        safe = _safe_identity(raw)
        if safe is None:
            continue
        if row_id not in (None, ""):
            by_id[str(row_id)] = safe
        method = str(safe.get("methodName") or "").strip().casefold()
        cls = str(safe.get("class") or "").strip().replace("/", ".").casefold()
        if method:
            by_name.setdefault(method, []).append(safe)
        if method and cls:
            by_pair.setdefault((cls, method), []).append(safe)
            short = cls.rsplit(".", 1)[-1]
            if short != cls:
                by_pair.setdefault((short, method), []).append(safe)
    return by_id, by_pair, by_name, conflicts_by_id


def _finding_rva(finding: dict[str, Any]) -> str:
    locator = finding.get("locator")
    if isinstance(locator, dict):
        return _norm_hex(locator.get("rva"))
    return ""


def _finding_method_id(finding: dict[str, Any]) -> str:
    locator = finding.get("locator")
    if isinstance(locator, dict):
        for key in ("methodId", "metadataMethodId", "methodIndex"):
            if locator.get(key) not in (None, ""):
                return str(locator.get(key))
    linked = finding.get("linkedMethods")
    if isinstance(linked, list) and len(linked) == 1 and isinstance(linked[0], dict):
        for key in ("id", "methodId", "metadataMethodId"):
            value = linked[0].get(key)
            if value not in (None, ""):
                return str(value)
    return ""


def _finding_class_method(finding: dict[str, Any]) -> tuple[str, str]:
    locator = finding.get("locator")
    if not isinstance(locator, dict):
        return "", ""
    cls = str(locator.get("class") or locator.get("className") or "").strip().replace("/", ".").casefold()
    method = str(locator.get("method") or locator.get("methodName") or "").strip()
    if "::" in method:
        method = method.rsplit("::", 1)[1]
    if "(" in method:
        method = method.split("(", 1)[0]
    return cls, method.strip().casefold()


def _append_artifact_guide(report: dict[str, Any], root: Path) -> None:
    guide = report.get("artifactGuide")
    if not isinstance(guide, list):
        guide = []
        report["artifactGuide"] = guide
    present = {str(row.get("file")) for row in guide if isinstance(row, dict)}
    specs = [
        ("runtime-session.json", "Read-only procfs runtime snapshot", "PID/UID, threads, file mappings and observed module load bases."),
        ("runtime-correlation.json", "Static RVA → observed runtime VA correlation", "Use as runtime layout corroboration; it does not prove method execution or patch safety."),
        ("il2cpp-crosscheck.json", "Independent IL2CPP metadata + ELF structural summary", "Checks metadata layout and executable ELF ranges without claiming an independent CodeRegistration mapping."),
        ("il2cpp-crosscheck.methods.jsonl", "Per-method IL2CPP structural cross-check", "Shows whether method-name presence and executable RVA range are independently present for each catalog row."),
        ("il2cpp-metadata-identity.json", "No-RVA IL2CPP metadata identity summary", "Confirms method/token identity from global metadata while leaving native address unresolved."),
        ("il2cpp-metadata-identity.methods.jsonl", "Per-method no-RVA metadata identity", "Distinguishes token, exact declaring-type+method, name-only, conflict and unresolved evidence without inventing RVA."),
    ]
    for name, purpose, use in specs:
        if name in present:
            continue
        path = root / name
        guide.append({
            "file": name,
            "available": path.exists(),
            "bytes": path.stat().st_size if path.is_file() else None,
            "purpose": purpose,
            "whenToUse": use,
        })


def _append_markdown(path: Path, report: dict[str, Any]) -> None:
    if not path.is_file():
        path.write_text("# ModKit connected report\n", encoding="utf-8")
    lines = [
        "",
        "## Runtime / IL2CPP corroboration",
        "",
        f"- Runtime-observed findings: {report.get('runtimeObservedFindings', 0)}",
        f"- IL2CPP structural findings: {report.get('il2cppStructuralFindings', 0)}",
        f"- IL2CPP metadata+executable-range both present: {report.get('il2cppStructuralBothFindings', 0)}",
        f"- No-RVA metadata identity confirmed: {report.get('metadataIdentityConfirmedFindings', 0)}",
        f"- No-RVA qualified class+method confirmed: {report.get('metadataQualifiedIdentityFindings', 0)}",
        f"- No-RVA token identity confirmed: {report.get('metadataTokenIdentityFindings', 0)}",
        f"- No-RVA token conflicts (blocked): {report.get('metadataTokenConflictFindings', 0)}",
        "",
        "> Runtime VA means the RVA landed in an observed procfs module mapping. It is not proof that the method executed.",
        "",
        "> IL2CPP structural cross-check verifies metadata method-name presence and executable ELF range independently. It does not independently prove the method-to-RVA association and never promotes buildability.",
        "",
        "> Metadata identity can confirm Class::Method or a unique method token even when RVA is absent. Identity evidence never invents a native address. Token/name/class disagreement is reported as a conflict and blocked fail-closed.",
        "",
    ]
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        runtime = finding.get("runtimeObservation")
        il2cpp = finding.get("il2cppStructural")
        identity = finding.get("metadataIdentity")
        conflict = finding.get("metadataIdentityConflict")
        if not any(isinstance(value, dict) for value in (runtime, il2cpp, identity, conflict)):
            continue
        lines.append(f"### Corroboration · {finding.get('title') or finding.get('id') or 'Finding'}")
        if isinstance(runtime, dict):
            lines.append(
                "- Runtime: "
                + f"RVA {runtime.get('rvaHex') or '?'} → VA {runtime.get('runtimeVaHex') or '?'}"
                + f" · module {runtime.get('moduleBasename') or runtime.get('modulePath') or '?'}"
                + f" · mapped={runtime.get('mapped')} · perms={runtime.get('mappingPerms') or '?'}"
            )
        if isinstance(il2cpp, dict):
            lines.append(
                "- IL2CPP structural: "
                + f"{il2cpp.get('status')} · metadata-name={il2cpp.get('metadataMethodNamePresent')}"
                + f" · executable-range={il2cpp.get('executableElfRangePresent')}"
                + " · associationConfirmed=false"
            )
        if isinstance(identity, dict):
            token = identity.get("metadataToken") or "?"
            lines.append(
                "- IL2CPP metadata identity: "
                + f"{identity.get('status')} · class={identity.get('class') or '?'}"
                + f" · method={identity.get('methodName') or '?'} · token={token}"
                + " · RVA=UNRESOLVED · actionable=false · buildable=false"
            )
        if isinstance(conflict, dict):
            lines.append(
                "- IL2CPP metadata identity CONFLICT: "
                + f"token={conflict.get('metadataToken') or '?'}"
                + f" · catalog={conflict.get('class') or '?'}::{conflict.get('methodName') or '?'}"
                + f" · metadata={conflict.get('metadataResolvedClass') or '?'}::{conflict.get('metadataResolvedMethodName') or '?'}"
                + " · blocked=true · RVA=UNRESOLVED · actionable=false · buildable=false"
            )
        lines.append("")
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def build_connected_report(workdir: str | Path, output_json: str | Path | None = None,
                           output_md: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    report = _build_base(root, None, output_md)
    report["schema"] = SCHEMA

    runtime_summary = _json(root / "runtime-correlation.json")
    runtime_by_id, runtime_by_rva = _runtime_indexes(runtime_summary)

    il2cpp_summary = _ensure_il2cpp_crosscheck(root)
    il2cpp_rows = _jsonl(root / "il2cpp-crosscheck.methods.jsonl") if il2cpp_summary and not il2cpp_summary.get("error") else []
    il2cpp_by_rva = _il2cpp_index(il2cpp_rows)

    identity_summary = _ensure_metadata_identity(root)
    identity_rows = _jsonl(root / "il2cpp-metadata-identity.methods.jsonl") if identity_summary and not identity_summary.get("error") else []
    identity_by_id, identity_by_pair, identity_by_name, identity_conflicts_by_id = _identity_indexes(identity_rows)

    runtime_count = 0
    il2cpp_count = 0
    il2cpp_both = 0
    identity_count = 0
    identity_qualified_count = 0
    identity_token_count = 0
    identity_conflict_count = 0

    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        original_buildable = bool(finding.get("buildable"))
        original_actionable = bool(finding.get("actionable"))
        card_id = finding.get("id")
        rva = _finding_rva(finding)

        runtime = runtime_by_id.get(str(card_id)) if card_id not in (None, "") else None
        if runtime is None and rva and len(runtime_by_rva.get(rva, [])) == 1:
            runtime = runtime_by_rva[rva][0]
        if isinstance(runtime, dict):
            finding["runtimeObservation"] = runtime
            finding["runtimeObserved"] = bool(runtime.get("mapped"))
            if finding["runtimeObserved"]:
                runtime_count += 1

        il2cpp = il2cpp_by_rva.get(rva) if rva else None
        if isinstance(il2cpp, dict):
            finding["il2cppStructural"] = il2cpp
            finding["il2cppStructuralObserved"] = bool(
                il2cpp.get("metadataMethodNamePresent") or il2cpp.get("executableElfRangePresent")
            )
            if finding["il2cppStructuralObserved"]:
                il2cpp_count += 1
            if il2cpp.get("status") == "STRUCTURAL_BOTH_PRESENT":
                il2cpp_both += 1

        if not rva:
            identity = None
            method_id = _finding_method_id(finding)
            if method_id and method_id in identity_conflicts_by_id:
                finding["metadataIdentityConflict"] = identity_conflicts_by_id[method_id]
                finding["metadataIdentityConfirmed"] = False
                identity_conflict_count += 1
            else:
                if method_id:
                    identity = identity_by_id.get(method_id)
                if identity is None:
                    cls, method = _finding_class_method(finding)
                    if cls and method:
                        matches = identity_by_pair.get((cls, method), [])
                        if len(matches) == 1:
                            identity = matches[0]
                        if identity is None:
                            short = cls.rsplit(".", 1)[-1]
                            if short != cls:
                                matches = identity_by_pair.get((short, method), [])
                                if len(matches) == 1:
                                    identity = matches[0]
                    elif method and len(identity_by_name.get(method, [])) == 1:
                        identity = identity_by_name[method][0]
                if isinstance(identity, dict):
                    finding["metadataIdentity"] = identity
                    finding["metadataIdentityConfirmed"] = bool(
                        identity.get("metadataTokenConfirmed")
                        or identity.get("metadataQualifiedMethodPresent")
                        or identity.get("metadataMethodNamePresent")
                    )
                    if finding["metadataIdentityConfirmed"]:
                        identity_count += 1
                    if identity.get("metadataQualifiedMethodPresent"):
                        identity_qualified_count += 1
                    if identity.get("metadataTokenConfirmed"):
                        identity_token_count += 1

        finding["buildable"] = original_buildable
        finding["actionable"] = original_actionable

    identity_counts = identity_summary.get("counts") if isinstance(identity_summary.get("counts"), dict) else {}
    source_conflicts = int(identity_counts.get("tokenConflictNoRva") or 0)

    report["runtimeObservedFindings"] = runtime_count
    report["il2cppStructuralFindings"] = il2cpp_count
    report["il2cppStructuralBothFindings"] = il2cpp_both
    report["metadataIdentityConfirmedFindings"] = identity_count
    report["metadataQualifiedIdentityFindings"] = identity_qualified_count
    report["metadataTokenIdentityFindings"] = identity_token_count
    report["metadataTokenConflictFindings"] = identity_conflict_count
    report["metadataTokenConflictRows"] = source_conflicts

    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        report["summary"] = summary
    summary["runtimeObservedFindings"] = runtime_count
    summary["il2cppStructuralFindings"] = il2cpp_count
    summary["il2cppStructuralBothFindings"] = il2cpp_both
    summary["metadataIdentityConfirmedFindings"] = identity_count
    summary["metadataQualifiedIdentityFindings"] = identity_qualified_count
    summary["metadataTokenIdentityFindings"] = identity_token_count
    summary["metadataTokenConflictFindings"] = identity_conflict_count
    summary["metadataTokenConflictRows"] = source_conflicts

    report["corroboration"] = {
        "runtime": {
            "available": bool(runtime_summary),
            "schema": runtime_summary.get("schema"),
            "mode": runtime_summary.get("mode"),
            "correlationCount": int(runtime_summary.get("correlationCount") or 0),
            "mappedRuntimeVaCount": int(runtime_summary.get("mappedRuntimeVaCount") or 0),
            "writesTargetMemory": False,
            "injectsCode": False,
            "promotesBuildability": False,
        },
        "il2cppStructural": {
            "available": bool(il2cpp_summary),
            "schema": il2cpp_summary.get("schema"),
            "engine": il2cpp_summary.get("engine"),
            "counts": il2cpp_summary.get("counts"),
            "freshnessVerified": bool(il2cpp_summary.get("freshnessVerified")),
            "sourceInputsAvailable": bool(il2cpp_summary.get("sourceInputsAvailable")),
            "confirmsMethodToRvaAssociation": False,
            "executesTargetCode": False,
            "promotesBuildability": False,
        },
        "il2cppMetadataIdentity": {
            "available": bool(identity_summary),
            "schema": identity_summary.get("schema"),
            "engine": identity_summary.get("engine"),
            "metadataVersion": identity_summary.get("metadataVersion"),
            "typeLayout": identity_summary.get("typeLayout"),
            "typeLayoutScore": identity_summary.get("typeLayoutScore"),
            "uniqueMethodTokenCount": int(identity_summary.get("uniqueMethodTokenCount") or 0),
            "counts": identity_summary.get("counts"),
            "freshnessVerified": bool(identity_summary.get("freshnessVerified")),
            "sourceInputsAvailable": bool(identity_summary.get("sourceInputsAvailable")),
            "tokenConflictRows": source_conflicts,
            "addressResolver": False,
            "actionable": False,
            "promotesBuildability": False,
        },
    }

    semantics = report.get("evidenceSemantics")
    if not isinstance(semantics, dict):
        semantics = {}
        report["evidenceSemantics"] = semantics
    semantics["PROCFS_MODULE_LAYOUT"] = (
        "Observed process module mapping/load base. RVA→runtime VA correlation is runtime layout evidence, not proof of code execution."
    )
    semantics["IL2CPP_STRUCTURAL_CROSSCHECK"] = (
        "Metadata method-name presence and executable ELF range are checked independently; this backend does not confirm the method-to-RVA association."
    )
    semantics["IL2CPP_METADATA_IDENTITY_NO_RVA"] = (
        "Global metadata can confirm method token/name/declaring type while RVA remains unresolved. This evidence is non-actionable and cannot become a patch binding."
    )
    semantics["IL2CPP_METADATA_TOKEN_CONFLICT_NO_RVA"] = (
        "A unique metadata token disagrees with catalogue class or method identity. The row is reported as conflict evidence, never as confirmation, and remains non-actionable/non-buildable."
    )
    semantics["corroborationBuildability"] = (
        "Runtime, IL2CPP structural, and metadata-identity corroboration never make a finding buildable; signed build still requires validated local executable binding and successful preflight."
    )

    _append_artifact_guide(report, root)

    if output_json:
        Path(output_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_md:
        _append_markdown(Path(output_md), report)
    return report
