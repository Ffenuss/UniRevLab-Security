"""Connected report 1.2: base report plus read-only runtime and IL2CPP corroboration.

The v1.1 report builder remains available for compatibility. This wrapper enriches its
finding rows without changing their buildability or method-link status. Runtime procfs
layout, IL2CPP metadata/ELF structural checks, and no-RVA metadata identity are evidence
only; none of them can create an executable patch binding.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile.connected_report import build_connected_report as _build_base

SCHEMA = "modkit-connected-report-1.2"


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


def _ensure_metadata_identity(root: Path) -> dict[str, Any]:
    summary_path = root / "il2cpp-metadata-identity.json"
    rows_path = root / "il2cpp-metadata-identity.methods.jsonl"
    existing = _json(summary_path)
    if existing and rows_path.is_file():
        return existing
    if not (root / "metadata.bin").is_file() or not (root / "analysis.methods.jsonl").is_file():
        return {}
    try:
        from modkit.mobile.il2cpp_metadata_identity import build_workspace_identity
        return build_workspace_identity(root, summary_path)
    except Exception as exc:
        failure = {
            "schema": "modkit-il2cpp-metadata-identity-error-1.0",
            "engine": "il2cpp.metadata-identity-embedded",
            "error": str(exc),
            "addressResolver": False,
            "promotesBuildability": False,
        }
        try:
            summary_path.write_text(json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return failure


def _safe_identity(row: dict[str, Any]) -> dict[str, Any] | None:
    if bool(row.get("promotesBuildability")) or bool(row.get("actionable")) or bool(row.get("buildable")):
        return None
    if row.get("rva") not in (None, "", 0, "0", "0x0") or bool(row.get("addressConfirmed")):
        return None
    status = str(row.get("status") or "UNRESOLVED_NO_RVA")
    return {
        "engine": "il2cpp.metadata-identity-embedded",
        "status": status,
        "class": row.get("class"),
        "methodName": row.get("methodName"),
        "metadataMethodNamePresent": bool(row.get("metadataMethodNamePresent")),
        "metadataQualifiedMethodPresent": bool(row.get("metadataQualifiedMethodPresent")),
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }


def _identity_indexes(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_qualified: dict[tuple[str, str], dict[str, Any]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        safe = _safe_identity(raw)
        if safe is None or str(safe.get("status")) == "UNRESOLVED_NO_RVA":
            continue
        row_id = raw.get("id")
        if row_id not in (None, ""):
            by_id[str(row_id)] = safe
        method = str(safe.get("methodName") or "").strip().casefold()
        cls = str(safe.get("class") or "").strip().replace("/", ".").casefold()
        if method:
            by_name.setdefault(method, []).append(safe)
        if method and cls:
            by_qualified[(cls, method)] = safe
            by_qualified[(cls.rsplit(".", 1)[-1], method)] = safe
    return by_id, by_qualified, by_name


def _finding_rva(finding: dict[str, Any]) -> str:
    locator = finding.get("locator")
    if isinstance(locator, dict):
        return _norm_hex(locator.get("rva"))
    return ""


def _finding_method_id(finding: dict[str, Any]) -> str:
    locator = finding.get("locator")
    if isinstance(locator, dict) and locator.get("methodId") not in (None, ""):
        return str(locator.get("methodId"))
    linked = finding.get("linkedMethods")
    if isinstance(linked, list) and len(linked) == 1 and isinstance(linked[0], dict):
        value = linked[0].get("id")
        if value not in (None, ""):
            return str(value)
    return ""


def _finding_class_method(finding: dict[str, Any]) -> tuple[str, str]:
    locator = finding.get("locator")
    if not isinstance(locator, dict):
        return "", ""
    cls = str(locator.get("class") or "").strip().replace("/", ".").casefold()
    method = str(locator.get("method") or "").strip()
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
        ("il2cpp-crosscheck.methods.jsonl", "Per-method IL2CPP structural cross-check", "Use to see whether method-name presence and executable RVA range are independently present for each catalog row."),
        ("il2cpp-metadata-identity.json", "No-RVA IL2CPP metadata identity summary", "Confirms method identity from global metadata while leaving native address unresolved."),
        ("il2cpp-metadata-identity.methods.jsonl", "Per-method no-RVA metadata identity", "Distinguishes exact declaring-type+method confirmation from weaker method-name-only presence."),
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
        "",
        "> Runtime VA means the RVA landed in an observed procfs module mapping. It is not proof that the method executed.",
        "",
        "> IL2CPP structural cross-check verifies metadata method-name presence and executable ELF range independently. It does not independently prove the method-to-RVA association and never promotes buildability.",
        "",
        "> Metadata identity can confirm Class::Method even when RVA is absent. That resolves identity only; the native address remains unresolved, non-actionable and non-buildable.",
        "",
    ]
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        runtime = finding.get("runtimeObservation")
        il2cpp = finding.get("il2cppStructural")
        identity = finding.get("metadataIdentity")
        if not isinstance(runtime, dict) and not isinstance(il2cpp, dict) and not isinstance(identity, dict):
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
            lines.append(
                "- IL2CPP metadata identity: "
                + f"{identity.get('status')} · class={identity.get('class') or '?'}"
                + f" · method={identity.get('methodName') or '?'} · RVA=UNRESOLVED · buildable=false"
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
    il2cpp_summary = _json(root / "il2cpp-crosscheck.json")
    il2cpp_by_rva = _il2cpp_index(_jsonl(root / "il2cpp-crosscheck.methods.jsonl"))
    identity_summary = _ensure_metadata_identity(root)
    identity_by_id, identity_by_qualified, identity_by_name = _identity_indexes(
        _jsonl(root / "il2cpp-metadata-identity.methods.jsonl")
    )

    runtime_count = 0
    il2cpp_count = 0
    il2cpp_both = 0
    identity_count = 0
    identity_qualified_count = 0
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        original_buildable = bool(finding.get("buildable"))
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

        # Metadata identity is only relevant when no native RVA was resolved.
        if not rva:
            identity = None
            method_id = _finding_method_id(finding)
            if method_id:
                identity = identity_by_id.get(method_id)
            if identity is None:
                cls, method = _finding_class_method(finding)
                if cls and method:
                    identity = identity_by_qualified.get((cls, method)) or identity_by_qualified.get((cls.rsplit(".", 1)[-1], method))
                elif method and len(identity_by_name.get(method, [])) == 1:
                    identity = identity_by_name[method][0]
            if isinstance(identity, dict):
                finding["metadataIdentity"] = identity
                finding["metadataIdentityConfirmed"] = bool(
                    identity.get("metadataQualifiedMethodPresent") or identity.get("metadataMethodNamePresent")
                )
                if finding["metadataIdentityConfirmed"]:
                    identity_count += 1
                if identity.get("metadataQualifiedMethodPresent"):
                    identity_qualified_count += 1

        finding["buildable"] = original_buildable

    report["runtimeObservedFindings"] = runtime_count
    report["il2cppStructuralFindings"] = il2cpp_count
    report["il2cppStructuralBothFindings"] = il2cpp_both
    report["metadataIdentityConfirmedFindings"] = identity_count
    report["metadataQualifiedIdentityFindings"] = identity_qualified_count
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        report["summary"] = summary
    summary["runtimeObservedFindings"] = runtime_count
    summary["il2cppStructuralFindings"] = il2cpp_count
    summary["il2cppStructuralBothFindings"] = il2cpp_both
    summary["metadataIdentityConfirmedFindings"] = identity_count
    summary["metadataQualifiedIdentityFindings"] = identity_qualified_count

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
            "confirmsMethodToRvaAssociation": False,
            "executesTargetCode": False,
            "promotesBuildability": False,
        },
        "il2cppMetadataIdentity": {
            "available": bool(identity_summary),
            "schema": identity_summary.get("schema"),
            "engine": identity_summary.get("engine"),
            "typeLayout": identity_summary.get("typeLayout"),
            "counts": identity_summary.get("counts"),
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
        "Global metadata confirms method identity/name while RVA remains unresolved. This evidence is non-actionable and cannot become a patch binding."
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
