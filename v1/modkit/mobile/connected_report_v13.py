"""Connected report 1.3: v1.2 report plus fail-closed IL2CPP metadata identity.

This layer exists for the common case where global-metadata.dat can independently
confirm a method identity but the native RVA is absent.  Identity evidence never
invents an address and never changes actionable/buildable state.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile.connected_report_v12 import build_connected_report as _build_v12

SCHEMA = "modkit-connected-report-1.3"


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    out.append(row)
    except Exception:
        return []
    return out


def _norm_name(value: Any) -> str:
    text = str(value or "").strip()
    if "::" in text:
        text = text.rsplit("::", 1)[1]
    if "(" in text:
        text = text.split("(", 1)[0]
    return text.strip().casefold()


def _norm_class(value: Any) -> str:
    return str(value or "").strip().replace("/", ".").casefold()


def _ensure_identity(root: Path) -> dict[str, Any]:
    summary = root / "il2cpp-metadata-identity.json"
    rows = root / "il2cpp-metadata-identity.methods.jsonl"
    existing = _json(summary)
    if existing and rows.is_file():
        return existing
    if not (root / "metadata.bin").is_file() or not (root / "analysis.methods.jsonl").is_file():
        return {}
    try:
        from modkit.mobile.il2cpp_metadata_identity import build_workspace_identity
        return build_workspace_identity(root, summary)
    except Exception as exc:
        value = {
            "schema": "modkit-il2cpp-metadata-identity-error-1.0",
            "engine": "il2cpp.metadata-identity-embedded",
            "error": str(exc),
            "addressResolver": False,
            "actionable": False,
            "promotesBuildability": False,
        }
        try:
            summary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return value


def _safe_identity(row: dict[str, Any]) -> dict[str, Any] | None:
    if bool(row.get("promotesBuildability")) or bool(row.get("addressConfirmed")):
        return None
    if bool(row.get("actionable")) or bool(row.get("buildable")):
        return None
    status = str(row.get("status") or "UNRESOLVED_NO_RVA")
    if status == "UNRESOLVED_NO_RVA":
        return None
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


def _indexes(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        safe = _safe_identity(row)
        if safe is None:
            continue
        row_id = row.get("id")
        if row_id not in (None, ""):
            by_id[str(row_id)] = safe
        method = _norm_name(row.get("methodName"))
        cls = _norm_class(row.get("class"))
        if method:
            by_name.setdefault(method, []).append(safe)
        if method and cls:
            by_pair.setdefault((cls, method), []).append(safe)
            by_pair.setdefault((cls.rsplit(".", 1)[-1], method), []).append(safe)
    return by_id, by_pair, by_name


def _finding_identity(finding: dict[str, Any], indexes: tuple[dict[str, dict[str, Any]], dict[tuple[str, str], list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]) -> dict[str, Any] | None:
    by_id, by_pair, by_name = indexes
    locator = finding.get("locator") if isinstance(finding.get("locator"), dict) else {}
    method_id = locator.get("methodId")
    if method_id not in (None, "") and str(method_id) in by_id:
        return by_id[str(method_id)]

    for method in finding.get("linkedMethods") or []:
        if not isinstance(method, dict):
            continue
        mid = method.get("id")
        if mid not in (None, "") and str(mid) in by_id:
            return by_id[str(mid)]

    method_name = _norm_name(locator.get("method") or locator.get("methodName") or finding.get("title"))
    class_name = _norm_class(locator.get("class") or locator.get("className"))
    if not class_name:
        linked = finding.get("linkedMethods") or []
        if len(linked) == 1 and isinstance(linked[0], dict):
            class_name = _norm_class(linked[0].get("class") or linked[0].get("className") or linked[0].get("declaringType"))
            if not method_name:
                method_name = _norm_name(linked[0].get("name") or linked[0].get("method") or linked[0].get("methodName"))

    if method_name and class_name:
        matches = by_pair.get((class_name, method_name), [])
        if len(matches) == 1:
            return matches[0]
        matches = by_pair.get((class_name.rsplit(".", 1)[-1], method_name), [])
        if len(matches) == 1:
            return matches[0]
    if method_name and len(by_name.get(method_name, [])) == 1:
        return by_name[method_name][0]
    return None


def _append_guide(report: dict[str, Any], root: Path) -> None:
    guide = report.get("artifactGuide")
    if not isinstance(guide, list):
        guide = []
        report["artifactGuide"] = guide
    present = {str(row.get("file")) for row in guide if isinstance(row, dict)}
    for name, purpose, use in (
        (
            "il2cpp-metadata-identity.json",
            "IL2CPP no-RVA metadata identity summary",
            "Shows how many catalogue methods without RVA are independently present in global metadata; this is not an address resolver.",
        ),
        (
            "il2cpp-metadata-identity.methods.jsonl",
            "Per-method no-RVA metadata identity evidence",
            "Use to distinguish exact Class::Method metadata confirmation from name-only or unresolved rows while keeping RVA unresolved.",
        ),
    ):
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
        "## IL2CPP metadata identity without RVA",
        "",
        f"- Metadata-identity findings: {report.get('metadataIdentityFindings', 0)}",
        f"- Exact Class::Method confirmations without RVA: {report.get('metadataQualifiedNoRvaFindings', 0)}",
        "",
        "> Metadata identity confirms that a method exists in global-metadata.dat. It does not invent a native RVA and never makes the finding actionable or buildable.",
        "",
    ]
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        identity = finding.get("metadataIdentity")
        if not isinstance(identity, dict):
            continue
        lines.append(f"### Metadata identity · {finding.get('title') or finding.get('id') or 'Finding'}")
        lines.append(
            "- "
            + f"status={identity.get('status')} · class={identity.get('class') or '?'}"
            + f" · method={identity.get('methodName') or '?'}"
            + f" · qualified={identity.get('metadataQualifiedMethodPresent')}"
            + " · addressConfirmed=false · RVA=unresolved · actionable=false · buildable=false"
        )
        lines.append("")
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def build_connected_report(workdir: str | Path, output_json: str | Path | None = None,
                           output_md: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    report = _build_v12(root, None, output_md)
    report["schema"] = SCHEMA

    identity_summary = _ensure_identity(root)
    identity_rows = _jsonl(root / "il2cpp-metadata-identity.methods.jsonl") if identity_summary and not identity_summary.get("error") else []
    indexes = _indexes(identity_rows)

    observed = 0
    qualified = 0
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        original_buildable = bool(finding.get("buildable"))
        original_actionable = bool(finding.get("actionable"))
        identity = _finding_identity(finding, indexes)
        if isinstance(identity, dict):
            finding["metadataIdentity"] = identity
            finding["metadataIdentityObserved"] = True
            observed += 1
            if identity.get("metadataQualifiedMethodPresent"):
                qualified += 1
        else:
            finding["metadataIdentityObserved"] = False
        finding["buildable"] = original_buildable
        finding["actionable"] = original_actionable

    report["metadataIdentityFindings"] = observed
    report["metadataQualifiedNoRvaFindings"] = qualified
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        report["summary"] = summary
    summary["metadataIdentityFindings"] = observed
    summary["metadataQualifiedNoRvaFindings"] = qualified

    corroboration = report.get("corroboration")
    if not isinstance(corroboration, dict):
        corroboration = {}
        report["corroboration"] = corroboration
    corroboration["il2cppMetadataIdentity"] = {
        "available": bool(identity_summary),
        "schema": identity_summary.get("schema"),
        "engine": identity_summary.get("engine"),
        "typeLayout": identity_summary.get("typeLayout"),
        "counts": identity_summary.get("counts"),
        "addressResolver": False,
        "executesTargetCode": False,
        "writesTarget": False,
        "actionable": False,
        "promotesBuildability": False,
    }

    semantics = report.get("evidenceSemantics")
    if not isinstance(semantics, dict):
        semantics = {}
        report["evidenceSemantics"] = semantics
    semantics["IL2CPP_METADATA_IDENTITY_NO_RVA"] = (
        "Confirms method identity from global metadata while leaving native RVA unresolved; evidence is non-actionable and cannot promote buildability."
    )
    _append_guide(report, root)

    if output_json:
        Path(output_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_md:
        _append_markdown(Path(output_md), report)
    return report
