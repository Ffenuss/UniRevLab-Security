"""Incremental target fingerprint cache for ModKit Simple Mode.

This cache never changes analyzer semantics. It only proves that the selected
APK/split set is byte-for-byte unchanged and that the core derived artifacts which
would be reused are still the exact files recorded by the previous completed pass.
A changed/missing target or changed core output fails closed to a fresh analysis.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-simple-cache-1.0"
_OUTPUTS = (
    "installed-scan.json",
    "analysis.json",
    "analysis.gameplay-coverage.json",
    "analysis.methods.jsonl",
    "re-analysis.json",
    "re-analysis.ui.json",
    "re-analysis.menu.json",
    "menu-spec.json",
    "security-surfaces.json",
    "simple-catalog.json",
)
_ANALYSIS_CORE = ("re-analysis.json",)
_IL2CPP_CORE = ("analysis.json", "analysis.methods.jsonl")
_SECURITY_CORE = ("security-surfaces.json",)


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _targets(root: Path) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        try:
            key = str(path.resolve())
        except Exception:
            key = str(path)
        if path.is_file() and key not in seen:
            seen.add(key)
            out.append(path)

    target = _json(root / "installed-target.json")
    if isinstance(target, dict):
        for row in target.get("splits", []) or []:
            if isinstance(row, dict) and row.get("path"):
                add(Path(str(row["path"])))
    installed = root / "installed-apks"
    if installed.is_dir():
        for path in sorted(installed.glob("*.apk")):
            add(path)
    add(root / "game.apk")
    return out


def _target_digest(rows: list[dict]) -> str:
    material = json.dumps(
        [(r["path"], r["size"], r["sha256"]) for r in rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _previous_outputs(previous: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(previous, dict):
        return out
    for row in previous.get("outputs", []) or []:
        if isinstance(row, dict) and row.get("name"):
            out[str(row["name"])] = row
    return out


def _verify_outputs(root: Path, previous: Any, names: tuple[str, ...]) -> tuple[bool, list[str], list[dict[str, Any]]]:
    recorded = _previous_outputs(previous)
    changed: list[str] = []
    rows: list[dict[str, Any]] = []
    for name in names:
        path = root / name
        prior = recorded.get(name)
        if not path.is_file():
            changed.append(name + ":missing")
            rows.append({"name": name, "present": False})
            continue
        digest = _sha256(path)
        row = {"name": name, "present": True, "size": path.stat().st_size, "sha256": digest}
        rows.append(row)
        if not prior or not prior.get("sha256"):
            changed.append(name + ":unrecorded")
        elif str(prior.get("sha256")) != digest:
            changed.append(name + ":sha256-changed")
    return not changed, changed, rows


def plan_workspace(workdir: str | Path, manifest_path: str | Path | None = None) -> str:
    root = Path(workdir)
    manifest = Path(manifest_path) if manifest_path else root / "simple-cache.json"
    previous = _json(manifest)
    prev_rows = {}
    if isinstance(previous, dict):
        for row in previous.get("targets", []) or []:
            if isinstance(row, dict) and row.get("path"):
                prev_rows[str(row["path"])] = row

    rows: list[dict] = []
    changed: list[str] = []
    reused_hashes = 0
    for path in _targets(root):
        st = path.stat()
        key = str(path.resolve())
        prev = prev_rows.get(key, {})
        stat_same = (
            int(prev.get("size", -1)) == st.st_size
            and int(prev.get("mtimeNs", -1)) == st.st_mtime_ns
            and bool(prev.get("sha256"))
        )
        digest = str(prev.get("sha256")) if stat_same else _sha256(path)
        if stat_same:
            reused_hashes += 1
        if not prev or str(prev.get("sha256", "")) != digest:
            changed.append(path.name)
        rows.append({
            "path": key,
            "name": path.name,
            "size": st.st_size,
            "mtimeNs": st.st_mtime_ns,
            "sha256": digest,
            "hashReused": stat_same,
        })

    digest = _target_digest(rows) if rows else ""
    previous_digest = str(previous.get("targetDigest", "")) if isinstance(previous, dict) else ""
    unchanged = bool(rows and previous_digest and digest == previous_digest)

    analysis_names = list(_ANALYSIS_CORE)
    if (root / "metadata.bin").is_file() and (root / "library.so").is_file():
        analysis_names.extend(_IL2CPP_CORE)
    analysis_ok, analysis_changed, analysis_rows = _verify_outputs(root, previous, tuple(analysis_names))
    security_ok, security_changed, security_rows = _verify_outputs(root, previous, _SECURITY_CORE)

    return json.dumps({
        "schema": SCHEMA,
        "targetDigest": digest,
        "previousTargetDigest": previous_digest,
        "unchanged": unchanged,
        "targets": rows,
        "targetCount": len(rows),
        "changedFiles": changed,
        "reusedHashCount": reused_hashes,
        "analysisOutputsUnchanged": bool(unchanged and analysis_ok),
        "securityOutputsUnchanged": bool(unchanged and security_ok),
        "changedAnalysisOutputs": analysis_changed,
        "changedSecurityOutputs": security_changed,
        "analysisOutputs": analysis_rows,
        "securityOutputs": security_rows,
    }, ensure_ascii=False)


def record_workspace(workdir: str | Path, manifest_path: str | Path, plan_json: str) -> str:
    root = Path(workdir)
    manifest = Path(manifest_path)
    plan = json.loads(plan_json)
    fingerprinted = set(_ANALYSIS_CORE + _IL2CPP_CORE + _SECURITY_CORE)
    outputs = []
    for name in _OUTPUTS:
        path = root / name
        if path.is_file():
            st = path.stat()
            row = {"name": name, "size": st.st_size, "mtimeNs": st.st_mtime_ns}
            if name in fingerprinted:
                row["sha256"] = _sha256(path)
            outputs.append(row)
    saved = {
        "schema": SCHEMA,
        "targetDigest": plan.get("targetDigest", ""),
        "targets": plan.get("targets", []),
        "outputs": outputs,
        "policy": {
            "reuseOnlyWhenTargetDigestMatches": True,
            "changedTargetForcesFreshPipeline": True,
            "changedCoreOutputForcesFreshPipeline": True,
            "analysisMethodsFingerprintRequiredForIl2cppReuse": True,
            "cacheDoesNotRelaxValidation": True,
        },
    }
    manifest.write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(saved, ensure_ascii=False)
