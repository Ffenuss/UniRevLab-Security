"""Typed contracts for the reverse-engineering correlation pipeline.

The runtime report remains plain JSON for Android/Python interoperability, but
centralising the shape here prevents the engine, scanner and UI from inventing
slightly different keys.  This module intentionally validates structure only;
it never upgrades evidence strength or runtime status.
"""
from __future__ import annotations

from typing import Any, NotRequired, TypedDict


REPORT_SCHEMA = "modkit-re-1.2"
TYPED_CONTRACT = "modkit-re-report-typed-1"


class EvidenceRow(TypedDict, total=False):
    artifact: str
    kind: str
    value: str
    location: str


class FindingRow(TypedDict, total=False):
    id: str
    title: str
    category: str
    status: str
    confidence: float
    evidence: list[EvidenceRow]
    rationale: str


class InventoryRow(TypedDict, total=False):
    name: str
    size: int
    sha256: str


class Inventory(TypedDict):
    dex: list[dict[str, Any]]
    native: list[dict[str, Any]]
    other: list[dict[str, Any]]


class REReport(TypedDict, total=False):
    schema: str
    typedContract: str
    inventory: Inventory
    nativeRelations: dict[str, Any]
    dexClasses: dict[str, list[str]]
    dexTrust: dict[str, Any]
    findings: list[FindingRow]
    apk: dict[str, Any]
    nestedApks: list[dict[str, Any]]
    duplicates: list[dict[str, Any]]
    skippedArtifacts: list[dict[str, Any]]
    streamingDiagnostics: dict[str, Any]
    controlCandidates: list[dict[str, Any]]
    applicationDiscovery: dict[str, Any]
    targetProfile: dict[str, Any]
    pipelineDiagnostics: dict[str, Any]


def ensure_report_contract(report: dict[str, Any]) -> REReport:
    """Normalise mandatory containers without altering evidence semantics."""
    if not isinstance(report, dict):
        raise TypeError("RE report must be a dict")
    report["schema"] = REPORT_SCHEMA
    report["typedContract"] = TYPED_CONTRACT
    inventory = report.setdefault("inventory", {})
    if not isinstance(inventory, dict):
        raise TypeError("inventory must be a dict")
    for key in ("dex", "native", "other"):
        value = inventory.setdefault(key, [])
        if not isinstance(value, list):
            raise TypeError(f"inventory.{key} must be a list")
    for key in ("findings",):
        value = report.setdefault(key, [])
        if not isinstance(value, list):
            raise TypeError(f"{key} must be a list")
    relations = report.setdefault("nativeRelations", {})
    if not isinstance(relations, dict):
        raise TypeError("nativeRelations must be a dict")
    return report  # type: ignore[return-value]
