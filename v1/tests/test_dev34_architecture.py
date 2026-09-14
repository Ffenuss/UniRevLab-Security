from __future__ import annotations

import json
from pathlib import Path

from modkit.mobile.metadata_catalog import build_method_search_index, lookup_method_ids
from modkit.reworkspace.correlate import analyze_artifacts


def test_small_artifacts_use_bounded_parallel_scan(monkeypatch):
    monkeypatch.setenv("MODKIT_RE_WORKERS", "2")
    result = analyze_artifacts([
        ("assets/a.txt", b"developer console enabled"),
        ("assets/b.json", b'{"premium":true,"feature":"health"}'),
        ("res/raw/c.xml", b"<root>debug menu</root>"),
    ])
    diag = result["artifactScanDiagnostics"]
    assert diag["workers"] == 2
    assert diag["parallelSubmitted"] == 3
    assert diag["maxPending"] <= 4
    assert diag["nativeSynchronous"] == 0


def test_parallel_scan_keeps_deterministic_evidence(monkeypatch):
    artifacts = [
        ("assets/a.txt", b"developer console enabled"),
        ("assets/b.txt", b"premium entitlement receipt"),
        ("assets/c.txt", b"global-metadata il2cpp_"),
    ]
    monkeypatch.setenv("MODKIT_RE_WORKERS", "1")
    sequential = analyze_artifacts(artifacts)
    monkeypatch.setenv("MODKIT_RE_WORKERS", "2")
    parallel = analyze_artifacts(artifacts)
    for report in (sequential, parallel):
        report.pop("artifactScanDiagnostics", None)
    assert parallel == sequential


def test_metadata_search_index_intersects_exact_tokens(tmp_path):
    catalog = tmp_path / "analysis.methods.jsonl"
    rows = [
        {"metadata_method_id": 0, "image": "Game.dll", "class": "PlayerController", "name": "Move", "label": "PlayerController::Move", "method_role": "action", "semantic": ["speed"]},
        {"metadata_method_id": 1, "image": "Game.dll", "class": "PlayerController", "name": "SetHealth", "label": "PlayerController::SetHealth", "method_role": "setter", "semantic": ["health"]},
        {"metadata_method_id": 2, "image": "Store.dll", "class": "EntitlementService", "name": "HasPremium", "label": "EntitlementService::HasPremium", "method_role": "query", "semantic": ["premium"]},
        {"metadata_method_id": 3, "image": "A.dll", "class": "a", "name": "b", "label": "a::b", "method_role": "unknown", "semantic": []},
    ]
    catalog.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in rows), encoding="utf-8")
    stats = build_method_search_index(catalog)
    index = Path(str(catalog) + ".search.idx")
    assert stats["available"] is True and index.is_file()
    assert lookup_method_ids(index, "health") == [1]
    assert lookup_method_ids(index, "PlayerController") == [0, 1]
    assert lookup_method_ids(index, "player health") == [1]
    assert lookup_method_ids(index, "premium") == [2]


def test_metadata_search_index_is_candidate_locator_only(tmp_path):
    catalog = tmp_path / "analysis.methods.jsonl"
    catalog.write_text(json.dumps({
        "metadata_method_id": 7, "image": "Game.dll", "class": "HealthStore", "name": "Read",
        "label": "HealthStore::Read", "method_role": "query", "semantic": ["health"],
        "runtime_status": "not-observed", "selectable": False,
    }) + "\n", encoding="utf-8")
    stats = build_method_search_index(catalog)
    assert stats["records"] > 0
    assert lookup_method_ids(str(catalog) + ".search.idx", "health") == [7]
    row = json.loads(catalog.read_text(encoding="utf-8"))
    assert row["runtime_status"] == "not-observed"
    assert row["selectable"] is False
