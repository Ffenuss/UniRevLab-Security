import json

from modkit.mobile.simple_cache import plan_workspace, record_workspace


def _write_required_workspace(root):
    (root / "game.apk").write_bytes(b"apk-v1")
    (root / "metadata.bin").write_bytes(b"metadata-v1")
    (root / "library.so").write_bytes(b"library-v1")
    files = {
        "re-analysis.json": '{"findingCount":1}',
        "analysis.json": '{"candidate_count":1}',
        "analysis.summary.json": '{"candidate_count":1,"summary":"current"}',
        "analysis.methods.jsonl": '{"id":1,"name":"Tick","rva":"0x1000"}\n',
        "analysis.gameplay-coverage.json": '{"covered":true}',
        "analysis.evidence-graph.jsonl": '{"id":"edge-1"}\n',
        "security-surfaces.json": '{"total":0}',
    }
    for name, value in files.items():
        (root / name).write_text(value, encoding="utf-8")


def test_il2cpp_cache_hit_requires_exact_analysis_summary_sha(tmp_path):
    _write_required_workspace(tmp_path)
    manifest = tmp_path / "simple-cache.json"

    first = json.loads(plan_workspace(tmp_path, manifest))
    assert first["unchanged"] is False
    record_workspace(tmp_path, manifest, json.dumps(first))

    second = json.loads(plan_workspace(tmp_path, manifest))
    assert second["targetUnchanged"] is True
    assert second["analysisOutputsUnchanged"] is True
    assert second["securityOutputsUnchanged"] is True
    assert second["unchanged"] is True

    (tmp_path / "analysis.summary.json").write_text(
        '{"candidate_count":1,"summary":"tampered"}', encoding="utf-8"
    )

    third = json.loads(plan_workspace(tmp_path, manifest))
    assert third["targetUnchanged"] is True
    assert third["analysisOutputsUnchanged"] is False
    assert third["unchanged"] is False
    assert "analysis.summary.json:sha256-changed" in third["changedAnalysisOutputs"]


def test_cache_manifest_records_analysis_summary_fingerprint_policy(tmp_path):
    _write_required_workspace(tmp_path)
    manifest = tmp_path / "simple-cache.json"
    plan = json.loads(plan_workspace(tmp_path, manifest))
    saved = json.loads(record_workspace(tmp_path, manifest, json.dumps(plan)))

    outputs = {row["name"]: row for row in saved["outputs"]}
    summary = outputs["analysis.summary.json"]
    assert summary["sha256"]
    assert len(summary["sha256"]) == 64
    assert saved["policy"]["analysisSummaryFingerprintRequiredForIl2cppReuse"] is True
