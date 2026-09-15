from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from modkit.mobile import simple_cache


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0


def _core(root: Path) -> None:
    (root / "re-analysis.json").write_text('{"findingCount":0}', encoding="utf-8")
    (root / "security-surfaces.json").write_text('{"total":0}', encoding="utf-8")


def test_same_size_same_mtime_target_mutation_still_forces_fresh_analysis(tmp_path: Path):
    apk = tmp_path / "game.apk"
    apk.write_bytes(b"AAAA-BBBB")
    _core(tmp_path)
    manifest = tmp_path / "simple-cache.json"

    first = json.loads(simple_cache.plan_workspace(tmp_path, manifest))
    simple_cache.record_workspace(tmp_path, manifest, json.dumps(first))
    before = apk.stat()

    apk.write_bytes(b"CCCC-DDDD")  # exact same length
    os.utime(apk, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = apk.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns

    plan = json.loads(simple_cache.plan_workspace(tmp_path, manifest))
    assert plan["targets"][0]["previousStatMatched"] is True
    assert plan["targets"][0]["hashReused"] is False
    assert plan["targetUnchanged"] is False
    assert plan["unchanged"] is False
    assert "game.apk" in plan["changedFiles"]


def test_cache_hashing_is_cooperatively_cancellable(tmp_path: Path):
    apk = tmp_path / "game.apk"
    apk.write_bytes(b"A" * (4 * 1024 * 1024))
    _core(tmp_path)
    with pytest.raises(simple_cache.CacheCancelled):
        simple_cache.plan_workspace(tmp_path, tmp_path / "simple-cache.json", CancelAfter(3))


def test_il2cpp_cache_requires_gameplay_graph_outputs(tmp_path: Path):
    apk = tmp_path / "game.apk"
    apk.write_bytes(b"APK")
    _core(tmp_path)
    (tmp_path / "metadata.bin").write_bytes(b"meta")
    (tmp_path / "library.so").write_bytes(b"elf")
    (tmp_path / "analysis.json").write_text("{}", encoding="utf-8")
    (tmp_path / "analysis.methods.jsonl").write_text('{}\n', encoding="utf-8")
    # Missing analysis.gameplay-coverage.json and analysis.evidence-graph.jsonl
    # must keep the cache ineligible even if analysis.json/methods exist.
    manifest = tmp_path / "simple-cache.json"
    first = json.loads(simple_cache.plan_workspace(tmp_path, manifest))
    simple_cache.record_workspace(tmp_path, manifest, json.dumps(first))
    second = json.loads(simple_cache.plan_workspace(tmp_path, manifest))
    assert second["analysisOutputsUnchanged"] is False
    assert second["unchanged"] is False
    assert "analysis.gameplay-coverage.json:missing" in second["changedAnalysisOutputs"]
    assert "analysis.evidence-graph.jsonl:missing" in second["changedAnalysisOutputs"]


def test_android_records_cache_only_for_complete_core_analyzers():
    root = Path(__file__).resolve().parents[1]
    service = (root / "android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")
    assert 'callAttr("plan_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),new Progress())' in service
    assert 'callAttr("record_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),plan.toString(),new Progress())' in service
    assert 'boolean cacheEligible=il2cppCacheable&&reCacheable' in service
    assert 'Files.deleteIfExists(app.file("simple-cache.json").toPath())' in service
