from pathlib import Path

import pytest

from modkit.mobile import embedded_pipeline


ROOT = Path(__file__).resolve().parents[1]


class CancelAfterArtifactFamilies:
    def __init__(self):
        self.checks = 0
        self.progress_rows: list[str] = []

    def isCancelled(self):
        self.checks += 1
        return self.checks >= 2

    def progress(self, text):
        self.progress_rows.append(str(text))


def test_embedded_pipeline_stops_before_next_backend_on_cancel(tmp_path, monkeypatch):
    calls = {"profiler": 0, "artifact": 0, "lua": 0}

    def profiler_scan(*_args, **_kwargs):
        calls["profiler"] += 1
        return {
            "schema": "test-runtime-profiler",
            "profileCount": 0,
            "detected": [],
            "profiles": [],
            "abis": [],
        }

    def artifact_scan(*_args, **_kwargs):
        calls["artifact"] += 1
        raise AssertionError("Artifact backend must not run after cancellation")

    def lua_scan(*_args, **_kwargs):
        calls["lua"] += 1
        raise AssertionError("Lua backend must not run after cancellation")

    monkeypatch.setattr(embedded_pipeline.runtime_profiler, "scan_workspace", profiler_scan)
    monkeypatch.setattr(embedded_pipeline.artifact_families, "scan_workspace", artifact_scan)
    monkeypatch.setattr(embedded_pipeline.lua_deep_cancellable, "scan_workspace", lua_scan)

    callback = CancelAfterArtifactFamilies()
    with pytest.raises(embedded_pipeline.Cancelled):
        embedded_pipeline.run_workspace(
            tmp_path,
            tmp_path / "artifact-families.json",
            tmp_path / "embedded-analysis.json",
            callback,
        )

    assert calls == {"profiler": 1, "artifact": 0, "lua": 0}
    assert callback.progress_rows == ["Embedded 1/18 · runtime / engine profiler…"]
    assert not (tmp_path / "embedded-analysis.json").exists()


def test_full_analysis_passes_cancel_callback_to_inventory_and_embedded_pipeline():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java").read_text(encoding="utf-8")
    assert "public final class Progress" in source
    assert "public boolean isCancelled(){return app.cancelled.get();}" in source
    assert 'getModule("modkit.mobile.embedded_pipeline")' in source
    assert 'app.file("embedded-analysis.json").getPath(),new Progress())' in source
    assert 'app.file("installed-scan.json").getPath(),new Progress(),false)' in source
    assert 'if(app.cancelled.get()){chain=false;progress("Полный анализ отменён пользователем.");return;}' in source
