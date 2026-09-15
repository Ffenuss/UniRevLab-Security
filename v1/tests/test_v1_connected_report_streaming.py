import json
from pathlib import Path

import pytest

from modkit.mobile import connected_report_streaming as streaming


def test_jsonl_adapter_is_lazy_and_skips_invalid_rows(tmp_path: Path):
    path = tmp_path / "rows.jsonl"
    path.write_text(
        '\n'.join([
            json.dumps({"id": 1}),
            "not-json",
            json.dumps(["not", "a", "dict"]),
            json.dumps({"id": 2}),
        ]) + "\n",
        encoding="utf-8",
    )
    rows = streaming._iter_jsonl(path)
    assert not isinstance(rows, list)
    assert next(rows) == {"id": 1}
    assert next(rows) == {"id": 2}
    with pytest.raises(StopIteration):
        next(rows)


def test_streaming_entry_point_temporarily_replaces_v12_reader_and_restores_it(tmp_path: Path, monkeypatch):
    original = streaming._v12._jsonl
    observed = {}

    def fake_builder(workdir, output_json=None, output_md=None):
        observed["reader"] = streaming._v12._jsonl
        return {"schema": streaming.SCHEMA, "findingCount": 0}

    monkeypatch.setattr(streaming._v12, "build_connected_report", fake_builder)
    out = tmp_path / "connected-report.json"
    report = streaming.build_connected_report(tmp_path, out, None)

    assert observed["reader"] is streaming._iter_jsonl
    assert streaming._v12._jsonl is original
    assert report["schema"] == "modkit-connected-report-1.2"
    assert report["memoryPolicy"]["methodEvidence"] == "STREAMED_JSONL"
    assert report["memoryPolicy"]["loadsFullMethodEvidenceIntoRam"] is False
    persisted = json.loads(out.read_text(encoding="utf-8"))
    assert persisted["memoryPolicy"]["loadsFullMethodEvidenceIntoRam"] is False


def test_android_release_paths_use_streaming_connected_report():
    root = Path(__file__).resolve().parents[1]
    automatic = (root / "android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")
    center = (root / "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java").read_text(encoding="utf-8")
    needle = 'getModule("modkit.mobile.connected_report_streaming")'
    assert needle in automatic
    assert needle in center
    assert 'getModule("modkit.mobile.connected_report_v12")' not in automatic
    assert 'getModule("modkit.mobile.connected_report_v12")' not in center
