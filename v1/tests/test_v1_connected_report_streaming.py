import json
from pathlib import Path

import pytest

from modkit.mobile import connected_report_streaming as streaming
from modkit.mobile.connected_report import build_connected_report as build_base_report


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


def test_base_connected_report_retains_only_method_rows_relevant_to_findings(tmp_path: Path):
    cards = [
        {"id": "wanted-id", "title": "A", "locator": {"methodId": 777, "class": "Game.Player", "method": "SetHealth"}},
        {"id": "wanted-rva", "title": "B", "locator": {"rva": "0x9000", "method": "ByRva"}},
        {"id": "wanted-name", "title": "C", "locator": {"method": "ExactName"}},
    ]
    (tmp_path / "simple-catalog.json").write_text(json.dumps({"cards": cards}), encoding="utf-8")
    rows = []
    for i in range(1000):
        rows.append({"id": i, "class": "Noise.Type", "name": f"Noise{i}", "rva": 0x1000 + i * 4})
    rows.extend([
        {"id": 777, "class": "Game.Player", "name": "SetHealth", "rva": 0x8000},
        {"id": 1001, "class": "Game.Player", "name": "ByRva", "rva": 0x9000},
        {"id": 1002, "class": "Game.Player", "name": "ExactName", "rva": 0xA000},
    ])
    (tmp_path / "analysis.methods.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    report = build_base_report(tmp_path)
    assert report["methodCatalogRows"] == len(rows)
    assert report["exactLinked"] == 3
    policy = report["methodIndexPolicy"]
    assert policy["loadsFullMethodCatalogIntoRam"] is False
    assert policy["retainedMethodIds"] == 1
    assert policy["retainedRvaBuckets"] == 1
    assert policy["retainedNameBuckets"] == 3


def test_finding_scoped_reader_drops_unrelated_identity_and_native_rows(tmp_path: Path):
    (tmp_path / "simple-catalog.json").write_text(json.dumps({"cards": [{
        "id": "hp",
        "locator": {"methodId": 42, "class": "Game.Player", "method": "SetHealth", "rva": "0x1234"},
    }]}), encoding="utf-8")
    identity = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    identity.write_text("\n".join([
        json.dumps({"id": 41, "class": "Noise.Player", "methodName": "Other", "metadataQualifiedMethodPresent": True}),
        json.dumps({"id": 42, "class": "Game.Player", "methodName": "SetHealth", "metadataQualifiedMethodPresent": True}),
        json.dumps({"id": 99, "class": "Other.Type", "methodName": "SetHealth", "metadataQualifiedMethodPresent": True}),
    ]) + "\n", encoding="utf-8")
    native = tmp_path / "il2cpp-no-rva-native.methods.jsonl"
    native.write_text("\n".join([
        json.dumps({"metadataMethodId": 42, "class": "Game.Player", "methodName": "SetHealth"}),
        json.dumps({"metadataMethodId": 43, "class": "Noise.Player", "methodName": "Other"}),
    ]) + "\n", encoding="utf-8")
    cross = tmp_path / "il2cpp-crosscheck.methods.jsonl"
    cross.write_text("\n".join([
        json.dumps({"rva": 0x1234}),
        json.dumps({"rva": 0x9999}),
    ]) + "\n", encoding="utf-8")

    reader, retained = streaming._filtered_reader(tmp_path)
    assert [row["id"] for row in reader(identity)] == [42]
    assert [row["metadataMethodId"] for row in reader(native)] == [42]
    assert [row["rva"] for row in reader(cross)] == [0x1234]
    assert retained == {"crosscheck": 1, "identity": 1, "native": 1}


def test_streaming_entry_point_temporarily_replaces_v12_reader_and_restores_it(tmp_path: Path, monkeypatch):
    original = streaming._v12._jsonl
    observed = {}

    def fake_builder(workdir, output_json=None, output_md=None):
        observed["reader"] = streaming._v12._jsonl
        return {"schema": streaming.SCHEMA, "findingCount": 0}

    monkeypatch.setattr(streaming._v12, "build_connected_report", fake_builder)
    out = tmp_path / "connected-report.json"
    report = streaming.build_connected_report(tmp_path, out, None)

    assert callable(observed["reader"])
    assert observed["reader"] is not original
    assert streaming._v12._jsonl is original
    assert report["schema"] == "modkit-connected-report-1.2"
    assert report["memoryPolicy"]["methodEvidence"] == "STREAMED_FINDING_SCOPED_JSONL"
    assert report["memoryPolicy"]["loadsFullMethodCatalogIntoRam"] is False
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
