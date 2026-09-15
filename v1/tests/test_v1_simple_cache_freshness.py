import json
from pathlib import Path

from modkit.mobile import simple_cache


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _plan(root: Path) -> dict:
    return json.loads(simple_cache.plan_workspace(root, root / "simple-cache.json"))


def _record(root: Path, plan: dict) -> dict:
    return json.loads(simple_cache.record_workspace(root, root / "simple-cache.json", json.dumps(plan)))


def test_cache_hit_requires_unchanged_non_il2cpp_core_outputs(tmp_path: Path):
    _write(tmp_path / "game.apk", b"apk-target-v1")
    _write(tmp_path / "re-analysis.json", b'{"ok":true}')
    _write(tmp_path / "security-surfaces.json", b'{"total":1}')

    first = _plan(tmp_path)
    assert first["unchanged"] is False
    _record(tmp_path, first)

    second = _plan(tmp_path)
    assert second["targetUnchanged"] is True
    assert second["analysisOutputsUnchanged"] is True
    assert second["securityOutputsUnchanged"] is True
    assert second["unchanged"] is True

    _write(tmp_path / "re-analysis.json", b'{"ok":false}')
    changed = _plan(tmp_path)
    assert changed["targetUnchanged"] is True
    assert changed["analysisOutputsUnchanged"] is False
    assert changed["unchanged"] is False
    assert "re-analysis.json:sha256-changed" in changed["changedAnalysisOutputs"]


def test_il2cpp_cache_hit_requires_exact_methods_catalog_fingerprint(tmp_path: Path):
    _write(tmp_path / "game.apk", b"same-apk")
    _write(tmp_path / "metadata.bin", b"metadata")
    _write(tmp_path / "library.so", b"elf-library")
    _write(tmp_path / "analysis.json", b'{"schema":"analysis"}')
    _write(tmp_path / "analysis.methods.jsonl", b'{"id":1,"name":"A"}\n')
    _write(tmp_path / "re-analysis.json", b'{"findingCount":0}')
    _write(tmp_path / "security-surfaces.json", b'{"total":0}')

    first = _plan(tmp_path)
    _record(tmp_path, first)
    assert _plan(tmp_path)["unchanged"] is True

    _write(tmp_path / "analysis.methods.jsonl", b'{"id":1,"name":"B"}\n')
    changed = _plan(tmp_path)
    assert changed["targetUnchanged"] is True
    assert changed["analysisOutputsUnchanged"] is False
    assert changed["unchanged"] is False
    assert "analysis.methods.jsonl:sha256-changed" in changed["changedAnalysisOutputs"]


def test_old_cache_without_core_hashes_forces_one_fresh_pass(tmp_path: Path):
    _write(tmp_path / "game.apk", b"same-apk")
    _write(tmp_path / "re-analysis.json", b'{}')
    _write(tmp_path / "security-surfaces.json", b'{}')

    first = _plan(tmp_path)
    old_manifest = {
        "schema": simple_cache.SCHEMA,
        "targetDigest": first["targetDigest"],
        "targets": first["targets"],
        "outputs": [
            {"name": "re-analysis.json", "size": 2, "mtimeNs": (tmp_path / "re-analysis.json").stat().st_mtime_ns},
            {"name": "security-surfaces.json", "size": 2, "mtimeNs": (tmp_path / "security-surfaces.json").stat().st_mtime_ns},
        ],
    }
    (tmp_path / "simple-cache.json").write_text(json.dumps(old_manifest), encoding="utf-8")

    plan = _plan(tmp_path)
    assert plan["targetUnchanged"] is True
    assert plan["unchanged"] is False
    assert "re-analysis.json:unrecorded" in plan["changedAnalysisOutputs"]
    assert "security-surfaces.json:unrecorded" in plan["changedSecurityOutputs"]
