from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modkit.mobile import artifact_families, deep_gameplay


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0

    def progress(self, _text: str):
        pass


class NeverCancel:
    def isCancelled(self):
        return False


def test_artifact_source_symbol_lines_stay_exact_with_linear_scan():
    data = b"function first() {}\n\nconst second = () => {};\nfunction third() {}\n"
    rows = artifact_families._source_symbols("javascript", data, NeverCancel())
    assert [(row["name"], row["line"]) for row in rows] == [
        ("first", 1), ("second", 3), ("third", 4),
    ]


def test_artifact_entry_cancel_does_not_publish_partial_inventory(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("assets/src/main.js", b"A" * (3 * 1024 * 1024) + b" function playerHealth() {}")
    output = tmp_path / "artifact-families.json"
    with pytest.raises(artifact_families.ArtifactScanCancelled):
        artifact_families.scan_apk_paths([apk], output, CancelAfter(4))
    assert not output.exists()


def test_gameplay_cancel_interrupts_large_native_function_walk():
    functions = [
        {"name": f"PlayerHealth_{i}", "rva": 0x1000 + i * 4, "size": 16}
        for i in range(5000)
    ]
    native = {"libraries": [{"entry": "lib/arm64-v8a/libgame.so", "functions": functions}]}
    with pytest.raises(deep_gameplay.GameplayScanCancelled):
        deep_gameplay.analyze({"artifacts": []}, native, CancelAfter(4))


def test_gameplay_cancel_does_not_publish_partial_report(tmp_path: Path):
    output = tmp_path / "deep-gameplay.json"
    with pytest.raises(deep_gameplay.GameplayScanCancelled):
        deep_gameplay.scan_workspace(tmp_path, {"artifacts": []}, {"libraries": []}, output, CancelAfter(1))
    assert not output.exists()


def test_embedded_pipeline_passes_callback_to_first_and_last_backends():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert "artifact_families.scan_workspace(root, None, cb)" in source
    assert "except artifact_families.ArtifactScanCancelled" in source
    assert 'deep_gameplay.scan_workspace(root, static_report, native_report, root / "deep-gameplay.json", cb)' in source
    assert "except deep_gameplay.GameplayScanCancelled" in source
