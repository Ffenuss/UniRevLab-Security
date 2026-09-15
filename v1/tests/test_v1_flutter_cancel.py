from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modkit.mobile import flutter_deep


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0

    def progress(self, _text: str):
        pass


def test_flutter_entry_read_checks_cancel_between_chunks(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("assets/flutter_assets/isolate_snapshot_data", b"F" * (3 * 1024 * 1024))
    with zipfile.ZipFile(apk) as zf:
        info = zf.getinfo("assets/flutter_assets/isolate_snapshot_data")
        with pytest.raises(flutter_deep.FlutterScanCancelled):
            flutter_deep._read_entry(zf, info, CancelAfter(3))


def test_flutter_cancel_does_not_publish_partial_report(tmp_path: Path):
    output = tmp_path / "flutter-deep.json"
    with pytest.raises(flutter_deep.FlutterScanCancelled):
        flutter_deep.scan_apk_paths([], {}, output, CancelAfter(1))
    assert not output.exists()


def test_embedded_pipeline_passes_callback_to_flutter_backend():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert 'flutter_deep.scan_workspace(root, native_report, root / "flutter-deep.json", cb)' in source
    assert "except flutter_deep.FlutterScanCancelled" in source
