from __future__ import annotations

from pathlib import Path

import pytest

from modkit.mobile import cocos_deep


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0

    def progress(self, _text: str):
        pass


def test_cocos_correlation_cancel_is_not_converted_to_partial_result():
    artifacts = {"artifacts": [{"id": "s1", "family": "javascript", "entry": "assets/src/player.js", "kind": "SCRIPT_SYMBOL", "function": "takeDamage"}]}
    functions = [{"name": f"js_Player_takeDamage_{i}", "rva": 0x1000 + i * 4, "size": 16} for i in range(5000)]
    native = {"libraries": [{"entry": "lib/arm64-v8a/libcocos2dcpp.so", "soname": "libcocos2dcpp.so", "functions": functions, "controlFlow": []}]}

    with pytest.raises(cocos_deep.CocosScanCancelled):
        cocos_deep.correlate(artifacts, native, CancelAfter(4))


def test_cocos_workspace_cancel_does_not_publish_partial_report(tmp_path: Path):
    output = tmp_path / "cocos-deep.json"
    with pytest.raises(cocos_deep.CocosScanCancelled):
        cocos_deep.scan_workspace(tmp_path, {"artifacts": []}, {"libraries": []}, output, CancelAfter(1))
    assert not output.exists()


def test_embedded_pipeline_passes_callback_to_cocos_backend():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert 'cocos_deep.scan_workspace(root, static_report, native_report, root / "cocos-deep.json", cb)' in source
    assert "except cocos_deep.CocosScanCancelled" in source
