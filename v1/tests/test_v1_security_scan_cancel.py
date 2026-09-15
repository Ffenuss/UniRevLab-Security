from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modkit.mobile.security_scan import ScanCancelled, scan_apk_paths


class CancelAfter:
    def __init__(self, checks: int):
        self.remaining = checks

    def isCancelled(self):
        self.remaining -= 1
        return self.remaining <= 0


class NeverCancel:
    def isCancelled(self):
        return False


def test_security_scan_cancel_does_not_publish_partial_report(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("classes.dex", b"A" * (3 * 1024 * 1024) + b" https://api.example.test/v1/profile ")
    output = tmp_path / "security-surfaces.json"

    with pytest.raises(ScanCancelled):
        scan_apk_paths([apk], output, CancelAfter(6))

    assert not output.exists()


def test_security_scan_keeps_existing_passive_detection_with_callback(tmp_path: Path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00 https://api.example.test/v1/profile Retrofit baseUrl AES/GCM")
    output = tmp_path / "security-surfaces.json"

    result = scan_apk_paths([apk], output, NeverCancel())

    assert output.is_file()
    assert result["passive"] is True
    assert result["activeConnectionAttempted"] is False
    assert result["uniqueEndpoints"] >= 1
    assert any(row.get("kind") == "API_ENDPOINT" for row in result["findings"])


def test_android_evidence_service_passes_cancel_callback_to_security_scan():
    root = Path(__file__).resolve().parents[1]
    service = (root / "android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")
    call = 'callAttr("scan_workspace",getFilesDir().getPath(),app.file("security-surfaces.json").getPath(),new Progress())'
    assert call in service
