from pathlib import Path

import pytest

from modkit.mobile import simple_mode, simple_mode_cancellable


class _NeverCancel:
    def isCancelled(self):
        return False


class _AlwaysCancel:
    def isCancelled(self):
        return True


def test_cancellable_catalog_preserves_schema_and_publishes_only_after_completion(tmp_path):
    output = tmp_path / "simple-catalog.json"
    report = simple_mode_cancellable.build_catalog(tmp_path, output, _NeverCancel())

    assert report["schema"] == simple_mode.SCHEMA
    assert report["cancelAware"] is True
    assert output.is_file()


def test_cancellable_catalog_does_not_publish_partial_output(tmp_path):
    output = tmp_path / "simple-catalog.json"

    with pytest.raises(simple_mode_cancellable.CatalogueCancelled):
        simple_mode_cancellable.build_catalog(tmp_path, output, _AlwaysCancel())

    assert not output.exists()


def test_android_evidence_service_routes_stage_five_through_cancellable_catalog():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'getModule("modkit.mobile.simple_mode_cancellable")' in source
    assert 'callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath(),new Progress())' in source
