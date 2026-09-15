import json
from pathlib import Path

import pytest

from modkit.mobile import automod_cancellable, connected_report_streaming
from modkit.mobile import il2cpp_crosscheck_cancellable, il2cpp_metadata_identity_cancellable


class _NeverCancel:
    def isCancelled(self):
        return False


class _AlwaysCancel:
    def isCancelled(self):
        return True


def test_automod_cancel_preserves_previous_plan_and_leaves_no_partial(tmp_path):
    output = tmp_path / "automod-plan.json"
    output.write_text('{"previous":true}', encoding="utf-8")

    with pytest.raises(automod_cancellable.AutoModCancelled):
        automod_cancellable.build_workspace_plan(tmp_path, output, _AlwaysCancel())

    assert json.loads(output.read_text(encoding="utf-8")) == {"previous": True}
    assert not (tmp_path / "automod-plan.json.part").exists()


def test_connected_report_cancel_preserves_previous_outputs(tmp_path):
    output_json = tmp_path / "connected-report.json"
    output_md = tmp_path / "connected-report.md"
    output_json.write_text('{"previous":true}', encoding="utf-8")
    output_md.write_text("previous report", encoding="utf-8")

    with pytest.raises(connected_report_streaming.ReportCancelled):
        connected_report_streaming.build_connected_report(
            tmp_path, output_json, output_md, _AlwaysCancel()
        )

    assert json.loads(output_json.read_text(encoding="utf-8")) == {"previous": True}
    assert output_md.read_text(encoding="utf-8") == "previous report"
    assert not (tmp_path / "connected-report.json.part").exists()
    assert not (tmp_path / "connected-report.md.part").exists()


def test_connected_report_uses_one_final_cancel_gate_for_output_pair(tmp_path):
    output_json = tmp_path / "connected-report.json"
    output_md = tmp_path / "connected-report.md"

    report = connected_report_streaming.build_connected_report(
        tmp_path, output_json, output_md, _NeverCancel()
    )

    policy = report["memoryPolicy"]
    assert policy["coordinatedFinalCancelGate"] is True
    assert policy["multiFileTransactionAtomic"] is False
    assert output_json.is_file() and output_md.is_file()
    assert not (tmp_path / "connected-report.json.part").exists()
    assert not (tmp_path / "connected-report.md.part").exists()


def test_automod_cancellable_keeps_base_schema_and_finding_scoped_policy(tmp_path):
    (tmp_path / "simple-catalog.json").write_text(json.dumps({
        "schema": "modkit-simple-mode-1.3",
        "cards": [{
            "id": "hp",
            "title": "Player health",
            "category": "Gameplay",
            "status": "READY_NATIVE",
            "verificationStage": "LOCATOR_CONFIRMED",
            "ownership": "APP_OR_GAME",
            "priority": 90,
            "actionable": True,
            "buildable": False,
            "serverAudit": False,
            "locator": {"rva": 4096, "class": "game.Player", "method": "GetHealth"},
        }],
    }), encoding="utf-8")
    output = tmp_path / "automod-plan.json"

    report = automod_cancellable.build_workspace_plan(tmp_path, output, _NeverCancel())

    assert report["schema"] == "modkit-automod-plan-1.4"
    assert report["readyForPreflightCount"] == 1
    assert report["memoryPolicy"]["loadsFullMethodEvidenceIntoRam"] is False
    assert report["memoryPolicy"]["cancelAware"] is True
    assert output.is_file()


def test_low_level_release_adapters_check_cancel_before_touching_outputs(tmp_path):
    with pytest.raises(il2cpp_crosscheck_cancellable.CrosscheckCancelled):
        il2cpp_crosscheck_cancellable.run_crosscheck(
            tmp_path / "metadata.bin", tmp_path / "library.so", tmp_path / "methods.jsonl",
            tmp_path / "cross.json", tmp_path / "cross.jsonl", _AlwaysCancel(),
        )
    with pytest.raises(il2cpp_metadata_identity_cancellable.MetadataIdentityCancelled):
        il2cpp_metadata_identity_cancellable.build_workspace_identity(
            tmp_path, tmp_path / "identity.json", _AlwaysCancel()
        )
    assert not list(tmp_path.glob("*.part"))


def test_android_stage_six_uses_cancellable_release_routes():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'getModule("modkit.mobile.automod_cancellable")' in source
    assert 'callAttr("build_workspace_plan",getFilesDir().getPath(),app.file("automod-plan.json").getPath(),new Progress())' in source
    assert 'callAttr("build_connected_report",getFilesDir().getPath(),app.file("connected-report.json").getPath(),app.file("connected-report.md").getPath(),new Progress())' in source
