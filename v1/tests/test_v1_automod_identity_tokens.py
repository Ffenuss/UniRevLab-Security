import json
import os
from pathlib import Path

from modkit.mobile.automod import build_plan, _ensure_metadata_identity


def _card(method_id: int):
    return {
        "id": "health-card",
        "title": "SetHealth",
        "category": "Gameplay",
        "source": "test",
        "verificationStage": "APP_OWNED",
        "ownership": "APP_OR_GAME",
        "buildable": False,
        "actionable": False,
        "serverAudit": False,
        "externalCorroborating": False,
        "locator": {"methodId": method_id, "rva": None},
        "status": "APP_OWNED",
        "gameplayDomain": "health",
        "priority": 90,
    }


def test_token_confirmed_no_rva_identity_is_visible_but_never_buildable():
    identity_rows = [{
        "id": 9,
        "class": "Game.Player",
        "methodName": "SetHealth",
        "status": "METADATA_TOKEN_METHOD_CONFIRMED_NO_RVA",
        "metadataMethodNamePresent": True,
        "metadataQualifiedMethodPresent": True,
        "metadataToken": "0x06000001",
        "metadataTokenConfirmed": True,
        "metadataTokenConflict": False,
        "metadataResolvedClass": "Game.Player",
        "metadataResolvedMethodName": "SetHealth",
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }]
    plan = build_plan({"cards": [_card(9)]}, None, None, identity_rows)
    row = plan["candidates"][0]
    assert row["stage"] == "REVIEW"
    assert row["metadataIdentityObserved"] is True
    assert row["metadataIdentity"]["metadataTokenConfirmed"] is True
    assert row["metadataIdentity"]["metadataToken"] == "0x06000001"
    assert row["metadataIdentity"]["rva"] is None
    assert row["actionable"] is False
    assert row["buildable"] is False
    assert plan["metadataTokenNoRvaCount"] == 1
    assert plan["exactLocatorCount"] == 0
    assert plan["readyForPreflightCount"] == 0
    assert plan["readyToBuildCount"] == 0
    assert plan["metadataIdentityPromotesBuildability"] is False


def test_token_conflict_is_not_attached_to_automod_candidate():
    conflict = [{
        "id": 9,
        "class": "Game.Player",
        "methodName": "Other",
        "status": "METADATA_TOKEN_CONFLICT_NO_RVA",
        "metadataMethodNamePresent": True,
        "metadataQualifiedMethodPresent": False,
        "metadataToken": "0x06000001",
        "metadataTokenConfirmed": False,
        "metadataTokenConflict": True,
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }]
    plan = build_plan({"cards": [_card(9)]}, None, None, conflict)
    row = plan["candidates"][0]
    assert row["metadataIdentityObserved"] is False
    assert row["metadataIdentity"] is None
    assert plan["metadataIdentityObservedCount"] == 0
    assert plan["metadataTokenNoRvaCount"] == 0
    assert plan["readyForPreflightCount"] == 0
    assert plan["readyToBuildCount"] == 0


def test_old_identity_schema_is_recomputed_even_when_files_are_fresh(tmp_path: Path, monkeypatch):
    metadata = tmp_path / "metadata.bin"
    methods = tmp_path / "analysis.methods.jsonl"
    summary = tmp_path / "il2cpp-metadata-identity.json"
    rows = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    metadata.write_bytes(b"metadata")
    methods.write_text("{}\n", encoding="utf-8")
    summary.write_text(json.dumps({"schema": "modkit-il2cpp-metadata-identity-1.0"}), encoding="utf-8")
    rows.write_text("{}\n", encoding="utf-8")

    for path in (metadata, methods):
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    for path in (summary, rows):
        os.utime(path, ns=(2_000_000_000, 2_000_000_000))

    calls = []
    import modkit.mobile.il2cpp_metadata_identity as identity

    def fake_build(root, output_path=None):
        calls.append(Path(root))
        value = {"schema": "modkit-il2cpp-metadata-identity-1.1", "engine": "il2cpp.metadata-identity-embedded", "counts": {}}
        Path(output_path).write_text(json.dumps(value), encoding="utf-8")
        (Path(root) / "il2cpp-metadata-identity.methods.jsonl").write_text("", encoding="utf-8")
        return value

    monkeypatch.setattr(identity, "build_workspace_identity", fake_build)
    result = _ensure_metadata_identity(tmp_path)
    assert calls == [tmp_path]
    assert result["schema"] == "modkit-il2cpp-metadata-identity-1.1"


def test_current_identity_schema_and_fresh_rows_are_reused(tmp_path: Path, monkeypatch):
    metadata = tmp_path / "metadata.bin"
    methods = tmp_path / "analysis.methods.jsonl"
    summary = tmp_path / "il2cpp-metadata-identity.json"
    rows = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    metadata.write_bytes(b"metadata")
    methods.write_text("{}\n", encoding="utf-8")
    expected = {"schema": "modkit-il2cpp-metadata-identity-1.1", "engine": "il2cpp.metadata-identity-embedded"}
    summary.write_text(json.dumps(expected), encoding="utf-8")
    rows.write_text("{}\n", encoding="utf-8")

    for path in (metadata, methods):
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    for path in (summary, rows):
        os.utime(path, ns=(2_000_000_000, 2_000_000_000))

    import modkit.mobile.il2cpp_metadata_identity as identity

    def should_not_run(*args, **kwargs):
        raise AssertionError("fresh current-schema identity must be reused")

    monkeypatch.setattr(identity, "build_workspace_identity", should_not_run)
    assert _ensure_metadata_identity(tmp_path) == expected
