from modkit.mobile.automod import build_plan
from modkit.mobile.il2cpp_no_rva_native import _class_identity_match


def _card(locator):
    return {
        "id": "candidate",
        "title": "SetHealth",
        "category": "Gameplay",
        "source": "test",
        "verificationStage": "APP_OWNED",
        "ownership": "APP_OR_GAME",
        "buildable": False,
        "actionable": False,
        "serverAudit": False,
        "externalCorroborating": False,
        "locator": locator,
        "status": "FOUND_STATIC",
        "gameplayDomain": "health",
        "priority": 80,
    }


def _recovery():
    return {
        "id": 77,
        "metadataMethodId": 77,
        "metadataToken": "0x0600002a",
        "image": "Assembly-CSharp.dll",
        "class": "Game.Player",
        "methodName": "SetHealth",
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE",
        "rva": 0x345678,
        "rvaHex": "0x345678",
        "addressConfirmed": True,
        "associationConfirmed": True,
        "uniqueExecutablePointer": True,
        "moduleResolution": "EXACT_EXPECTED_METHOD_COUNT",
        "identityProof": "metadataMethodId+token+image+declaringType+methodName",
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }


def test_no_rva_recovery_declaring_type_requires_full_namespace_identity():
    assert _class_identity_match("Game.Player", "Game.Player") is True
    assert _class_identity_match("Game/Player", "Game.Player") is True
    assert _class_identity_match("Other.Player", "Game.Player") is False
    assert _class_identity_match("Player", "Game.Player") is False


def test_automod_rejects_recovered_rva_when_method_id_identity_conflicts_with_class():
    plan = build_plan({"cards": [_card({"methodId": 77, "class": "Other.Player", "method": "SetHealth", "rva": None})]}, native_recovery_rows=[_recovery()])
    row = plan["candidates"][0]
    assert row["nativeRvaRecovered"] is False
    assert row["resolvedLocator"] is None
    assert row["stage"] == "REVIEW"
    assert plan["nativeRecoveredLocatorCount"] == 0
    assert plan["readyForPreflightCount"] == 0


def test_automod_rejects_short_name_or_other_namespace_recovery_fallback():
    recovery = [_recovery()]
    for cls in ("Player", "Other.Player"):
        plan = build_plan({"cards": [_card({"class": cls, "method": "SetHealth", "rva": None})]}, native_recovery_rows=recovery)
        row = plan["candidates"][0]
        assert row["nativeRvaRecovered"] is False
        assert row["resolvedLocator"] is None
        assert row["stage"] == "REVIEW"


def test_automod_allows_exact_class_method_fallback_when_method_id_is_absent():
    plan = build_plan({"cards": [_card({"class": "Game.Player", "method": "SetHealth", "rva": None})]}, native_recovery_rows=[_recovery()])
    row = plan["candidates"][0]
    assert row["nativeRvaRecovered"] is True
    assert row["resolvedLocator"]["rva"] == 0x345678
    assert row["stage"] == "READY_FOR_PREFLIGHT"
    assert plan["readyForPreflightCount"] == 1
    assert plan["readyToBuildCount"] == 0
