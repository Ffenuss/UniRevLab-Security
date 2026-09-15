from modkit.mobile.automod import build_plan
from modkit.mobile.evidence_quality import refine_catalog


def _base(card_id, title, *, locator=None, actionable=False, source="Analysis"):
    return {
        "id": card_id,
        "title": title,
        "category": "Gameplay",
        "source": source,
        "status": "READY_NATIVE" if locator else "FOUND_STATIC",
        "verificationStage": "LOCATOR_CONFIRMED" if locator else "FOUND_STATIC",
        "ownership": "APP_OR_GAME",
        "buildable": False,
        "selectable": False,
        "actionable": actionable,
        "locator": locator,
        "priority": 80,
        "important": True,
        "serverAudit": False,
        "evidence": {"methodName": title, "class": "Game.Player"} if locator else {"value": title},
    }


def test_method_bound_correlated_card_becomes_preflight_candidate_not_direct_build():
    report = refine_catalog({"cards": [
        _base(
            "hp",
            "SetHealth",
            locator={"rva": 0x1234, "library": "libil2cpp.so"},
            actionable=True,
        )
    ]})
    card = report["cards"][0]
    assert card["evidenceTier"] == "CORRELATED_EVIDENCE"
    assert card["methodBoundEvidence"] is True
    assert card["controlCandidate"] is True
    assert card["buildable"] is False

    plan = build_plan(report)
    row = plan["candidates"][0]
    assert row["stage"] == "READY_FOR_PREFLIGHT"
    assert row["executableControl"] is True
    assert row["buildable"] is False
    assert plan["readyToBuildCount"] == 0
    assert plan["readyForPreflightCount"] == 1


def test_unbound_discovery_never_becomes_executable_control():
    report = refine_catalog({"cards": [
        _base("text", "health multiplier")
    ]})
    card = report["cards"][0]
    assert card["evidenceTier"] == "DISCOVERED_SURFACE"
    assert card["methodBoundEvidence"] is False
    assert card["controlCandidate"] is False

    plan = build_plan(report)
    row = plan["candidates"][0]
    assert row["stage"] == "REVIEW"
    assert row["executableControl"] is False
    assert plan["executableControlCount"] == 0
    assert plan["reviewOnlyCount"] == 1
