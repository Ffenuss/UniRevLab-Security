from modkit.mobile.automod import build_plan


def _card(card_id, stage, *, tier, control, locator=None, actionable=False, buildable=False):
    return {
        "id": card_id,
        "title": card_id,
        "category": "Gameplay",
        "source": "phase7-test",
        "verificationStage": stage,
        "ownership": "APP_OR_GAME",
        "buildable": buildable,
        "actionable": actionable,
        "serverAudit": False,
        "externalCorroborating": False,
        "locator": locator,
        "status": "FOUND_STATIC",
        "gameplayDomain": "health",
        "priority": 80,
        "evidenceTier": tier,
        "controlCandidate": control,
        "methodBoundEvidence": bool(locator),
        "flowCorrelated": stage in {"FLOW_CONFIRMED", "RUNTIME_CONFIRMED"},
    }


def test_discovered_surface_with_rva_stays_non_control():
    plan = build_plan({
        "cards": [
            _card(
                "raw-rva",
                "LOCATOR_CONFIRMED",
                tier="DISCOVERED_SURFACE",
                control=False,
                actionable=True,
                locator={"rva": 0x1200, "library": "libil2cpp.so"},
            )
        ]
    })
    row = plan["candidates"][0]
    assert row["stage"] == "RUNTIME_NEEDED"
    assert row["executableControl"] is False
    assert row["qualityPolicyPresent"] is True
    assert row["qualityControlEligible"] is False
    assert plan["readyForPreflightCount"] == 0
    assert plan["executableControlCount"] == 0
    assert plan["runtimeProbeCount"] == 1


def test_correlated_control_candidate_with_exact_locator_enters_preflight():
    plan = build_plan({
        "cards": [
            _card(
                "bound-rva",
                "LOCATOR_CONFIRMED",
                tier="CORRELATED_EVIDENCE",
                control=True,
                actionable=True,
                locator={"rva": 0x2200, "library": "libil2cpp.so"},
            )
        ]
    })
    row = plan["candidates"][0]
    assert row["stage"] == "READY_FOR_PREFLIGHT"
    assert row["executableControl"] is True
    assert row["qualityControlEligible"] is True
    assert plan["executableControlCount"] == 1
    assert plan["runtimeProbeCount"] == 0


def test_exact_native_recovery_may_enter_preflight_without_promoting_buildability():
    card = _card(
        "native",
        "APP_OWNED",
        tier="DISCOVERED_SURFACE",
        control=False,
        locator={"methodId": 77, "class": "Game.Player", "method": "SetHealth", "rva": None},
    )
    recovery = [{
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
    }]
    plan = build_plan({"cards": [card]}, None, None, None, recovery)
    row = plan["candidates"][0]
    assert row["stage"] == "READY_FOR_PREFLIGHT"
    assert row["nativeRvaRecovered"] is True
    assert row["buildable"] is False
    assert row["actionable"] is False
    assert row["resolvedLocator"]["source"] == "EXACT_CODEGENMODULE_RECOVERY"
    assert plan["readyToBuildCount"] == 0
    assert plan["readyForPreflightCount"] == 1


def test_phase7_plan_separates_controls_runtime_and_review():
    plan = build_plan({
        "cards": [
            _card(
                "control",
                "LOCATOR_CONFIRMED",
                tier="CORRELATED_EVIDENCE",
                control=True,
                actionable=True,
                locator={"rva": 0x4000},
            ),
            _card(
                "runtime",
                "FLOW_CONFIRMED",
                tier="CORRELATED_EVIDENCE",
                control=False,
            ),
            _card(
                "review",
                "FOUND_STATIC",
                tier="DISCOVERED_SURFACE",
                control=False,
                locator={"rva": 0x5000},
            ),
        ]
    })
    rows = {row["id"]: row for row in plan["candidates"]}
    assert rows["control"]["executableControl"] is True
    assert rows["runtime"]["runtimeProbe"] is True
    assert rows["review"]["reviewOnly"] is True
    assert plan["executableControlCount"] == 1
    assert plan["runtimeProbeCount"] == 1
    assert plan["reviewOnlyCount"] == 1
    assert plan["nonControlEvidenceCount"] == 2
    assert plan["phase7Policy"]["refinedCatalogRequiresControlCandidate"] is True
    assert plan["phase7Policy"]["reviewEvidencePromotesBuildability"] is False


def test_review_only_semantic_native_recovery_never_enters_preflight():
    card = _card(
        "weak-accessor",
        "APP_OWNED",
        tier="CORRELATED_EVIDENCE",
        control=False,
        locator={"methodId": 88, "class": "a.b.C", "method": "GetLevel", "rva": None},
    )
    card["automationExcluded"] = True
    card["evidence"] = {"reviewOnlySemantic": True, "automationExcluded": True}
    recovery = [{
        "id": 88,
        "metadataMethodId": 88,
        "metadataToken": "0x06000058",
        "image": "Assembly-CSharp.dll",
        "class": "a.b.C",
        "methodName": "GetLevel",
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE",
        "rva": 0x456780,
        "rvaHex": "0x456780",
        "addressConfirmed": True,
        "associationConfirmed": True,
        "uniqueExecutablePointer": True,
        "moduleResolution": "EXACT_EXPECTED_METHOD_COUNT",
        "identityProof": "metadataMethodId+token+image+declaringType+methodName",
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }]
    plan = build_plan({"cards": [card]}, None, None, None, recovery)
    row = plan["candidates"][0]
    assert row["nativeRvaRecovered"] is True
    assert row["automationExcluded"] is True
    assert row["stage"] == "REVIEW"
    assert row["executableControl"] is False
    assert row["reviewOnly"] is True
    assert plan["readyForPreflightCount"] == 0
    assert plan["executableControlCount"] == 0


def test_review_only_xref_bridge_can_request_runtime_but_not_preflight():
    card = _card(
        "xref-bridge",
        "FLOW_CONFIRMED",
        tier="CORRELATED_EVIDENCE",
        control=False,
        locator={"methodId": 99, "class": "a.b.C", "method": "a", "rva": None},
    )
    card["automationExcluded"] = True
    card["evidence"] = {"reviewOnlySemantic": True, "automationExcluded": True}
    recovery = [{
        "id": 99,
        "metadataMethodId": 99,
        "metadataToken": "0x06000063",
        "image": "Assembly-CSharp.dll",
        "class": "a.b.C",
        "methodName": "a",
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE",
        "rva": 0x567890,
        "rvaHex": "0x567890",
        "addressConfirmed": True,
        "associationConfirmed": True,
        "uniqueExecutablePointer": True,
        "moduleResolution": "EXACT_EXPECTED_METHOD_COUNT",
        "identityProof": "metadataMethodId+token+image+declaringType+methodName",
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }]
    plan = build_plan({"cards": [card]}, None, None, None, recovery)
    row = plan["candidates"][0]
    assert row["nativeRvaRecovered"] is True
    assert row["stage"] == "RUNTIME_NEEDED"
    assert row["runtimeProbe"] is True
    assert row["executableControl"] is False
    assert plan["readyForPreflightCount"] == 0
