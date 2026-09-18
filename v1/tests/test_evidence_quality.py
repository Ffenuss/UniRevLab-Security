from modkit.mobile.evidence_quality import normalize_endpoint, refine_catalog


def card(source, title, **kwargs):
    value = {
        "id": kwargs.pop("id", source + ":" + title),
        "source": source,
        "title": title,
        "category": kwargs.pop("category", "General"),
        "status": kwargs.pop("status", "FOUND_STATIC"),
        "priority": kwargs.pop("priority", 80),
        "important": kwargs.pop("important", True),
        "lowSignal": kwargs.pop("lowSignal", False),
        "buildable": kwargs.pop("buildable", False),
        "selectable": kwargs.pop("selectable", False),
        "actionable": kwargs.pop("actionable", False),
        "serverAudit": kwargs.pop("serverAudit", False),
        "ownership": kwargs.pop("ownership", "APP_OR_GAME"),
        "evidence": kwargs.pop("evidence", {}),
    }
    value.update(kwargs)
    return value


def test_endpoint_normalization_removes_volatile_values_but_keeps_keys():
    a = normalize_endpoint("HTTPS://API.Example.com:443/v1//user/?token=AAA&lang=ru#x")
    b = normalize_endpoint("https://api.example.com/v1/user?lang=en&token=BBB")
    assert a == b == "https://api.example.com/v1/user?lang&token"


def test_duplicate_security_surfaces_collapse_and_raw_strings_are_not_important_controls():
    report = {
        "cards": [
            card("SecuritySurface", "Server/API endpoint", serverAudit=True,
                 evidence={"kind": "API_ENDPOINT", "value": "https://api.example.com/v1/user?token=A", "apk": "base.apk", "offset": 10}),
            card("SecuritySurface", "Server/API endpoint", serverAudit=True,
                 evidence={"kind": "API_ENDPOINT", "value": "https://API.example.com/v1/user/?token=B", "apk": "split.apk", "offset": 20}),
        ]
    }
    out = refine_catalog(report)
    assert out["rawCardCountBeforeDedup"] == 2
    assert out["total"] == 1
    assert out["deduplicatedCardCount"] == 1
    item = out["cards"][0]
    assert item["evidenceTier"] == "DISCOVERED_SURFACE"
    assert item["buildable"] is False
    assert item["selectable"] is False
    assert item["controlCandidate"] is False
    assert item["important"] is False
    assert item["deduplicated"] is True


def test_security_summary_is_potential_trust_boundary_not_confirmed_issue():
    out = refine_catalog({"cards": [card("SecuritySummary", "Network / API Endpoints", serverAudit=True, ownership="SECURITY")]})
    assert out["cards"][0]["evidenceTier"] == "POTENTIAL_TRUST_BOUNDARY"


def test_method_bound_or_flow_evidence_is_correlated_without_inventing_issue():
    out = refine_catalog({"cards": [card("Gameplay", "Health", evidence={"metadataMethodId": 42, "class": "Player", "methodName": "ApplyDamage"})]})
    item = out["cards"][0]
    assert item["evidenceTier"] == "CORRELATED_EVIDENCE"
    assert item["methodBoundEvidence"] is True
    assert item["evidenceTier"] != "CONFIRMED_ISSUE"


def test_confirmed_issue_requires_explicit_or_strong_security_runtime_confirmation():
    explicit = refine_catalog({"cards": [card("SecuritySurface", "Trust issue", serverAudit=True, evidence={"issueConfirmed": True})]})
    assert explicit["cards"][0]["evidenceTier"] == "CONFIRMED_ISSUE"


def test_known_framework_cdn_surface_is_downranked():
    out = refine_catalog({"cards": [card("SecuritySurface", "endpoint", serverAudit=True, evidence={"kind": "API_ENDPOINT", "value": "https://firebasestorage.googleapis.com/v0/b/demo"})]})
    item = out["cards"][0]
    assert item["networkRole"] == "FRAMEWORK_CDN_OR_TELEMETRY"
    assert item["important"] is False
    assert item["priority"] <= 36


def test_review_only_semantic_method_stays_non_control_even_with_method_identity():
    out = refine_catalog({"cards": [
        card(
            "Gameplay",
            "GetLevel",
            evidence={
                "metadataMethodId": 42,
                "class": "a.b.C",
                "methodName": "GetLevel",
                "reviewOnlySemantic": True,
                "automationExcluded": True,
            },
        )
    ]})
    item = out["cards"][0]
    assert item["methodBoundEvidence"] is True
    assert item["evidenceTier"] == "CORRELATED_EVIDENCE"
    assert item["automationExcluded"] is True
    assert item["controlCandidate"] is False
    assert item["buildable"] is False
    assert item["selectable"] is False
    assert item["actionable"] is False
    assert out["qualityPolicy"]["reviewOnlySemanticAutomationExcluded"] is True
