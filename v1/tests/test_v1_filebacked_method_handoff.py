from __future__ import annotations

import json
from pathlib import Path

from modkit.mobile.filebacked_method_handoff import enrich_catalog


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_exact_app_owned_filebacked_method_becomes_preflight_card_without_build_claim(tmp_path: Path):
    write_jsonl(
        tmp_path / "analysis.autopilot-index.jsonl",
        [
            {
                "metadataMethodId": 10585,
                "rva": 0x1FE7640,
                "label": "IGameTime::set_timeScale",
                "class": "IGameTime",
                "name": "set_timeScale",
                "isStatic": True,
                "generic": False,
                "abstract": False,
                "methodRole": "setter",
                "applicationOwned": True,
                "domains": ["movement", "world"],
                "semanticDomains": ["movement", "world"],
                "callerCount": 1,
                "calleeCount": 4,
            },
            {
                "metadataMethodId": 21000,
                "rva": 0x2111000,
                "label": "DG.Tweening.Tween::set_timeScale",
                "class": "DG.Tweening.Tween",
                "name": "set_timeScale",
                "isStatic": False,
                "generic": False,
                "abstract": False,
                "methodRole": "setter",
                "applicationOwned": True,
                "domains": ["movement"],
                "semanticDomains": ["movement"],
                "callerCount": 2,
                "calleeCount": 1,
            },
            {
                "metadataMethodId": 31000,
                "rva": 0x3111000,
                "label": "Game.Player::set_health",
                "class": "Game.Player",
                "name": "set_health",
                "isStatic": False,
                "generic": True,
                "abstract": False,
                "methodRole": "setter",
                "applicationOwned": True,
                "domains": ["health"],
                "semanticDomains": ["health"],
                "callerCount": 1,
                "calleeCount": 1,
            },
        ],
    )

    report = enrich_catalog({"cards": []}, tmp_path)
    cards = {card["id"]: card for card in report["cards"]}

    card = cards["MethodCatalog:10585"]
    assert card["locator"]["rva"] == 0x1FE7640
    assert card["locator"]["metadataMethodId"] == 10585
    assert card["locator"]["class"] == "IGameTime"
    assert card["locator"]["method"] == "set_timeScale"
    assert card["verificationStage"] == "LOCATOR_CONFIRMED"
    assert card["actionable"] is True
    assert card["buildable"] is False
    assert card["patchReady"] is False
    assert card["evidence"]["runtimeConfirmed"] is False
    assert card["evidence"]["promotesBuildability"] is False
    assert card["methodBoundEvidence"] is True
    assert card["controlCandidate"] is True

    assert "MethodCatalog:21000" not in cards
    assert "MethodCatalog:31000" not in cards
    handoff = report["fileBackedMethodHandoff"]
    assert handoff["methodCardsAdded"] == 1
    assert handoff["buildabilityPromoted"] is False
    assert handoff["runtimeClaimed"] is False


def test_framework_and_sdk_token_collisions_are_demoted(tmp_path: Path):
    report = {
        "cards": [
            {
                "id": "native-cxa",
                "title": "__cxa_call_unexpected",
                "category": "Gameplay",
                "ownership": "APP_OR_GAME",
                "gameplayDomain": "level_xp",
                "controlCandidate": True,
                "buildable": False,
                "selectable": True,
                "important": True,
                "priority": 96,
                "evidence": {"kind": "native-symbol", "value": "__cxa_call_unexpected"},
                "locator": {"rva": 0x1000, "library": "libil2cpp.so"},
            },
            {
                "id": "crash-logger",
                "title": "UQM::CSLogger::setLoggerLevel",
                "category": "Gameplay",
                "ownership": "APP_OR_GAME",
                "gameplayDomain": "level_xp",
                "controlCandidate": True,
                "buildable": False,
                "selectable": True,
                "important": True,
                "priority": 94,
                "evidence": {"kind": "native-symbol", "value": "setLoggerLevel", "library": "libCrashSight.so"},
                "locator": {"rva": 0x2000, "library": "libCrashSight.so"},
            },
            {
                "id": "goldfish",
                "title": "/sys/module/goldfish_audio",
                "category": "Gameplay",
                "ownership": "APP_OR_GAME",
                "gameplayDomain": "currency",
                "controlCandidate": True,
                "buildable": False,
                "selectable": True,
                "important": True,
                "priority": 90,
                "evidence": {"kind": "string", "value": "/sys/module/goldfish_audio"},
                "locator": {},
            },
        ]
    }

    out = enrich_catalog(report, tmp_path)
    cards = {card["id"]: card for card in out["cards"]}

    assert cards["native-cxa"]["ownership"] == "FRAMEWORK"
    assert cards["crash-logger"]["ownership"] == "BUNDLED_SDK"
    assert cards["goldfish"]["ownership"] == "FRAMEWORK"
    for card in cards.values():
        assert card["gameplayDomain"] is None
        assert card["controlCandidate"] is False
        assert card["selectable"] is False
        assert card["buildable"] is False
        assert card["important"] is False
        assert card["lowSignal"] is True
        assert card["priority"] <= 32
        assert card["semanticNoiseReason"] == "framework-or-sdk-token-collision"
    assert out["fileBackedMethodHandoff"]["falsePositiveCardsDemoted"] == 3


def test_re_diagnostics_expose_effective_filebacked_rows_without_inventing_xrefs(tmp_path: Path):
    write_json(
        tmp_path / "analysis.json",
        {
            "metadata_method_catalog": {
                "rows": 167426,
                "addressConfirmed": 148875,
                "directBlObserved": 44729,
                "storage": "jsonl-file-backed",
                "file": "analysis.methods.jsonl",
            }
        },
    )
    write_json(
        tmp_path / "re-analysis.json",
        {
            "pipelineDiagnostics": {
                "il2cppRows": 0,
                "il2cppDirectCallRefs": 0,
                "contextMethods": 0,
            }
        },
    )
    write_jsonl(
        tmp_path / "analysis.autopilot-index.jsonl",
        [
            {
                "metadataMethodId": 10585,
                "rva": 0x1FE7640,
                "label": "IGameTime::set_timeScale",
                "class": "IGameTime",
                "name": "set_timeScale",
                "isStatic": True,
                "generic": False,
                "abstract": False,
                "methodRole": "setter",
                "applicationOwned": True,
                "semanticDomains": ["movement"],
                "callerCount": 1,
                "calleeCount": 4,
            }
        ],
    )

    enrich_catalog({"cards": []}, tmp_path)
    repaired = json.loads((tmp_path / "re-analysis.json").read_text(encoding="utf-8"))
    diag = repaired["pipelineDiagnostics"]

    assert diag["il2cppRows"] == 0
    assert diag["il2cppDirectCallRefs"] == 0
    assert diag["contextMethods"] == 0
    assert diag["il2cppEffectiveRows"] == 167426
    assert diag["il2cppEffectiveRowsSource"] == "file-backed-method-catalog"
    fb = diag["fileBackedMethodCatalog"]
    assert fb["rows"] == 167426
    assert fb["addressConfirmed"] == 148875
    assert fb["directBlObserved"] == 44729
    assert fb["handoffCandidates"] == 1
    assert fb["runtimeTruth"] == "not-observed-by-static-analysis"


def test_release_catalog_runs_handoff_before_quality_refinement():
    source = Path(__file__).resolve().parents[1] / "modkit/mobile/simple_mode_cancellable.py"
    text = source.read_text(encoding="utf-8")
    assert "from modkit.mobile import filebacked_method_handoff as _handoff" in text
    assert "_handoff.enrich_catalog(report, workdir, gate.tick)" in text
    assert text.index("_handoff.enrich_catalog(report, workdir, gate.tick)") < text.index("_quality.refine_catalog(report)")
