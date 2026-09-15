from __future__ import annotations

import json
from pathlib import Path

from modkit.mobile.connected_report import build_connected_report


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_connected_report_links_method_id_rva_and_name_and_summarizes_deep_engines(tmp_path: Path):
    methods = [
        {"id": 7, "name": "TakeDamage", "rva": "0x1234", "class": "Player"},
        {"id": 8, "name": "AddCoins", "rva": "0x4560", "class": "Wallet"},
        {"id": 9, "name": "SetHealth", "rva": "0x7890", "class": "Player"},
    ]
    (tmp_path / "analysis.methods.jsonl").write_text(
        "\n".join(json.dumps(row) for row in methods) + "\n", encoding="utf-8"
    )
    _write_json(
        tmp_path / "simple-catalog.json",
        {
            "total": 4,
            "important": 4,
            "buildable": 2,
            "actionable": 3,
            "serverAudit": 1,
            "cards": [
                {"id": "a", "title": "Damage", "locator": {"methodId": 7}},
                {"id": "b", "title": "Coins", "locator": {"rva": 0x4560}},
                {"id": "c", "title": "Health", "locator": {"method": "SetHealth"}},
                {"id": "d", "title": "Unknown", "locator": {"method": "NoSuchMethod"}},
            ],
        },
    )
    _write_json(tmp_path / "analysis.summary.json", {"targetProfile": "GAME"})
    _write_json(tmp_path / "security-surfaces.json", {"summary": {"tls": 1}})
    _write_json(
        tmp_path / "embedded-analysis.json",
        {
            "schema": "modkit-embedded-analysis-1.3",
            "runs": [
                {"engineId": "lua.bytecode-embedded", "status": "SUCCESS"},
                {"engineId": "native.deep-embedded", "status": "SUCCESS"},
                {"engineId": "cocos.deep-embedded", "status": "SUCCESS"},
                {"engineId": "flutter.aot-embedded", "status": "UNAVAILABLE"},
            ],
        },
    )
    _write_json(
        tmp_path / "artifact-families.json",
        {
            "familyCounts": {"lua": 2, "cocos": 1},
            "recoveryCounts": {"DISASSEMBLED_METADATA": 2},
            "deepLua": {"mergedFindingCount": 3},
            "deepNative": {"mergedFindingCount": 4},
            "deepCocos": {"mergedFindingCount": 2},
        },
    )
    _write_json(
        tmp_path / "lua-deep.json",
        {
            "engineId": "lua.bytecode-embedded",
            "available": True,
            "findingCount": 3,
            "chunkCount": 2,
            "chunks": [
                {"status": "BYTECODE_DISASSEMBLED", "recoveryLevel": "DISASSEMBLED_METADATA"},
                {"status": "OPAQUE_OR_ENCRYPTED", "recoveryLevel": "OPAQUE"},
            ],
        },
    )
    _write_json(
        tmp_path / "native-deep.json",
        {
            "engineId": "native.deep-embedded",
            "analyzedLibraryCount": 1,
            "findingCount": 4,
            "libraries": [
                {"directCallCount": 5, "tailCallCount": 2, "indirectSlotCount": 3},
            ],
        },
    )
    _write_json(
        tmp_path / "cocos-deep.json",
        {
            "engineId": "cocos.deep-embedded",
            "available": True,
            "findingCount": 2,
            "detectionConfidence": "HIGH",
            "nativeLibraryCount": 1,
            "scriptArtifactCount": 2,
            "bridgeSymbolCount": 1,
            "correlationCount": 1,
        },
    )
    _write_json(tmp_path / "apktool-analysis.json", {"status": "OK", "decoded": 1, "failed": 0})

    out_json = tmp_path / "connected-report.json"
    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, out_json, out_md)

    assert report["schema"] == "modkit-connected-report-1.1"
    assert report["findingCount"] == 4
    assert report["exactLinked"] == 3
    assert report["unresolvedLinks"] == 1
    assert report["methodCatalogRows"] == 3
    assert report["embedded"]["manualImportRequired"] is False
    assert report["embedded"]["pipelineSchema"] == "modkit-embedded-analysis-1.3"
    assert report["embedded"]["familyCounts"]["lua"] == 2
    assert [row["methodLinkStatus"] for row in report["findings"]] == [
        "EXACT_METHOD_ID",
        "EXACT_RVA",
        "EXACT_NAME",
        "UNRESOLVED",
    ]
    assert report["findings"][0]["linkedMethods"][0]["name"] == "TakeDamage"
    assert report["findings"][1]["linkedMethods"][0]["name"] == "AddCoins"
    assert report["findings"][2]["linkedMethods"][0]["name"] == "SetHealth"

    coverage = {row["engineId"]: row for row in report["engineCoverage"]}
    assert coverage["lua.bytecode-embedded"]["available"] is True
    assert coverage["lua.bytecode-embedded"]["decodedChunks"] == 1
    assert coverage["lua.bytecode-embedded"]["opaqueChunks"] == 1
    assert coverage["native.deep-embedded"]["directCallCount"] == 5
    assert coverage["native.deep-embedded"]["tailCallCount"] == 2
    assert coverage["native.deep-embedded"]["indirectSlotCount"] == 3
    assert coverage["cocos.deep-embedded"]["correlationCount"] == 1
    assert coverage["cocos.deep-embedded"]["detectionConfidence"] == "HIGH"
    assert coverage["flutter.aot-embedded"]["available"] is False
    assert report["summary"]["deepEnginesAvailable"] == 3

    guide = {row["file"]: row for row in report["artifactGuide"]}
    assert guide["lua-deep.json"]["available"] is True
    assert guide["cocos-deep.json"]["available"] is True
    assert guide["analysis.methods.jsonl"]["available"] is True
    assert "where" not in report  # guide is structured, not a prose-only field.

    assert out_json.is_file()
    markdown = out_md.read_text(encoding="utf-8")
    assert "Exact method/locator links: 3" in markdown
    assert "Deep engines available: 3/5" in markdown
    assert "## Deep engine coverage" in markdown
    assert "## Где что смотреть" in markdown
    assert "lua.bytecode-embedded" in markdown
    assert "cocos-deep.json" in markdown
