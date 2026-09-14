from __future__ import annotations

import json
from pathlib import Path

from modkit.mobile.connected_report import build_connected_report


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_connected_report_links_method_id_rva_and_name(tmp_path: Path):
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
    _write_json(tmp_path / "embedded-analysis.json", {"familyCounts": {"hermes": 1}})
    _write_json(tmp_path / "apktool-analysis.json", {"status": "OK", "decoded": 1, "failed": 0})

    out_json = tmp_path / "connected-report.json"
    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, out_json, out_md)

    assert report["findingCount"] == 4
    assert report["exactLinked"] == 3
    assert report["unresolvedLinks"] == 1
    assert report["methodCatalogRows"] == 3
    assert report["embedded"]["manualImportRequired"] is False
    assert [row["methodLinkStatus"] for row in report["findings"]] == [
        "EXACT_METHOD_ID",
        "EXACT_RVA",
        "EXACT_NAME",
        "UNRESOLVED",
    ]
    assert report["findings"][0]["linkedMethods"][0]["name"] == "TakeDamage"
    assert report["findings"][1]["linkedMethods"][0]["name"] == "AddCoins"
    assert report["findings"][2]["linkedMethods"][0]["name"] == "SetHealth"
    assert out_json.is_file()
    assert "Exact method/locator links: 3" in out_md.read_text(encoding="utf-8")
