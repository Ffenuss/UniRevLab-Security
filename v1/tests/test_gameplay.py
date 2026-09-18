

def test_package_evidence_scans_nested_split_apks(tmp_path):
    import zipfile
    from modkit.mobile.gameplay import scan_apk_package_evidence
    base=tmp_path/'base.apk'; feature=tmp_path/'feature_game.apk'; apkset=tmp_path/'installed-apk-set.zip'
    with zipfile.ZipFile(base,'w') as z:
        z.writestr('AndroidManifest.xml',b'x')
        z.writestr('classes.dex',b'dex\n035\0 ordinary')
    with zipfile.ZipFile(feature,'w') as z:
        z.writestr('AndroidManifest.xml',b'x')
        z.writestr('assets/StreamingAssets/progression.lua',b'hero level cooldown diamond')
    with zipfile.ZipFile(apkset,'w') as z:
        z.write(base,'base.apk'); z.write(feature,'feature_game.apk')
    rows=scan_apk_package_evidence(apkset)
    assert any(str(x.get('artifact','')).startswith('feature_game.apk!') for x in rows)
    assert any('progression.lua' in str(x.get('artifact','')) and x.get('kind')=='script/content-layer' for x in rows)


def test_obfuscated_application_owned_fields_keep_concrete_gameplay_domains():
    from modkit.mobile.gameplay import domains_for

    assert domains_for("currentHP", owner="a.b.C", field=True, application_owned=True) == ["health"]
    assert "damage" in domains_for("Armor", owner="x.y.Z", field=True, application_owned=True)
    assert "resource" in domains_for("maxMana", owner="x.y.Z", field=True, application_owned=True)
    assert "inventory" in domains_for("Ammo", owner="x.y.Z", field=True, application_owned=True)
    assert "currency" in domains_for("Coins", owner="x.y.Z", field=True, application_owned=True)
    assert "progression" in domains_for("Experience", owner="x.y.Z", field=True, application_owned=True)

    # Ambiguous state names still require gameplay owner context.
    assert domains_for("level", owner="x.y.Z", field=True, application_owned=True) == []
    assert domains_for("speed", owner="x.y.Z", field=True, application_owned=True) == []
    assert domains_for("balance", owner="x.y.Z", field=True, application_owned=True) == []

    # A concrete token in an unproven/third-party type is not enough by itself.
    assert domains_for("Health", owner="x.y.Z", field=True, application_owned=False) == []


def test_application_owned_strong_method_survives_obfuscated_owner_as_review(tmp_path):
    import json
    from modkit.mobile.gameplay import build_gameplay_coverage

    graph = tmp_path / "analysis.evidence-graph.jsonl"
    fields = tmp_path / "analysis.fields.jsonl"
    fields.write_text("", encoding="utf-8")
    graph.write_text(json.dumps({
        "metadataMethodId": 10,
        "label": "a.b.C::GetHealth",
        "class": "a.b.C",
        "name": "GetHealth",
        "rva": 0x1200,
        "isStatic": False,
        "typedFieldAccesses": [],
        "callers": [],
        "callees": [],
        "applicationOwned": True,
        "domains": ["health"],
        "bridgeDomains": [],
        "semanticDomains": ["health"],
        "methodRole": "query",
    }) + "\n", encoding="utf-8")

    report = build_gameplay_coverage(graph, fields)
    health = next(card for card in report["cards"] if card["domain"] == "health")
    assert health["status"] == "REVIEW"
    assert [row["metadataMethodId"] for row in health["methods"]] == [10]
    assert health["bridges"] == []


def test_same_domain_graph_bridge_is_visible_but_never_confirmed(tmp_path):
    import json
    from modkit.mobile.gameplay import build_gameplay_coverage

    graph = tmp_path / "analysis.evidence-graph.jsonl"
    fields = tmp_path / "analysis.fields.jsonl"
    fields.write_text("", encoding="utf-8")
    graph.write_text(json.dumps({
        "metadataMethodId": 20,
        "label": "a.b.C::a",
        "class": "a.b.C",
        "name": "a",
        "rva": 0x2200,
        "isStatic": False,
        "typedFieldAccesses": [],
        "callers": [{"metadataMethodId": 19, "kind": "bl", "callRva": 0x2100}],
        "callees": [{"metadataMethodId": 21, "kind": "bl", "callRva": 0x2210}],
        "applicationOwned": True,
        "domains": [],
        "bridgeDomains": ["health"],
        "semanticDomains": ["health"],
        "methodRole": "unknown",
    }) + "\n", encoding="utf-8")

    report = build_gameplay_coverage(graph, fields)
    health = next(card for card in report["cards"] if card["domain"] == "health")
    assert health["status"] == "REVIEW"
    assert health["methods"] == []
    assert [row["metadataMethodId"] for row in health["bridges"]] == [20]
    assert health["bridges"][0]["bridgeDomains"] == ["health"]


def test_third_party_strong_method_does_not_bypass_owner_gate(tmp_path):
    import json
    from modkit.mobile.gameplay import build_gameplay_coverage

    graph = tmp_path / "analysis.evidence-graph.jsonl"
    fields = tmp_path / "analysis.fields.jsonl"
    fields.write_text("", encoding="utf-8")
    graph.write_text(json.dumps({
        "metadataMethodId": 30,
        "label": "ThirdParty.Client::GetHealth",
        "class": "ThirdParty.Client",
        "name": "GetHealth",
        "rva": 0x3200,
        "isStatic": False,
        "typedFieldAccesses": [],
        "callers": [],
        "callees": [],
        "applicationOwned": False,
        "domains": ["health"],
        "bridgeDomains": [],
        "semanticDomains": ["health"],
        "methodRole": "query",
    }) + "\n", encoding="utf-8")

    report = build_gameplay_coverage(graph, fields)
    health = next(card for card in report["cards"] if card["domain"] == "health")
    assert health["status"] == "NOT FOUND LOCAL"
    assert health["methods"] == []
    assert health["bridges"] == []


def test_compact_gameplay_summary_keeps_related_xref_methods_visible():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/engine.py").read_text(encoding="utf-8")
    block = source.split("def build_gameplay_discovery", 1)[1].split("\ndef ", 1)[0]
    assert "'relatedMethods':related" in block
    assert "'relatedMethodCount':len(card.get('bridges') or [])" in block
    assert "'fieldCount':len(card.get('fields') or [])" in block
    assert "'methodCount':len(card.get('methods') or [])" in block
