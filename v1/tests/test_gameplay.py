

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
    assert health["bridges"][0]["reviewOnlySemantic"] is True
    assert health["bridges"][0]["automationExcluded"] is True
    assert health["bridges"][0]["semanticEvidenceRole"] == "xref-bridge"


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


def test_ambiguous_app_owned_accessors_are_review_only_domains():
    from modkit.mobile.gameplay import _accessor_review_domains

    assert _accessor_review_domains("GetLevel", "query", owner="a.b.C", application_owned=True) == ["progression"]
    assert _accessor_review_domains("SetBalance", "setter", owner="a.b.C", application_owned=True) == ["currency"]
    assert _accessor_review_domains("GetMP", "query", owner="a.b.C", application_owned=True) == ["resource"]
    assert _accessor_review_domains("SetCD", "setter", owner="a.b.C", application_owned=True) == ["cooldown"]
    assert _accessor_review_domains("GetLife", "query", owner="a.b.C", application_owned=True) == ["health"]

    assert _accessor_review_domains("GetLevel", "query", owner="a.b.C", application_owned=False) == []
    assert _accessor_review_domains("GetLevel", "action", owner="a.b.C", application_owned=True) == []
    assert _accessor_review_domains("GetLevel", "query", owner="Game.Logger", application_owned=True) == []


def test_accessor_review_domain_reaches_coverage_without_confirmation(tmp_path):
    import json
    from modkit.mobile.gameplay import build_gameplay_coverage

    graph = tmp_path / "analysis.evidence-graph.jsonl"
    fields = tmp_path / "analysis.fields.jsonl"
    fields.write_text("", encoding="utf-8")
    graph.write_text(json.dumps({
        "metadataMethodId": 41,
        "label": "a.b.C::GetLevel",
        "class": "a.b.C",
        "name": "GetLevel",
        "rva": 0x4100,
        "isStatic": False,
        "typedFieldAccesses": [],
        "callers": [],
        "callees": [],
        "applicationOwned": True,
        "domains": [],
        "bridgeDomains": [],
        "semanticDomains": [],
        "accessorReviewDomains": ["progression"],
        "reviewDomains": ["progression"],
        "methodRole": "query",
    }) + "\n", encoding="utf-8")

    report = build_gameplay_coverage(graph, fields)
    progression = next(card for card in report["cards"] if card["domain"] == "progression")
    assert progression["status"] == "REVIEW"
    assert [row["metadataMethodId"] for row in progression["methods"]] == [41]
    assert progression["methods"][0]["accessorReviewDomains"] == ["progression"]
    assert progression["methods"][0]["typedFieldAccesses"] == []
    assert progression["methods"][0]["reviewOnlySemantic"] is True
    assert progression["methods"][0]["automationExcluded"] is True
    assert progression["methods"][0]["semanticEvidenceRole"] == "ambiguous-accessor"


def test_accessor_review_domains_stay_out_of_automatic_binding_seed():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/gameplay.py").read_text(encoding="utf-8")
    graph_block = source.split("def build_evidence_graph", 1)[1].split("\ndef graph_method", 1)[0]
    assert 'review_domains = sorted(set(node.get("accessorReviewDomains") or []))' in graph_block
    assert '"reviewDomains": review_domains' in graph_block
    assert 'semantic_domains = sorted(set(node.get("domains") or []) | set(field_domains) | set(bridge_domains.get(mid, [])))' in graph_block
    assert 'and semantic_domains' in graph_block
    assert 'semantic_domains | review_domains' not in graph_block


def test_compound_gameplay_terms_use_token_order_not_set_iteration():
    from modkit.mobile.gameplay import _method_domain_relevant, _package_domains, domains_for

    assert "movement" in _package_domains("PlayerMoveSpeed")
    assert "movement" in _package_domains("TimeScale")
    assert "progression" in _package_domains("LevelUp")
    assert "progression" in _package_domains("SkillPoints")
    assert "world" in _package_domains("GameTime")

    assert "health" in domains_for("GetHitPoints", owner="a.b.C")
    assert _method_domain_relevant({
        "class": "a.b.C", "name": "GetHitPoints", "applicationOwned": True,
        "typedFieldAccesses": [], "bridgeDomains": [], "accessorReviewDomains": [],
    }, "health")
    assert _method_domain_relevant({
        "class": "a.b.C", "name": "GetSkillPoints", "applicationOwned": True,
        "typedFieldAccesses": [], "bridgeDomains": [], "accessorReviewDomains": [],
    }, "progression")
    assert _method_domain_relevant({
        "class": "a.b.C", "name": "SetTimeScale", "applicationOwned": True,
        "typedFieldAccesses": [], "bridgeDomains": [], "accessorReviewDomains": [],
    }, "movement")

    # Curated compound matching must not turn arbitrary substrings into domains.
    assert not _method_domain_relevant({
        "class": "a.b.C", "name": "StorageManager", "applicationOwned": True,
        "typedFieldAccesses": [], "bridgeDomains": [], "accessorReviewDomains": [],
    }, "resource")


def test_compound_matching_does_not_build_compact_text_from_a_set():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/gameplay.py").read_text(encoding="utf-8")
    package = source.split("def _package_domains", 1)[1].split("\ndef ", 1)[0]
    relevant = source.split("def _method_domain_relevant", 1)[1].split("\ndef ", 1)[0]
    assert 'compact="".join(token_list)' in package
    assert 'compact = "".join(token_list)' in relevant
    assert '"".join(tokens)' not in package
    assert '"".join(tokens)' not in relevant
