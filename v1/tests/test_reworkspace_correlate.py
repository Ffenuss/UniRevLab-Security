from modkit.reworkspace.correlate import analyze_artifacts
from modkit.selftest import fixtures


def test_cross_artifact_correlation():
    dex = b"dex\n035\0" + b"Lcom/android/support/Menu; WindowManager overlay floating modmenu"
    so = bytearray(fixtures.so_blob())
    # Append evidence outside sections; symbol evidence from fixture still supplies il2cpp.
    # Native menu/hook evidence is provided as another artifact string container.
    extra = b"DobbyHook hookFunction modmenu console damage health"
    result = analyze_artifacts({"classes3.dex": dex, "lib/arm64-v8a/libil2cpp.so": bytes(so), "assets/native-markers.txt": extra})
    cats = {f["category"]: f for f in result["findings"]}
    assert "menu_overlay" in cats
    assert cats["menu_overlay"]["status"] in {"correlated", "confirmed"}
    assert "il2cpp_surface" in cats


def test_mana_does_not_match_activity_manager():
    result = analyze_artifacts({"classes.dex": b"dex\\n035\\0Landroid/app/ActivityManager; PackageManager"})
    cats = {f["category"] for f in result["findings"]}
    assert "gameplay_controls" not in cats


def test_control_candidates_include_unity_cheat_surface_without_binding():
    from modkit.reworkspace.correlate import derive_control_candidates
    report = {
        "findings": [],
        "unity": {"bundles": [{
            "apk_entry": "assets/game.bundle",
            "matched_strings": ["Cheat_Invic", "Cheat_NoClip", "Canvas_CheatOverlay", "ordinary text"],
        }]},
    }
    candidates = derive_control_candidates(report)
    titles = {c["title"]: c for c in candidates}
    assert "Cheat Invic" in titles
    assert titles["Cheat Invic"]["suggestedType"] == "toggle"
    assert titles["Cheat Invic"]["binding"] is None
    assert titles["Cheat Invic"]["evidenceRva"] is None


def test_control_candidates_merge_unity_and_il2cpp_evidence():
    from modkit.reworkspace.correlate import derive_control_candidates
    report = {
        "findings": [],
        "unity": {"bundles": [{
            "apk_entry": "assets/game.bundle",
            "matched_strings": ["Cheat_Invic"],
        }]},
        "il2cpp": {"metadata_resolved_methods": [{
            "label": "Cheat_Invic",
            "image": "Drova.dll",
            "rva": 0x12340,
            "resolution": "confirmed-unique",
        }]},
    }
    candidates = derive_control_candidates(report)
    c = next(x for x in candidates if x["title"] == "Cheat Invic")
    assert c["status"] == "correlated"
    assert c["evidenceRva"] == 0x12340
    assert c["evidenceCount"] == 2
    assert c["confidence"] >= 0.95
    assert {c["kind"], *(e["kind"] for e in c["corroboratingEvidence"])} >= {"unity-string", "il2cpp-metadata-method"}


def test_il2cpp_structured_method_becomes_review_candidate_with_rva():
    from modkit.reworkspace.correlate import derive_control_candidates
    report = {
        "findings": [],
        "il2cpp": {"candidates": [{
            "label": "PlayerCheat::GetInfiniteStamina",
            "image": "Drova.dll",
            "rva": 0x45678,
        }]},
    }
    candidates = derive_control_candidates(report)
    c = next(x for x in candidates if "InfiniteStamina" in x["value"])
    assert c["kind"] == "rodroid-method"
    assert c["evidenceRva"] == 0x45678
    assert c["binding"] is None


def test_candidate_preserves_calling_contract_as_review_evidence():
    from modkit.reworkspace.correlate import derive_control_candidates
    contract = {
        'signature': 'void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);',
        'isStatic': False,
        'bindingSuggestion': 'bool_setter',
        'bindingBlocker': 'instance-method-needs-confirmed-instance-resolver',
    }
    report = {'findings': [], 'il2cpp': {'discoveries': [{
        'label': 'X.CheatHandler::EnableCheat()', 'image': 'Game.dll', 'rva': 0x2000,
        'item_type': 'method', 'signature_contract': contract,
    }]}}
    c = derive_control_candidates(report)[0]
    assert c['evidenceRva'] == 0x2000
    assert c['bindingSuggestion'] == 'bool_setter'
    assert c['isStatic'] is False
    assert c['bindingBlocker'] == 'instance-method-needs-confirmed-instance-resolver'


def test_instance_control_gets_same_class_tryget_resolver_candidate():
    from modkit.reworkspace.correlate import derive_control_candidates
    inst = {
        'signature': 'void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);',
        'isStatic': False, 'bindingSuggestion': 'bool_setter',
        'bindingBlocker': 'instance-method-needs-confirmed-instance-resolver',
    }
    resolver = {
        'signature': 'bool X__TryGet (X_o** handler, const MethodInfo* method);',
        'isStatic': True, 'bindingSuggestion': None, 'resolverSuggestion': 'out_ptr_bool',
    }
    report = {'findings': [], 'il2cpp': {'discoveries': [
        {'label': 'X.CheatHandler::EnableCheat()', 'image': 'Game.dll', 'rva': 0x2000,
         'item_type': 'method', 'signature_contract': inst},
        {'label': 'X.CheatHandler::TryGet()', 'image': 'Game.dll', 'rva': 0x3000,
         'item_type': 'method', 'signature_contract': resolver},
    ]}}
    c = next(x for x in derive_control_candidates(report) if 'EnableCheat' in x['value'])
    assert c['isStatic'] is False
    assert c['resolverRva'] == 0x3000
    assert c['resolverKind'] == 'out_ptr_bool'
    assert c['instanceResolver']['label'].endswith('::TryGet()')
    assert c['bindingBlocker'] == 'instance-resolver-review-required'


def test_instance_control_gets_exact_metadata_target_resolver_as_verified():
    from modkit.reworkspace.correlate import derive_control_candidates
    inst = {
        'signature': 'void Metadata__EnableDebug (void* __this, bool value, const MethodInfo* method);',
        'isStatic': False, 'bindingSuggestion': 'bool_setter',
        'bindingBlocker': 'instance-method-needs-confirmed-instance-resolver',
        'contractSource': 'global-metadata+CodeRegistration',
    }
    resolver = {
        'signature': 'void* Metadata__get_Instance (const MethodInfo* method);',
        'isStatic': True, 'bindingSuggestion': None, 'resolverSuggestion': 'return_ptr',
        'resolverTargetVerified': True, 'resolverTargetImage': 'Game.dll',
        'resolverTargetClass': 'Game.DebugController',
        'contractSource': 'global-metadata+CodeRegistration',
    }
    report = {'findings': [], 'il2cpp': {'metadata_callable_methods': [
        {'label': 'Game.DebugController::EnableDebug', 'image': 'Game.dll', 'rva': 0x2000,
         'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
         'signature_contract': inst},
        {'label': 'Game.DebugRegistry::get_Instance', 'image': 'Game.dll', 'rva': 0x3000,
         'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
         'signature_contract': resolver},
    ]}}
    c = next(x for x in derive_control_candidates(report) if 'EnableDebug' in x['value'])
    assert c['resolverRva'] == 0x3000
    assert c['resolverKind'] == 'return_ptr'
    assert c['resolverVerified'] is True
    assert c['resolverMatch'] == 'metadata-target-type-exact'
    assert c['bindingBlocker'] is None
    assert c['instanceResolver']['targetClass'] == 'Game.DebugController'


def test_exact_resolver_is_not_attached_to_different_target_type():
    from modkit.reworkspace.correlate import derive_control_candidates
    inst = {
        'signature': 'void Metadata__EnableDebug (void* __this, bool value, const MethodInfo* method);',
        'isStatic': False, 'bindingSuggestion': 'bool_setter',
        'bindingBlocker': 'instance-method-needs-confirmed-instance-resolver',
        'contractSource': 'global-metadata+CodeRegistration',
    }
    resolver = {
        'signature': 'void* Metadata__get_Instance (const MethodInfo* method);',
        'isStatic': True, 'resolverSuggestion': 'return_ptr',
        'resolverTargetVerified': True, 'resolverTargetImage': 'Game.dll',
        'resolverTargetClass': 'Game.OtherController',
        'contractSource': 'global-metadata+CodeRegistration',
    }
    report = {'findings': [], 'il2cpp': {'metadata_callable_methods': [
        {'label': 'Game.DebugController::EnableDebug', 'image': 'Game.dll', 'rva': 0x2000,
         'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
         'signature_contract': inst},
        {'label': 'Game.Registry::get_Instance', 'image': 'Game.dll', 'rva': 0x3000,
         'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
         'signature_contract': resolver},
    ]}}
    c = next(x for x in derive_control_candidates(report) if 'EnableDebug' in x['value'])
    assert c['resolverRva'] is None
    assert c['resolverVerified'] is False
    assert c['bindingBlocker'] == 'instance-method-needs-confirmed-instance-resolver'


def test_structured_developer_control_api_finding_uses_verified_rodroid_contracts():
    from modkit.reworkspace import augment_structured_findings
    from modkit.reworkspace.signature import rodroid_signature_contract

    a = 'void Drova_Cheat_Cheat_Damage__set_IsMaxed (bool value, const MethodInfo* method);'
    b = 'void Drova_Cheat_Cheat_TimeScale__SetTimeScale (float time, const MethodInfo* method);'
    report = {
        'findings': [],
        'il2cpp': {'discoveries': [
            {'label': 'Drova.Cheat.Cheat_Damage::set_IsMaxed()', 'image': 'Drova.dll', 'rva': 0x1000,
             'signature_contract': rodroid_signature_contract(a)},
            {'label': 'Drova.Cheat.Cheat_TimeScale::SetTimeScale()', 'image': 'Drova.dll', 'rva': 0x2000,
             'signature_contract': rodroid_signature_contract(b)},
            # Constructor-shaped evidence must not count as a callable control.
            {'label': 'Drova.Cheat.Cheat_X::.ctor()', 'image': 'Drova.dll', 'rva': 0x3000,
             'signature_contract': rodroid_signature_contract('void Drova_Cheat_Cheat_X___ctor (int32_t value, const MethodInfo* method);')},
        ]},
        'unity': {'bundles': [{'apk_entry': 'assets/game.bundle', 'matched_strings': ['Canvas_CheatOverlay']}]},
    }
    augment_structured_findings(report)
    f = next(x for x in report['findings'] if x['id'] == 're.structured_developer_control_api')
    assert f['status'] == 'confirmed'
    assert f['confidence'] == 0.98
    calls = [e for e in f['evidence'] if e['kind'] == 'rodroid-call-contract']
    assert len(calls) == 2
    assert all(e['location'].startswith('RVA 0x') for e in calls)
    assert any(e['kind'] == 'unity-control-marker' for e in f['evidence'])


def test_native_inventory_exposes_symbol_and_dependency_relationships():
    from modkit.selftest import fixtures
    result = analyze_artifacts({"lib/arm64-v8a/libsample.so": fixtures.so_blob()})
    native = result["inventory"]["native"][0]
    assert native["symbolSummary"]["functions"] >= 2
    assert "il2cpp_domain_get" in native["symbolSummary"]["exportsSample"]
    assert native["linkingSymbols"]["exportRvas"]["il2cpp_domain_get"] > 0
    assert set(native["needed"]) >= {"liblog.so", "libandroid.so"}
    rel = result["nativeRelations"]
    assert rel["libraries"] == 1
    assert any(x["dependency"] == "liblog.so" for x in rel["externalDependencies"])
    assert result["schema"] == "modkit-re-1.2"


def test_dex_to_native_link_uses_library_string_and_jni_onload():
    # We only claim static linkage evidence: matching library-name + loadLibrary marker.
    from modkit.selftest import fixtures
    dex = b"dex\n035\0" + b"loadLibrary\0neon\0Lcom/example/Menu;\0"
    result = analyze_artifacts({
        "classes3.dex": dex,
        "lib/arm64-v8a/libneon.so": fixtures.so_blob(),
    })
    links = result["nativeRelations"]["dexNativeLinks"]
    assert links and links[0]["from"] == "classes3.dex"
    assert links[0]["library"] == "libneon.so"
    assert links[0]["loadLibraryMarker"] is True


def test_native_embedded_library_string_edges_are_bounded_and_explicit():
    # A plain embedded lib*.so name is a reference edge, not a DT_NEEDED claim.
    from modkit.selftest import fixtures
    host = bytearray(fixtures.so_blob())
    host.extend(b"\0libpeer.so\0")
    result = analyze_artifacts({
        "lib/arm64-v8a/libhost.so": bytes(host),
        "lib/arm64-v8a/libpeer.so": fixtures.so_blob(),
    })
    edges = result["nativeRelations"]["embeddedLibraryStringEdges"]
    assert any(e["from"].endswith("libhost.so") and e["to"].endswith("libpeer.so") for e in edges)
    assert all(e["kind"] == "embedded-library-string" for e in edges)


def test_dex_native_loader_bridge_finding_requires_loader_name_and_jni_surface():
    from modkit.selftest import fixtures
    so = bytearray(fixtures.so_blob())
    old = b"il2cpp_domain_get"
    pos = so.find(old)
    assert pos >= 0
    repl = b"JNI_OnLoad" + b"\0" * (len(old) - len(b"JNI_OnLoad"))
    so[pos:pos+len(old)] = repl
    so.extend(b"\0libpeer.so\0")
    dex = b"dex\n035\0loadLibrary\0neon\0Lcom/example/Menu;\0"
    result = analyze_artifacts({
        "classes3.dex": dex,
        "lib/arm64-v8a/libneon.so": bytes(so),
        "lib/arm64-v8a/libpeer.so": fixtures.so_blob(),
    })
    f = next(x for x in result["findings"] if x["id"] == "re.dex_native_loader_bridge")
    assert f["status"] == "confirmed"
    kinds = {e["kind"] for e in f["evidence"]}
    assert "dex-native-link" in kinds
    assert "embedded-library-reference" in kinds


def test_arm64_direct_bl_xref_resolves_named_target():
    import struct
    from modkit.elf.reader import ElfFile
    from modkit.reworkspace.native import direct_bl_calls
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8  # il2cpp_domain_get in the fixture dynsym
    delta = target_rva - call_rva
    struct.pack_into('<I', blob, call_rva, 0x94000000 | ((delta >> 2) & 0x03FFFFFF))
    refs = direct_bl_calls(ElfFile(bytes(blob)), {target_rva})
    assert refs
    assert refs[0]['callRva'] == call_rva
    assert refs[0]['targetRva'] == target_rva
    assert refs[0]['targetFunction'] == 'il2cpp_domain_get'
    assert refs[0]['kind'] == 'arm64-direct-bl'


def test_augment_function_correlations_links_rodroid_rva_to_direct_call(tmp_path):
    import struct
    import zipfile
    from modkit.reworkspace import augment_function_correlations
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, call_rva, 0x94000000 | (((target_rva - call_rva) >> 2) & 0x03FFFFFF))
    apk = tmp_path / 'app.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', bytes(blob))
    report = {
        'findings': [],
        'nativeRelations': {},
        'il2cpp': {'discoveries': [{
            'label': 'Game.CheatHandler::EnableCheat()', 'image': 'Game.dll', 'rva': target_rva,
        }]},
    }
    augment_function_correlations(report, apk_path=apk)
    refs = report['nativeRelations']['il2cppDirectCallRefs']
    assert refs and refs[0]['targetRva'] == target_rva
    assert refs[0]['targetMethods'][0]['label'].endswith('EnableCheat()')
    assert any(f['id'] == 're.il2cpp_static_call_references' for f in report['findings'])


def test_function_correlation_attributes_callsite_to_managed_interval(tmp_path):
    import struct, zipfile
    from modkit.reworkspace import augment_function_correlations
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    source_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, source_rva, 0x94000000 | (((target_rva - source_rva) >> 2) & 0x03FFFFFF))
    apk = tmp_path / 'app.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', bytes(blob))
    report = {'findings': [], 'nativeRelations': {}, 'il2cpp': {'discoveries': [
        {'label': 'Game.CheatHandler::StartHandler()', 'image': 'Game.dll', 'rva': source_rva},
        {'label': 'Game.CheatHandler::EnableCheat()', 'image': 'Game.dll', 'rva': target_rva},
    ]}}
    augment_function_correlations(report, apk_path=apk)
    ref = report['nativeRelations']['il2cppDirectCallRefs'][0]
    assert ref['sourceMethodCandidates'][0]['label'].endswith('StartHandler()')
    assert ref['sourceAttribution'] == 'unique-managed-interval'
    finding = next(f for f in report['findings'] if f['id'] == 're.il2cpp_static_call_references')
    assert 'StartHandler()' in finding['evidence'][0]['value']


def test_static_relationship_graph_builds_only_directed_evidence_chain():
    from modkit.reworkspace import build_static_relationship_graph
    report = {
        'nativeRelations': {
            'dexNativeLinks': [{
                'from': 'classes3.dex', 'to': 'lib/arm64-v8a/libBedo.so', 'library': 'libBedo.so',
                'loadLibraryMarker': True, 'jniOnLoad': True, 'confidence': 0.92,
            }],
            'jniSurfaces': [{
                'artifact': 'lib/arm64-v8a/libBedo.so', 'exports': ['JNI_OnLoad'], 'hasJniOnLoad': True,
            }],
            'jniDirectCallRefs': [{
                'artifact': 'lib/arm64-v8a/libBedo.so', 'sourceFunction': 'JNI_OnLoad', 'sourceRva': 0x100,
                'targetFunction': 'install', 'targetRva': 0x120, 'callRva': 0x108,
            }],
            'dynamicSymbolEdges': [{
                'from': 'lib/arm64-v8a/libBedo.so', 'to': 'lib/arm64-v8a/libCore.so',
                'symbol': 'A64HookFunction', 'targetRva': 0x200, 'confidence': 0.88,
                'staticStringXrefs': [{'sourceFunction': 'install', 'sourceRva': 0x120, 'xrefRva': 0x130}],
            }],
        },
        'controlCandidates': [{
            'id': 'candidate.hook', 'title': 'Hook Function', 'source': 'lib/arm64-v8a/libCore.so',
            'value': 'A64HookFunction', 'kind': 'native-symbol', 'evidenceRva': 0x200,
            'confidence': 0.9, 'status': 'review', 'suggestedType': 'button', 'binding': None,
        }],
    }
    graph = build_static_relationship_graph(report)
    assert graph['summary']['completeChains'] == 1
    chain = graph['completeChains'][0]
    labels = [next(n['label'] for n in graph['nodes'] if n['id'] == node_id) for node_id in chain['nodes']]
    assert labels[0] == 'classes3.dex'
    assert 'JNI_OnLoad' in labels
    assert 'install' in labels
    assert 'A64HookFunction' in labels
    assert labels[-1] == 'Hook Function'
    kinds = [graph['edges'][i]['kind'] for i in chain['edges']]
    assert kinds == ['loads-library', 'exports-jni-entry', 'direct-call', 'dynamic-symbol-candidate', 'evidence-for-control']


def test_static_relationship_graph_reports_missing_bridge_instead_of_inventing_one():
    from modkit.reworkspace import build_static_relationship_graph
    report = {
        'nativeRelations': {
            'dexNativeLinks': [{
                'from': 'classes3.dex', 'to': 'lib/arm64-v8a/libBedo.so', 'library': 'libBedo.so',
                'loadLibraryMarker': True, 'jniOnLoad': True, 'confidence': 0.92,
            }],
            'jniSurfaces': [{'artifact': 'lib/arm64-v8a/libBedo.so', 'exports': ['JNI_OnLoad'], 'hasJniOnLoad': True}],
            'il2cppDirectCallRefs': [{
                'artifact': 'lib/arm64-v8a/libil2cpp.so', 'callRva': 0x3000, 'targetRva': 0x4000,
                'sourceMethodCandidates': [{'label': 'Game.Cheat::Start()', 'rva': 0x2F00}],
                'targetMethods': [{'label': 'Game.Cheat::Enable()', 'image': 'Game.dll'}],
                'sourceAttribution': 'unique-managed-interval', 'confidence': 0.96,
            }],
        },
        'controlCandidates': [{
            'id': 'candidate.enable', 'title': 'Enable', 'source': 'Game.dll', 'value': 'Game.Cheat::Enable()',
            'kind': 'rodroid-method', 'evidenceRva': 0x4000, 'confidence': 0.9, 'status': 'review',
            'suggestedType': 'button', 'binding': None,
        }],
    }
    graph = build_static_relationship_graph(report)
    assert graph['summary']['completeChains'] == 0
    assert graph['summary']['unlinkedControls'] == 1
    assert graph['gaps'][0]['reason'] == 'no-directed-static-path-from-dex-loader'
    # The IL2CPP method-to-control subgraph still exists; only the missing cross-library hop is refused.
    assert any(e['kind'] == 'managed-direct-call' for e in graph['edges'])
    assert any(e['kind'] == 'evidence-for-control' for e in graph['edges'])


def test_control_candidates_ignore_elf_debug_section_names():
    from modkit.reworkspace import derive_control_candidates
    report = {'findings': [{
        'id': 're.debug_console', 'title': 'Debug', 'category': 'debug_console',
        'status': 'candidate', 'confidence': 0.5, 'rationale': 'fixture',
        'evidence': [
            {'artifact': 'libx.so', 'kind': 'native-string', 'value': '.debug_info', 'location': 'file+0x10'},
            {'artifact': 'libx.so', 'kind': 'native-string', 'value': 'Cheat_NoClip', 'location': 'file+0x20'},
        ],
    }]}
    values = [x['value'] for x in derive_control_candidates(report)]
    assert '.debug_info' not in values
    assert 'Cheat_NoClip' in values


def test_semantic_verifier_requires_unique_managed_direct_call_context():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__EnableDebug (bool value, const MethodInfo* method);',
        'bindingSuggestion': 'bool_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Boolean',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [
            {'label': 'Game.DebugController::EnableDebug', 'image': 'Assembly-CSharp.dll', 'rva': 0x2000,
             'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
             'semantic': ['debug'], 'signature_contract': sig},
            {'label': 'Game.DebugController::ToggleDebugMenu', 'image': 'Assembly-CSharp.dll', 'rva': 0x1800,
             'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
             'semantic': ['debug'], 'signature_contract': {
                 'signature': 'void Metadata__ToggleDebugMenu (const MethodInfo* method);',
                 'bindingSuggestion': 'action', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True, 'autoBindingSafe': True,
             }},
        ]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x1810, 'targetRva': 0x2000, 'sourceAttribution': 'unique-metadata-method-interval',
            'sourceMethodCandidates': [{'label': 'Game.DebugController::ToggleDebugMenu', 'image': 'Assembly-CSharp.dll', 'rva': 0x1800}],
            'targetMethods': [{'label': 'Game.DebugController::EnableDebug', 'image': 'Assembly-CSharp.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'EnableDebug' in x['value'])
    assert c['semanticVerified'] is True
    assert c['semanticStatus'] == 'verified-static-xref'
    assert c['semanticConfidence'] >= 0.68
    assert any(e['kind'] == 'managed-incoming-direct-call' for e in c['semanticEvidence'])
    assert report['semanticVerification']['verified'] >= 1


def test_semantic_verifier_refuses_ambiguous_or_unrelated_callers():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__SetSpeed (float value, const MethodInfo* method);',
        'bindingSuggestion': 'number_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Single',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'Game.PlayerMotor::SetSpeed', 'image': 'Assembly-CSharp.dll', 'rva': 0x3000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
            'semantic': ['movement'], 'signature_contract': sig,
        }]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x1200, 'targetRva': 0x3000, 'sourceAttribution': 'ambiguous-shared-rva',
            'sourceMethodCandidates': [{'label': 'Telemetry.Upload::Flush', 'image': 'Telemetry.dll', 'rva': 0x1100}],
            'targetMethods': [{'label': 'Game.PlayerMotor::SetSpeed', 'image': 'Assembly-CSharp.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'SetSpeed' in x['value'])
    assert c['semanticVerified'] is False
    assert c['semanticBlocker'] in {'semantic-direct-call-verification-required', 'semantic-context-insufficient'}


def test_semantic_verifier_never_promotes_framework_only_method():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'UnityEngine.Debug::EnableDebug', 'image': 'UnityEngine.CoreModule.dll', 'rva': 0x4000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': False,
            'semantic': ['debug'], 'signature_contract': {
                'signature': 'void Metadata__EnableDebug (bool value, const MethodInfo* method);',
                'bindingSuggestion': 'bool_setter', 'isStatic': True, 'autoBindingSafe': True,
            },
        }]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x4010, 'targetRva': 0x4000, 'sourceAttribution': 'unique-metadata-method-interval',
            'sourceMethodCandidates': [{'label': 'UnityEngine.Debug::ToggleDebug', 'image': 'UnityEngine.CoreModule.dll', 'rva': 0x3f00}],
            'targetMethods': [{'label': 'UnityEngine.Debug::EnableDebug', 'image': 'UnityEngine.CoreModule.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'EnableDebug' in x['value'])
    assert c['semanticVerified'] is False


def test_dev15_method_local_outgoing_context_can_be_verified():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__SetSpeed (float value, const MethodInfo* method);',
        'bindingSuggestion': 'number_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Single',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'Game.PlayerMotor::SetSpeed', 'image': 'Assembly-CSharp.dll', 'rva': 0x3000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
            'semantic': ['movement'], 'signature_contract': sig,
        }]},
        'nativeRelations': {
            'il2cppDirectCallRefs': [],
            'il2cppMethodContext': [{
                'method': {'label': 'Game.PlayerMotor::SetSpeed', 'image': 'Assembly-CSharp.dll',
                           'rva': 0x3000, 'applicationOwned': True, 'semantic': ['movement']},
                'interval': {'startRva': 0x3000, 'nextMethodRva': 0x3080, 'size': 0x80},
                'outgoingManagedCalls': [{
                    'callRva': 0x3010, 'targetRva': 0x5000, 'kind': 'arm64-direct-bl',
                    'targetMethod': {'label': 'Game.PlayerMotor::ApplyMovement',
                                     'image': 'Assembly-CSharp.dll', 'rva': 0x5000,
                                     'applicationOwned': True, 'semantic': ['movement']},
                }],
                'stringRefs': [], 'thisOffsetCandidates': [],
            }],
        },
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'SetSpeed' in x['value'])
    assert c['semanticVerified'] is True
    assert c['contextVerified'] is True
    assert c['contextStatus'] == 'verified-method-context'
    assert any(e['kind'] == 'method-local-managed-callee' for e in c['contextEvidence'])
    assert report['methodContextVerification']['verified'] >= 1


def test_dev15_incoming_only_semantics_remains_context_review():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__EnableDebug (bool value, const MethodInfo* method);',
        'bindingSuggestion': 'bool_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Boolean',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'Game.DebugController::EnableDebug', 'image': 'Assembly-CSharp.dll', 'rva': 0x2000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
            'semantic': ['debug'], 'signature_contract': sig,
        }]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x1810, 'targetRva': 0x2000,
            'sourceAttribution': 'unique-metadata-method-interval',
            'sourceMethodCandidates': [{'label': 'Game.DebugController::ToggleDebugMenu',
                                        'image': 'Assembly-CSharp.dll', 'rva': 0x1800}],
            'targetMethods': [{'label': 'Game.DebugController::EnableDebug',
                               'image': 'Assembly-CSharp.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'EnableDebug' in x['value'])
    assert c['semanticVerified'] is True
    assert c['contextVerified'] is False
    assert c['contextBlocker'] == 'method-local-context-verification-required'


def test_dev15_render_quality_surface_is_never_semantically_promoted():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__SetFxSpeed (float value, const MethodInfo* method);',
        'bindingSuggestion': 'number_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Single',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'BattleFxHelper::SetFxSpeed', 'image': 'Assembly-CSharp.dll', 'rva': 0x6000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
            'semantic': ['movement'], 'signature_contract': sig,
        }]},
        'nativeRelations': {
            'il2cppDirectCallRefs': [{
                'callRva': 0x5810, 'targetRva': 0x6000,
                'sourceAttribution': 'unique-metadata-method-interval',
                'sourceMethodCandidates': [{'label': 'BattleFxHelperWrap::SetFxSpeed',
                                            'image': 'Assembly-CSharp.dll', 'rva': 0x5800}],
                'targetMethods': [{'label': 'BattleFxHelper::SetFxSpeed',
                                   'image': 'Assembly-CSharp.dll'}],
            }],
            'il2cppMethodContext': [{
                'method': {'label': 'BattleFxHelper::SetFxSpeed', 'image': 'Assembly-CSharp.dll',
                           'rva': 0x6000, 'applicationOwned': True, 'semantic': ['movement']},
                'interval': {'startRva': 0x6000, 'nextMethodRva': 0x6080, 'size': 0x80},
                'outgoingManagedCalls': [{
                    'callRva': 0x6010, 'targetRva': 0x7000,
                    'targetMethod': {'label': 'BattleFxHelper::ApplyFxSpeed',
                                     'image': 'Assembly-CSharp.dll', 'rva': 0x7000,
                                     'applicationOwned': True, 'semantic': ['movement']},
                }],
                'stringRefs': [], 'thisOffsetCandidates': [],
            }],
        },
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'SetFxSpeed' in x['value'])
    assert c['semanticVerified'] is False
    assert c['contextVerified'] is False
    assert c['semanticBlocker'] == 'technical-rendering-or-quality-surface'
    assert c['contextBlocker'] == 'technical-rendering-or-quality-surface'
    assert any(e['kind'] == 'technical-surface-penalty' for e in c['semanticEvidence'])


def test_re_analyze_split_base_uses_external_libil2cpp_and_compact_return(tmp_path):
    """Regression for dev17 split-base bug: RVA data must not be lost when the
    selected base.apk has no libil2cpp.so but the already selected external pair
    and Rodroid report are supplied to RE Workspace.
    """
    import json
    import struct
    import zipfile
    from modkit.mobile.engine import re_analyze_apk
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, call_rva,
                     0x94000000 | (((target_rva - call_rva) >> 2) & 0x03FFFFFF))
    external = tmp_path / 'library.so'
    external.write_bytes(blob)
    metadata = tmp_path / 'metadata.bin'
    metadata.write_bytes(b'not-a-full-metadata-fixture')
    il2cpp_report = tmp_path / 'analysis.json'
    il2cpp_report.write_text(json.dumps({
        'metadata_callable_methods': [{
            'label': 'Game.CheatHandler::EnableCheat()',
            'image': 'Assembly-CSharp.dll',
            'rva': target_rva,
            'resolution': 'confirmed-unique-code-registration',
            'semantic': ['cheat'],
            'provenance': 'game-primary',
            'application_owned': True,
            'signature_contract': {
                'bindingSuggestion': 'action', 'suggestedControlType': 'button',
                'autoBindingSafe': True, 'isStatic': True,
            },
        }],
    }), encoding='utf-8')

    # Deliberately no libil2cpp.so in base.apk: this is the split-base shape
    # which produced IL2CPP xrefs=0 in dev17 on AFK Journey.
    apk = tmp_path / 'base.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('AndroidManifest.xml', b'manifest')
        z.writestr('lib/arm64-v8a/libplaceholder.so', fixtures.so_blob())

    output = tmp_path / 're-analysis.json'
    compact = json.loads(re_analyze_apk(
        apk, output, metadata, external, None, None, il2cpp_report, None,
        'selected-external-pair+reused-rodroid', True,
    ))
    full = json.loads(output.read_text(encoding='utf-8'))
    refs = (full.get('nativeRelations') or {}).get('il2cppDirectCallRefs') or []
    assert refs and refs[0]['targetRva'] == target_rva
    assert compact['il2cppXrefs'] >= 1
    assert compact['inputSources']['externalSelectedPair'] is True
    assert compact['inputSources']['il2cppReportLoaded'] is True
    assert compact['pipelineDiagnostics']['managedXrefStatus'] == 'xref-evidence-present'
    ui_path = output.with_name(output.stem + '.ui.json')
    ui = json.loads(ui_path.read_text(encoding='utf-8'))
    assert ui['schema'] == 'modkit-re-ui-1.0'
    assert ui['reportState'] == 'complete'
    assert ui['reportSizeBytes'] == output.stat().st_size
    assert ui['summaryText'] and ui['pipelineDiagnostics']['managedXrefStatus'] == 'xref-evidence-present'


def test_dev20_current_unique_managed_interval_is_semantically_accepted():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__SetSpeed (float value, const MethodInfo* method);',
        'bindingSuggestion': 'number_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Single',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'Game.PlayerMotor::SetSpeed', 'image': 'Assembly-CSharp.dll', 'rva': 0x2200,
            'resolution': 'confirmed-unique-code-registration', 'semantic': ['movement'],
            'signature_contract': sig,
        }]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x2110, 'targetRva': 0x2200,
            'sourceAttribution': 'unique-managed-interval',
            'sourceMethodCandidates': [{'label': 'Game.PlayerMotor::ApplyMovement',
                                        'image': 'Assembly-CSharp.dll', 'rva': 0x2100}],
            'targetMethods': [{'label': 'Game.PlayerMotor::SetSpeed',
                               'image': 'Assembly-CSharp.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'SetSpeed' in x['value'])
    assert c['semanticVerified'] is True
    assert c['gameplayRelevance'] >= 45


def test_dev20_lifetime_and_fx_surfaces_are_low_relevance_review_only():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates
    sig = {
        'signature': 'void Metadata__SetFxSpeedLifeTime (float value, const MethodInfo* method);',
        'bindingSuggestion': 'number_setter', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'autoBindingSafe': True, 'managedValueType': 'System.Single',
    }
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'BattleFxHelper::SetFxSpeedLifeTime', 'image': 'Assembly-CSharp.dll', 'rva': 0x6200,
            'resolution': 'confirmed-unique-code-registration', 'semantic': ['state'],
            'signature_contract': sig,
        }]},
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'callRva': 0x6110, 'targetRva': 0x6200,
            'sourceAttribution': 'unique-managed-interval',
            'sourceMethodCandidates': [{'label': 'BattleFxHelper::ApplyFxSpeedLifeTime',
                                        'image': 'Assembly-CSharp.dll', 'rva': 0x6100}],
            'targetMethods': [{'label': 'BattleFxHelper::SetFxSpeedLifeTime', 'image': 'Assembly-CSharp.dll'}],
        }]},
    }
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if 'SetFxSpeedLifeTime' in x['value'])
    assert c['semanticVerified'] is False
    assert c['semanticBlocker'] == 'technical-rendering-or-quality-surface'
    assert c['gameplayRelevance'] < 45


def test_dev20_relationship_graph_emits_native_only_managed_chain_without_dex_root():
    from modkit.reworkspace import build_static_relationship_graph
    report = {
        'nativeRelations': {'il2cppDirectCallRefs': [{
            'artifact': 'extra/libil2cpp.so', 'callRva': 0x1010, 'targetRva': 0x2000,
            'confidence': 0.96, 'sourceAttribution': 'unique-managed-interval',
            'sourceMethodCandidates': [{'label': 'Game.PlayerMotor::ApplyMovement',
                                        'image': 'Assembly-CSharp.dll', 'rva': 0x1000}],
            'targetMethods': [{'label': 'Game.PlayerMotor::SetSpeed',
                               'image': 'Assembly-CSharp.dll'}],
        }]},
        'controlCandidates': [{
            'id': 'candidate.setspeed', 'title': 'SetSpeed', 'source': 'Assembly-CSharp.dll',
            'value': 'Game.PlayerMotor::SetSpeed', 'evidenceRva': 0x2000,
            'status': 'correlated', 'confidence': 0.95, 'suggestedType': 'slider_or_toggle',
        }],
    }
    graph = build_static_relationship_graph(report)
    assert graph['summary']['dexRoots'] == 0
    assert graph['summary']['completeChains'] == 0
    assert graph['summary']['nativeOnlyChains'] == 1
    assert graph['summary']['controlsReachedFromNative'] == 1
    assert graph['nativeOnlyChains'][0]['scope'] == 'native-only'
    labels = {n['id']: n['label'] for n in graph['nodes']}
    chain_labels = [labels[x] for x in graph['nativeOnlyChains'][0]['nodes']]
    assert chain_labels == ['Game.PlayerMotor::ApplyMovement', 'Game.PlayerMotor::SetSpeed', 'SetSpeed']


def test_dev21_generic_metadata_callable_becomes_candidate_without_gameplay_keywords():
    from modkit.reworkspace.correlate import derive_control_candidates
    contract = {
        'signature': 'void Metadata__SetOpacity (float value, const MethodInfo* method);',
        'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'bindingSuggestion': 'number_setter', 'bindingBlocker': None,
    }
    verification = {
        'schema': 'modkit-method-verification-1.0', 'addressConfirmed': True,
        'abiConfirmed': True, 'executableReady': True, 'structuralConfidence': 0.91,
        'relationStatus': 'confirmed-static-xref', 'contextStatus': 'corroborated-static-context',
        'runtimeConfirmed': False,
    }
    report = {'findings': [], 'il2cpp': {'metadata_callable_methods': [{
        'label': 'Example.Settings::SetOpacity', 'image': 'Example.Core.dll', 'rva': 0x2400,
        'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
        'signature_contract': contract, 'method_verification': verification,
    }]}}
    rows = derive_control_candidates(report)
    hit = next(x for x in rows if x['value'] == 'Example.Settings::SetOpacity')
    assert hit['status'] == 'structural-confirmed'
    assert hit['evidenceRva'] == 0x2400
    assert hit['bindingSuggestion'] == 'number_setter'
    assert hit['methodVerification']['addressConfirmed'] is True
    assert hit['methodVerification']['runtimeConfirmed'] is False


def test_dev21_universal_method_verification_attaches_xref_and_context():
    from modkit.reworkspace.correlate import augment_method_verification
    contract = {
        'signature': 'void Metadata__SetOpacity (float value, const MethodInfo* method);',
        'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
        'bindingSuggestion': 'number_setter', 'bindingBlocker': None,
        'metadataToken': 1, 'metadataMethodId': 2,
    }
    row = {
        'label': 'Example.Settings::SetOpacity', 'image': 'Example.Core.dll',
        'rva': 0x2400, 'offset': 0x400,
        'resolution': 'confirmed-unique-code-registration',
        'metadata_token': 1, 'metadata_method_id': 2,
        'signature_contract': contract,
    }
    report = {
        'il2cpp': {'metadata_callable_methods': [row]},
        'nativeRelations': {
            'il2cppDirectCallRefs': [{
                'callRva': 0x2200, 'targetRva': 0x2400,
                'sourceAttribution': 'unique-managed-interval',
                'sourceMethodCandidates': [{'label': 'Example.Settings::Refresh', 'rva': 0x2200}],
                'targetMethods': [{'label': 'Example.Settings::SetOpacity', 'rva': 0x2400}],
            }],
            'il2cppMethodContext': [{
                'method': {'label': 'Example.Settings::SetOpacity', 'rva': 0x2400},
                'outgoingManagedCalls': [{'targetRva': 0x2500}], 'stringRefs': [], 'thisOffsetCandidates': [],
            }],
        },
    }
    augment_method_verification(report)
    v = row['method_verification']
    assert v['addressConfirmed'] is True
    assert v['relationStatus'] == 'confirmed-static-xref'
    assert v['contextStatus'] == 'corroborated-static-context'
    assert v['runtimeConfirmed'] is False
    assert report['methodVerification']['xrefCorroborated'] == 1


def test_dev21_function_correlation_accepts_generic_callable_target_without_control_vocab(tmp_path):
    import struct, zipfile
    from modkit.reworkspace import augment_function_correlations
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, call_rva, 0x94000000 | (((target_rva - call_rva) >> 2) & 0x03FFFFFF))
    apk = tmp_path / 'app.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', bytes(blob))
    report = {'findings': [], 'nativeRelations': {}, 'il2cpp': {'metadata_callable_methods': [{
        'label': 'Example.Settings::SetOpacity', 'image': 'Example.Core.dll', 'rva': target_rva,
        'provenance': 'custom-unknown',
        'signature_contract': {
            'signature': 'void Metadata__SetOpacity (float value, const MethodInfo* method);',
            'isStatic': True, 'shapeSupported': True, 'bindingSuggestion': 'number_setter',
        },
    }]}}
    augment_function_correlations(report, apk_path=apk)
    refs = report['nativeRelations']['il2cppDirectCallRefs']
    assert refs and refs[0]['targetRva'] == target_rva
    assert refs[0]['targetMethods'][0]['label'] == 'Example.Settings::SetOpacity'


def test_dev21_function_correlation_follows_obfuscated_method_from_prior_all_rva_bl_evidence(tmp_path):
    import struct, zipfile
    from modkit.reworkspace import augment_function_correlations
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, call_rva, 0x94000000 | (((target_rva - call_rva) >> 2) & 0x03FFFFFF))
    apk = tmp_path / 'app.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', bytes(blob))
    report = {'findings': [], 'nativeRelations': {}, 'il2cpp': {'metadata_callable_methods': [{
        'label': 'Example.X::a', 'image': 'Assembly-CSharp.dll', 'rva': target_rva,
        'provenance': 'game-primary', 'static_incoming_direct_bl_count': 1,
        'signature_contract': {
            'signature': 'void Metadata__a (const MethodInfo* method);',
            'isStatic': True, 'shapeSupported': True, 'bindingSuggestion': 'action',
        },
    }]}}
    augment_function_correlations(report, apk_path=apk)
    refs = report['nativeRelations']['il2cppDirectCallRefs']
    assert refs and refs[0]['targetRva'] == target_rva
    assert refs[0]['targetMethods'][0]['label'] == 'Example.X::a'


def _dev21_obfuscated_action_semantic_report(with_string=False):
    report = {
        'findings': [],
        'il2cpp': {'metadata_callable_methods': [{
            'label': 'Game.PlayerMotor::a', 'image': 'Assembly-CSharp.dll', 'rva': 0x3000,
            'resolution': 'confirmed-unique-code-registration', 'application_owned': True,
            'semantic': [], 'static_incoming_direct_bl_count': 1,
            'signature_contract': {
                'signature': 'void Metadata__a (const MethodInfo* method);',
                'bindingSuggestion': 'action', 'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True, 'autoBindingSafe': True,
                'shapeSupported': True, 'staticnessVerified': True,
                'metadataToken': 1, 'metadataMethodId': 2,
            },
        }]},
        'nativeRelations': {
            'il2cppDirectCallRefs': [{
                'callRva': 0x2810, 'targetRva': 0x3000,
                'sourceAttribution': 'unique-metadata-method-interval',
                'sourceMethodCandidates': [{
                    'label': 'Game.PlayerMotor::ApplyMovement', 'image': 'Assembly-CSharp.dll', 'rva': 0x2800,
                }],
                'targetMethods': [{'label': 'Game.PlayerMotor::a', 'image': 'Assembly-CSharp.dll', 'rva': 0x3000}],
            }],
            'il2cppMethodContext': [{
                'method': {'label': 'Game.PlayerMotor::a', 'image': 'Assembly-CSharp.dll', 'rva': 0x3000},
                'outgoingManagedCalls': [],
                'stringRefs': ([{'value': 'movement speed', 'xrefRva': 0x3010, 'targetRva': 0x9000}]
                               if with_string else []),
                'thisOffsetCandidates': [],
            }],
        },
    }
    return report


def test_dev21_obfuscated_same_owner_xref_is_not_semantic_confirmation_by_itself():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates, augment_method_verification
    report = _dev21_obfuscated_action_semantic_report(with_string=False)
    augment_method_verification(report)
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if x['value'] == 'Game.PlayerMotor::a')
    assert c['semanticVerified'] is False
    assert c['semanticCorroboratedTags'] == []
    assert c['semanticBlocker'] == 'semantic-signal-corroboration-required'


def test_dev21_obfuscated_semantics_require_two_independent_static_sources():
    from modkit.reworkspace import augment_control_semantics, derive_control_candidates, augment_method_verification
    report = _dev21_obfuscated_action_semantic_report(with_string=True)
    augment_method_verification(report)
    report['controlCandidates'] = derive_control_candidates(report)
    augment_control_semantics(report)
    c = next(x for x in report['controlCandidates'] if x['value'] == 'Game.PlayerMotor::a')
    assert c['semanticVerified'] is True
    assert 'movement' in c['semanticCorroboratedTags']
    assert len(c['semanticSignalSources']['movement']) >= 2
    assert any(e['kind'] == 'semantic-signal-corroboration' for e in c['semanticEvidence'])


def test_dev21_direct_bl_xref_falls_back_to_exec_pt_load_without_section_table():
    import struct
    from modkit.elf.reader import ElfFile
    from modkit.reworkspace.native import direct_bl_calls
    from modkit.selftest import fixtures

    blob = bytearray(fixtures.so_blob())
    call_rva = fixtures.TEXT_VADDR
    target_rva = fixtures.TEXT_VADDR + 8
    struct.pack_into('<I', blob, call_rva,
                     0x94000000 | (((target_rva - call_rva) >> 2) & 0x03FFFFFF))
    # Remove section-table visibility while preserving loader program headers.
    struct.pack_into('<Q', blob, 40, 0)   # e_shoff
    struct.pack_into('<H', blob, 60, 0)   # e_shnum
    struct.pack_into('<H', blob, 62, 0)   # e_shstrndx
    refs = direct_bl_calls(ElfFile(bytes(blob)), {target_rva})
    assert refs and refs[0]['callRva'] == call_rva
    assert refs[0]['targetRva'] == target_rva
    assert refs[0]['kind'] == 'arm64-direct-bl'
