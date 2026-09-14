from modkit.reworkspace.method_evidence import (
    apply_semantic_result,
    build_method_verification,
    enrich_method_verification,
    method_role,
    retention_priority,
    should_retain_metadata_row,
    structurally_actionable,
)


def _static_contract():
    return {
        "signature": "void Metadata__SetOpacity (float value, const MethodInfo* method);",
        "isStatic": True,
        "staticnessVerified": True,
        "shapeSupported": True,
        "bindingSuggestion": "number_setter",
        "bindingBlocker": None,
        "metadataToken": 0x06000042,
        "metadataMethodId": 65,
        "dumpArityVerified": True,
        "dumpStaticnessVerified": True,
    }


def test_generic_method_role_has_no_fixture_or_game_dependency():
    assert method_role("Example.Settings::SetOpacity", _static_contract()) == "setter"
    assert method_role("Example.Settings::ToggleOverlay") == "toggle_action"
    assert method_role("Example.Registry::TryGetService") == "instance_resolver"
    assert method_role("Example.Worker::<RunAsync>d__4::MoveNext") == "lifecycle"


def test_retention_is_generic_api_morphology_not_game_keyword_match():
    row = {"name": "SetOpacity", "args": 1, "generic": False, "abstract": False}
    assert should_retain_metadata_row(row)
    assert retention_priority(row) >= 20
    unknown = {"name": "xqv", "args": 7, "generic": True, "abstract": False}
    assert not should_retain_metadata_row(unknown)


def test_unique_executable_typed_static_method_is_structurally_ready():
    row = {
        "label": "Example.Settings::SetOpacity", "rva": 0x401000, "offset": 0x1000,
        "resolution": "confirmed-unique-code-registration",
        "metadata_token": 0x06000042, "metadata_method_id": 65,
        "signature_contract": _static_contract(),
    }
    v = build_method_verification(row)
    assert v["addressConfirmed"] is True
    assert v["abiConfirmed"] is True
    assert v["executableReady"] is True
    assert v["runtimeConfirmed"] is False
    assert v["runtimeStatus"] == "not-observed"
    assert v["confirmationLevel"] == "executable-ready-static"


def test_instance_method_requires_type_verified_resolver():
    contract = _static_contract() | {
        "signature": "void Metadata__SetOpacity (void* __this, float value, const MethodInfo* method);",
        "isStatic": False,
        "bindingBlocker": "instance-method-needs-confirmed-instance-resolver",
    }
    row = {
        "label": "Example.Settings::SetOpacity", "rva": 0x401000, "offset": 0x1000,
        "resolution": "confirmed-unique-code-registration", "metadata_token": 1,
        "signature_contract": contract,
    }
    assert build_method_verification(row)["executableReady"] is False
    resolver = {"verified": True, "rva": 0x402000, "match": "metadata-target-type-exact",
                "targetClass": "Example.Settings"}
    v = build_method_verification(row, resolver)
    assert v["resolverVerified"] is True
    assert v["executableReady"] is True


def test_static_xref_and_context_raise_structural_evidence_not_runtime_truth():
    row = {
        "label": "Example.Settings::SetOpacity", "rva": 0x401000, "offset": 0x1000,
        "resolution": "confirmed-unique-code-registration", "metadata_token": 1,
        "signature_contract": _static_contract(),
    }
    v = build_method_verification(row)
    ref = {"sourceAttribution": "unique-managed-interval", "callRva": 0x400100, "targetRva": 0x401000}
    v = enrich_method_verification(v, incoming_refs=[ref], method_context={"outgoingManagedCalls": [{}], "stringRefs": [], "thisOffsetCandidates": []})
    assert v["relationStatus"] == "confirmed-static-xref"
    assert v["contextStatus"] == "corroborated-static-context"
    assert v["runtimeConfirmed"] is False


def test_semantics_never_turn_static_evidence_into_runtime_confirmation():
    row = {
        "label": "Example.Settings::SetOpacity", "rva": 0x401000, "offset": 0x1000,
        "resolution": "confirmed-unique-code-registration", "metadata_token": 1,
        "signature_contract": _static_contract(),
    }
    v = apply_semantic_result(build_method_verification(row), status="verified-static-xref",
                              confidence=0.91, verified=True, tags=["presentation"])
    assert v["semanticVerified"] is True
    assert v["runtimeConfirmed"] is False
    assert structurally_actionable(row["label"], row["signature_contract"])


def test_dev21_direct_bl_observation_is_relation_evidence_not_full_caller_confirmation():
    from modkit.reworkspace.method_evidence import build_method_verification
    row = {
        'label': 'Example.X::a', 'rva': 0x2400, 'offset': 0x400,
        'resolution': 'confirmed-unique-code-registration',
        'metadata_token': 1, 'metadata_method_id': 2,
        'static_incoming_direct_bl_count': 3, 'static_first_call_rva': 0x2200,
        'signature_contract': {
            'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
            'bindingSuggestion': 'action', 'metadataToken': 1, 'metadataMethodId': 2,
        },
    }
    v = build_method_verification(row)
    assert v['relationStatus'] == 'observed-static-xref'
    assert v['runtimeConfirmed'] is False
    ev = next(e for e in v['evidence'] if e['kind'] == 'native-direct-bl-target')
    assert ev['count'] == 3 and ev['firstCallRva'] == 0x2200


def test_obfuscated_static_method_can_have_confirmed_abi_without_auto_binding():
    row = {
        "label": "Example.X::a", "rva": 0x501000, "offset": 0x1000,
        "resolution": "confirmed-unique-code-registration",
        "metadata_token": 0x06000077, "metadata_method_id": 118,
        "signature_contract": {
            "signature": "int32_t Metadata__a (const MethodInfo* method);",
            "isStatic": True, "staticnessVerified": True, "shapeSupported": True,
            "bindingSuggestion": None, "bindingBlocker": None,
            "metadataToken": 0x06000077, "metadataMethodId": 118,
        },
    }
    v = build_method_verification(row)
    assert v["addressConfirmed"] is True
    assert v["abiConfirmed"] is True
    assert v["callableReady"] is True
    assert v["bindingReady"] is False
    assert v["executableReady"] is False
    assert v["confirmationLevel"] == "callable-abi-confirmed"
    assert v["bindingBlocker"] == "method-intent-unproven-for-auto-binding"
    assert v["runtimeStatus"] == "not-observed"
