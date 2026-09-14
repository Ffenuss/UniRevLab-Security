from modkit.menu import MenuControl, MenuSpec, spec_from_analysis, write_project


def test_menu_spec_and_project(tmp_path):
    spec = MenuSpec("Test", controls=[MenuControl("god", "God", "toggle", rva=0x1234)])
    result = write_project(spec, tmp_path / "menu")
    assert result["rvaBindings"] == 1
    assert result["executableBindings"] == 0
    assert result["reviewBindings"] == 1
    assert (tmp_path / "menu/assets/modkit-menu.json").is_file()
    header = (tmp_path / "menu/native/bindings.generated.h").read_text()
    assert "0x1234ULL" in header and '"review"' in header


def test_explicit_binding_generates_full_runtime_project(tmp_path):
    spec = MenuSpec("Test", controls=[MenuControl(
        "god", "God", "toggle", rva=0x1234, binding="bool_setter",
        target_so="libil2cpp.so",
    )])
    result = write_project(spec, tmp_path / "menu")
    runtime = tmp_path / "menu/runtime"
    assert result["executableBindings"] == 1
    assert (runtime / "app/src/main/cpp/game.cpp").is_file()
    assert (runtime / "app/src/main/res/mipmap-anydpi/ic_launcher.xml").is_file()
    manifest = (runtime / "app/src/main/AndroidManifest.xml").read_text()
    assert '@mipmap/ic_launcher' in manifest
    assert "0x1234" in (runtime / "app/src/main/cpp/features.inc").read_text()


def test_seed_from_analysis_requires_correlated_and_keeps_call_unbound():
    analysis = {"findings": [
        {"id":"a", "title":"A", "status":"candidate", "evidence":[{"location":"RVA 0x10"}]},
        {"id":"b", "title":"B", "status":"confirmed", "evidence":[{"location":"RVA 0x20"}]},
    ]}
    spec = spec_from_analysis(analysis)
    assert len(spec.controls) == 1
    assert spec.controls[0].rva == 0x20
    assert spec.controls[0].type == "label"
    assert spec.controls[0].binding is None


def test_validate_bindings_against_real_apk_native(tmp_path):
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "god", "God", "toggle", rva=0x1040, binding="bool_setter",
        target_so="libil2cpp.so",
    )])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is False
    assert report["validatedBindings"] == 1
    assert report["checks"][0]["fileOffset"] is not None
    assert report["checks"][0]["preview"]


def test_validate_bindings_blocks_bad_rva(tmp_path):
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "bad", "Bad", "button", rva=0x7fffffff, binding="action",
        target_so="libil2cpp.so",
    )])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is True
    assert any(i["code"] == "RVA_NOT_FILE_BACKED" for i in report["issues"])


def test_seed_preserves_control_candidate_provenance_without_binding():
    analysis = {"controlCandidates": [{
        "id":"candidate.cheatinvic", "title":"Cheat Invic", "suggestedType":"toggle",
        "source":"lib/arm64-v8a/libBedo.so", "kind":"native-symbol", "location":"RVA 0x2040",
        "evidenceRva":0x2040, "confidence":0.92, "rationale":"static evidence"
    }], "findings": []}
    spec = spec_from_analysis(analysis)
    assert len(spec.controls) == 1
    c = spec.controls[0]
    assert c.title == "Cheat Invic"
    assert c.type == "toggle"
    assert c.binding is None
    assert c.rva is None
    assert c.evidence_rva == 0x2040
    assert c.evidence_source.endswith("libBedo.so")
    assert c.evidence_kind == "native-symbol"
    assert c.evidence_confidence == 0.92
    assert c.suggested_target_so == "libBedo.so"
    assert "Suggested control: toggle" in c.note


def test_menu_runtime_enables_dt_needed_autoload_mode(tmp_path):
    spec = MenuSpec("Test", controls=[MenuControl(
        "god", "God", "toggle", rva=0x1234, binding="bool_setter",
        target_so="libil2cpp.so",
    )])
    write_project(spec, tmp_path / "menu")
    runtime = tmp_path / "menu/runtime"
    cmake = (runtime / "app/src/main/cpp/CMakeLists.txt").read_text()
    gradle = (runtime / "app/build.gradle").read_text()
    jni = (runtime / "app/src/main/cpp/jni_main.cpp").read_text()
    assert "MODKIT_AUTOLOAD" in cmake and "MODKIT_AUTOLOAD=ON" in gradle
    assert "modkit_autoload_constructor" in jni


def test_menu_builder_writes_dex_free_native_patch_payload(tmp_path):
    import zipfile
    from modkit.menu import write_patch_payload
    from modkit.patchpack import apply_pack
    from modkit.elf.reader import ElfFile
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n035\0Lcom/example/Game;")
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    runtime = tmp_path / "libmodkitmenu.so"
    runtime.write_bytes(fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "god", "God", "toggle", rva=0x1040, binding="bool_setter",
        target_so="libil2cpp.so",
    )])
    pack = tmp_path / "menu-payload.zip"
    result = write_patch_payload(spec, apk, runtime, pack)
    assert result["bindings"] == 1
    with zipfile.ZipFile(pack) as z:
        assert "modkit-payload.json" in z.namelist()
        assert "lib/arm64-v8a/libmodkitmenu.so" in z.namelist()
        assert not any(n.endswith(".dex") for n in z.namelist())

    out = tmp_path / "out.apk"
    apply_pack(apk, pack, out)
    with zipfile.ZipFile(out) as z:
        assert z.read("classes.dex") == b"dex\n035\0Lcom/example/Game;"
        assert "libmodkitmenu.so" in ElfFile(z.read("lib/arm64-v8a/libil2cpp.so")).needed()


def test_generic_runtime_payload_embeds_menu_config(tmp_path):
    import zipfile
    from modkit.menu import write_patch_payload
    from modkit.menu.runtime_config import decode_runtime_config
    from modkit.elf.reader import ElfFile
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n035\0Lcom/example/Game;")
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    runtime = tmp_path / "libmodkit_runtime.so"
    runtime.write_bytes(fixtures.runtime_so_blob())
    spec = MenuSpec("Меню", controls=[MenuControl(
        "god", "Бессмертие", "toggle", rva=0x1040, binding="bool_setter",
        target_so="libil2cpp.so",
    )])
    pack = tmp_path / "payload.zip"
    result = write_patch_payload(spec, apk, runtime, pack)
    assert result["runtimeConfigMode"] == "embedded-generic-runtime"
    with zipfile.ZipFile(pack) as z:
        blob = z.read("lib/arm64-v8a/libmodkit_runtime.so")
        sec = ElfFile(blob).section(".modkitcfg")
        cfg = decode_runtime_config(blob[sec.offset: sec.offset + sec.size])
        assert cfg["targetSo"] == "libil2cpp.so"
        assert cfg["controls"][0]["id"] == "god"


def test_detect_render_host_prefers_libunity(tmp_path):
    import zipfile
    from modkit.menu import detect_render_host
    from modkit.selftest import fixtures
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libfoo.so", fixtures.so_blob())
        z.writestr("lib/arm64-v8a/libunity.so", fixtures.so_blob())
    result = detect_render_host(apk)
    assert result["selected"] == "libunity.so"
    assert result["candidates"][0]["score"] >= 10


def test_menu_review_preflight_separates_evidence_from_bound_rva(tmp_path):
    import zipfile
    from modkit.menu import review_preflight
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[
        MenuControl("review", "Review", "toggle", evidence_rva=0x1040, suggested_type="toggle"),
        MenuControl("bound", "Bound", "toggle", rva=0x1040, binding="bool_setter"),
        MenuControl("unknown", "Unknown", "label"),
    ])
    report = review_preflight(spec, apk)
    assert report["readyForPayload"] is True
    assert {k: report["counts"][k] for k in ("total", "bound", "evidenceOnly", "unresolved")} == {"total": 3, "bound": 1, "evidenceOnly": 1, "unresolved": 1}
    assert report["counts"]["actionableReview"] == 0
    assert report["readyForAutoBuild"] is True
    by_id = {x["id"]: x for x in report["controls"]}
    assert by_id["review"]["state"] == "evidence-only"
    assert by_id["review"]["suggestedRva"] == 0x1040
    assert by_id["bound"]["state"] == "bound"


def test_menu_review_preflight_not_ready_without_explicit_binding(tmp_path):
    import zipfile
    from modkit.menu import review_preflight
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "review", "Review", "toggle", evidence_rva=0x1040, suggested_type="toggle"
    )])
    report = review_preflight(spec, apk)
    assert report["blocked"] is False
    assert report["readyForPayload"] is False
    assert any(x["code"] == "NO_EXECUTABLE_BINDINGS" for x in report["issues"])


def test_menu_seed_carries_instance_binding_blocker_to_review_spec():
    analysis = {'controlCandidates': [{
        'id': 'candidate.enablecheat', 'title': 'Enable Cheat', 'suggestedType': 'button',
        'source': 'Game.dll', 'kind': 'rodroid-discovery', 'location': 'RVA 0x2000',
        'evidenceRva': 0x2000, 'confidence': 0.97,
        'bindingSuggestion': 'bool_setter', 'isStatic': False,
        'bindingBlocker': 'instance-method-needs-confirmed-instance-resolver',
        'signatureContract': {'signature': 'void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);'},
    }], 'findings': []}
    c = spec_from_analysis(analysis).controls[0]
    assert c.binding is None and c.rva is None
    assert c.evidence_rva == 0x2000
    assert c.suggested_binding == 'bool_setter'
    assert c.evidence_is_static is False
    assert c.is_static is False
    assert c.binding_blocker == 'instance-method-needs-confirmed-instance-resolver'
    assert '__this' in c.evidence_signature


def test_validate_instance_binding_checks_resolver_rva(tmp_path):
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Cheat", "toggle", rva=0x1040, binding="bool_setter",
        target_so="libil2cpp.so", is_static=False, call_abi="il2cpp",
        resolver_rva=0x1044, resolver_kind="out_ptr_bool", resolver_verified=True,
    )])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is False
    row = report["checks"][0]
    assert row["resolverRva"] == 0x1044
    assert row["resolverFileOffset"] is not None
    assert row["resolverPreview"]


def test_validate_instance_binding_blocks_bad_resolver_rva(tmp_path):
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Cheat", "button", rva=0x1040, binding="action",
        target_so="libil2cpp.so", is_static=False, call_abi="il2cpp",
        resolver_rva=0x7FFFFFFF, resolver_kind="out_ptr_bool", resolver_verified=True,
    )])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is True
    assert any(i["code"] == "RESOLVER_RVA_NOT_FILE_BACKED" for i in report["issues"])


def test_write_project_uses_generic_runtime_for_il2cpp_instance(tmp_path):
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Cheat", "button", rva=0x2000, binding="action",
        target_so="libil2cpp.so", is_static=False, call_abi="il2cpp",
        resolver_rva=0x3000, resolver_kind="out_ptr_bool", resolver_verified=True,
    )])
    result = write_project(spec, tmp_path / "menu")
    assert result["runtimeMode"] == "built-in-generic-config"
    assert (tmp_path / "menu/runtime/MENU-SPEC.json").is_file()
    assert not (tmp_path / "menu/runtime/app/src/main/cpp/game.cpp").exists()


def test_instance_il2cpp_resolver_survives_generic_patch_payload(tmp_path):
    import zipfile
    from modkit.menu import write_patch_payload
    from modkit.menu.runtime_config import decode_runtime_config
    from modkit.elf.reader import ElfFile
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    runtime = tmp_path / "libmk.so"
    runtime.write_bytes(fixtures.runtime_so_blob())
    spec = MenuSpec("X", controls=[MenuControl(
        "cheat", "Cheat", "toggle", rva=0x1040, binding="bool_setter",
        target_so="libil2cpp.so", is_static=False, call_abi="il2cpp",
        resolver_rva=0x1044, resolver_kind="out_ptr_bool", resolver_verified=True,
    )])
    pack = tmp_path / "payload.zip"
    write_patch_payload(spec, apk, runtime, pack)
    with zipfile.ZipFile(pack) as z:
        blob = z.read("lib/arm64-v8a/libmk.so")
        sec = ElfFile(blob).section(".modkitcfg")
        row = decode_runtime_config(blob[sec.offset:sec.offset + sec.size])["controls"][0]
    assert row["rva"] == 0x1040
    assert row["resolverRva"] == 0x1044
    assert row["callAbi"] == "il2cpp"
    assert row["isStatic"] is False


def test_auto_confirm_promotes_only_structurally_proven_instance_candidate(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Enable Cheat", "toggle",
        evidence_rva=0x1040, evidence_confidence=0.97,
        suggested_binding="bool_setter", evidence_is_static=False,
        evidence_signature="void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);",
        call_abi="il2cpp", is_static=False,
        resolver_rva=0x1044, resolver_kind="out_ptr_bool", resolver_verified=True,
        resolver_match="metadata-target-type-exact", resolver_target_class="X.CheatHandler",
        resolver_contract_source="global-metadata+CodeRegistration",
        resolver_signature="bool X__TryGet (X_o** handler, const MethodInfo* method);",
    )])
    report = auto_confirm_bindings(spec, apk)
    assert report["promoted"] == ["cheat"]
    assert report["rejected"] == []
    c = spec.controls[0]
    assert c.binding == "bool_setter" and c.rva == 0x1040
    assert c.is_static is False and c.resolver_rva == 0x1044


def test_auto_confirm_refuses_instance_resolver_without_type_identity(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Enable Cheat", "toggle",
        evidence_rva=0x1040, evidence_confidence=0.97,
        suggested_binding="bool_setter", evidence_is_static=False,
        evidence_signature="void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);",
        call_abi="il2cpp", is_static=False,
        resolver_rva=0x1044, resolver_kind="out_ptr_bool",
        resolver_verified=False,
        resolver_signature="bool X__TryGet (X_o** handler, const MethodInfo* method);",
    )])
    report = auto_confirm_bindings(spec, apk)
    assert report["promoted"] == []
    assert any(x["id"] == "cheat" and x["reason"] == "instance-resolver-type-not-verified"
               for x in report["skipped"])
    assert spec.controls[0].binding is None


def test_auto_confirm_rolls_back_candidate_when_elf_preflight_blocks(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "bad", "Bad", "button",
        evidence_rva=0x7FFFFFFF, evidence_confidence=0.99,
        suggested_binding="action", evidence_is_static=True,
        evidence_signature="void X__ToggleBad (const MethodInfo* method);",
        call_abi="il2cpp", is_static=True,
    )])
    report = auto_confirm_bindings(spec, apk)
    assert report["promoted"] == []
    assert report["rejected"] == [{"id": "bad", "reason": "elf-preflight-block"}]
    assert spec.controls[0].binding is None and spec.controls[0].rva is None


def test_auto_confirm_keeps_low_confidence_candidate_review_only(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[MenuControl(
        "weak", "Weak", "button",
        evidence_rva=0x1040, evidence_confidence=0.60,
        suggested_binding="action", evidence_is_static=True,
        evidence_signature="void X__ToggleWeak (const MethodInfo* method);",
        call_abi="il2cpp", is_static=True,
    )])
    report = auto_confirm_bindings(spec, apk)
    assert report["promoted"] == []
    assert any(x["id"] == "weak" and x["reason"] == "confidence-below-threshold" for x in report["skipped"])
    assert spec.controls[0].binding is None


def test_seed_preserves_numeric_signature_type_but_requires_range_review():
    analysis = {'controlCandidates': [{
        'id': 'candidate.speed', 'title': 'Set Speed', 'suggestedType': 'slider_float',
        'source': 'Game.dll', 'kind': 'rodroid-discovery', 'location': 'RVA 0x1040',
        'evidenceRva': 0x1040, 'confidence': 0.97,
        'bindingSuggestion': 'number_setter', 'isStatic': True,
        'signatureContract': {
            'signature': 'void X__SetSpeed (float value, const MethodInfo* method);',
            'bindingSuggestion': 'number_setter', 'isStatic': True,
            'suggestedControlType': 'slider_float', 'managedValueType': 'System.Single',
        },
    }], 'findings': []}
    c = spec_from_analysis(analysis).controls[0]
    assert c.type == 'label'
    assert c.suggested_type == 'slider_float'
    assert c.value_type == 'System.Single'
    assert c.binding is None


def test_auto_confirm_numeric_setter_only_after_slider_range_review(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())

    review = MenuSpec('Test', controls=[MenuControl(
        'speed', 'Set Speed', 'label', evidence_rva=0x1040, evidence_confidence=0.97,
        suggested_type='slider_float', suggested_binding='number_setter', evidence_is_static=True,
        evidence_signature='void X__SetSpeed (float value, const MethodInfo* method);',
        value_type='System.Single', call_abi='il2cpp', is_static=True,
    )])
    first = auto_confirm_bindings(review, apk)
    assert first['promoted'] == []
    assert any(x['id'] == 'speed' and x['reason'] == 'numeric-range-review-required' for x in first['skipped'])

    reviewed = MenuSpec('Test', controls=[MenuControl(
        'speed', 'Set Speed', 'slider_float', min_value=0.5, max_value=3.0, default=1.0,
        evidence_rva=0x1040, evidence_confidence=0.97,
        suggested_type='slider_float', suggested_binding='number_setter', evidence_is_static=True,
        evidence_signature='void X__SetSpeed (float value, const MethodInfo* method);',
        value_type='System.Single', call_abi='il2cpp', is_static=True,
    )])
    second = auto_confirm_bindings(reviewed, apk)
    assert second['promoted'] == ['speed']
    c = reviewed.controls[0]
    assert c.binding == 'number_setter'
    assert c.type == 'slider_float'
    assert c.min_value == 0.5 and c.max_value == 3.0


def test_auto_confirm_rederives_signature_contract_instead_of_trusting_json(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    spec = MenuSpec('Test', controls=[MenuControl(
        'fake', 'Fake setter', 'toggle', evidence_rva=0x1040, evidence_confidence=0.99,
        suggested_binding='bool_setter', evidence_is_static=True,
        # One numeric constructor-like parameter: serialized suggestion is intentionally forged.
        evidence_signature='void X___ctor (int32_t value, const MethodInfo* method);',
        call_abi='il2cpp', is_static=True,
    )])
    report = auto_confirm_bindings(spec, apk)
    assert report['promoted'] == []
    assert any(x['id'] == 'fake' and x['reason'] == 'signature-contract-mismatch' for x in report['skipped'])
    assert spec.controls[0].binding is None


def test_auto_build_gate_stops_on_strong_unreviewed_candidate(tmp_path):
    import zipfile
    from modkit.menu import review_preflight
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    spec = MenuSpec("Test", controls=[
        MenuControl("bound", "Bound", "toggle", rva=0x1040, binding="bool_setter"),
        MenuControl("review", "Enable Cheat", "toggle", evidence_rva=0x1044,
                    evidence_signature="void X__EnableCheat (bool value, const MethodInfo* method);",
                    evidence_confidence=0.96, suggested_binding="bool_setter",
                    call_abi="il2cpp", evidence_is_static=True),
    ])
    report = review_preflight(spec, apk)
    assert report["readyForPayload"] is True
    assert report["readyForAutoBuild"] is False
    assert report["counts"]["actionableReview"] == 1
    assert any(x["code"] == "ACTIONABLE_REVIEW_REMAINING" for x in report["issues"])


def test_auto_confirm_emits_verification_record(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings
    from modkit.reworkspace.signature import rodroid_signature_contract
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    sig = "void X__EnableCheat (bool value, const MethodInfo* method);"
    contract = rodroid_signature_contract(sig)
    spec = MenuSpec("Test", controls=[MenuControl(
        "cheat", "Enable Cheat", "toggle", evidence_rva=0x1040,
        evidence_signature=sig, evidence_confidence=0.97,
        suggested_binding=contract["bindingSuggestion"], evidence_is_static=True,
        call_abi="il2cpp",
    )])
    result = auto_confirm_bindings(spec, apk)
    assert result["schema"] == "modkit-menu-auto-confirm-1.1"
    assert result["promoted"] == ["cheat"]
    row = result["promotionRecords"][0]
    assert row["rva"] == 0x1040
    assert row["signature"] == sig
    assert row["elfVerification"]["fileOffset"] is not None
    assert row["decision"] == "auto-confirmed-signature-plus-elf"


def test_seed_preserves_corroborating_evidence_chain():
    analysis = {"controlCandidates": [{
        "id":"candidate.cheat", "title":"Cheat Mode", "suggestedType":"toggle",
        "source":"Drova.dll", "kind":"rodroid-method", "location":"RVA 0x1040",
        "evidenceRva":0x1040, "confidence":0.98, "status":"correlated", "evidenceCount":3,
        "corroboratingEvidence":[
            {"source":"assets/game.bundle","kind":"unity-string","value":"Cheat_Mode","location":""},
            {"source":"lib/arm64-v8a/libBedo.so","kind":"native-string","value":"Cheat Mode","location":"file+0x20"},
        ],
    }], "findings": []}
    c = spec_from_analysis(analysis).controls[0]
    assert c.evidence_status == "correlated"
    assert c.evidence_count == 3
    assert len(c.corroborating_evidence) == 2
    raw = MenuSpec("T", controls=[c]).json()["controls"][0]
    assert raw["corroborating_evidence"][0]["kind"] == "unity-string"


def test_seed_preserves_apk_and_libil2cpp_hash_provenance():
    analysis = {
        "apk": {"sha256": "a" * 64},
        "inventory": {"native": [{
            "name": "extra/libil2cpp.so", "soname": "libil2cpp.so", "sha256": "b" * 64,
        }]},
        "controlCandidates": [], "findings": [],
    }
    spec = spec_from_analysis(analysis)
    assert spec.source_apk_sha256 == "a" * 64
    assert spec.target_sha256 == "b" * 64
    raw = spec.json()
    assert raw["schema"] == "modkit-menu-1.1"
    assert raw["sourceApkSha256"] == "a" * 64
    assert raw["targetSha256"] == "b" * 64


def test_validate_split_apk_uses_hash_bound_external_libil2cpp(tmp_path):
    import hashlib
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/placeholder", b"x")
    lib = fixtures.so_blob()
    (tmp_path / "library.so").write_bytes(lib)
    spec = MenuSpec("Test", target_sha256=hashlib.sha256(lib).hexdigest(), controls=[
        MenuControl("run", "Run", "button", rva=0x1040, binding="action",
                    target_so="libil2cpp.so", call_abi="il2cpp", is_static=True),
    ])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is False
    row = report["checks"][0]
    assert row["moduleSource"] == "external-selected-library"
    assert row["apkPath"] == "external:library.so"
    assert row["targetSha256"] == spec.target_sha256


def test_validate_split_apk_rejects_external_libil2cpp_hash_mismatch(tmp_path):
    import zipfile
    from modkit.menu import validate_bindings
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/placeholder", b"x")
    (tmp_path / "library.so").write_bytes(fixtures.so_blob())
    spec = MenuSpec("Test", target_sha256="f" * 64, controls=[
        MenuControl("run", "Run", "button", rva=0x1040, binding="action",
                    target_so="libil2cpp.so", call_abi="il2cpp", is_static=True),
    ])
    report = validate_bindings(spec, apk)
    assert report["blocked"] is True
    assert any(x["code"] == "EXTERNAL_TARGET_HASH_MISMATCH" for x in report["issues"])


def test_seed_preserves_semantic_verification_and_auto_confirm_requires_it(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings, spec_from_analysis
    from modkit.selftest import fixtures

    analysis = {'controlCandidates': [{
        'id': 'candidate.debug', 'title': 'Enable Debug', 'suggestedType': 'toggle',
        'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-metadata-callable',
        'location': 'RVA 0x1040', 'evidenceRva': 0x1040, 'confidence': 0.98,
        'bindingSuggestion': 'bool_setter', 'isStatic': True,
        'semanticVerified': False, 'semanticStatus': 'correlated-review',
        'semanticConfidence': 0.55, 'semanticTags': ['debug'],
        'semanticBlocker': 'semantic-direct-call-verification-required',
        'semanticEvidence': [{'kind': 'metadata-callable'}],
        'signatureContract': {
            'signature': 'void X__EnableDebug (bool value, const MethodInfo* method);',
            'bindingSuggestion': 'bool_setter', 'isStatic': True,
            'suggestedControlType': 'toggle', 'managedValueType': 'System.Boolean',
        },
    }], 'findings': []}
    spec = spec_from_analysis(analysis)
    c = spec.controls[0]
    assert c.semantic_verified is False
    assert c.semantic_status == 'correlated-review'
    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    result = auto_confirm_bindings(spec, apk)
    assert result['promoted'] == []
    assert any(x['id'] == c.id and x['reason'] == 'semantic-direct-call-verification-required' for x in result['skipped'])


def test_semantically_verified_seed_reaches_existing_elf_preflight(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings, spec_from_analysis
    from modkit.selftest import fixtures

    analysis = {'controlCandidates': [{
        'id': 'candidate.debug', 'title': 'Enable Debug', 'suggestedType': 'toggle',
        'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-metadata-callable',
        'location': 'RVA 0x1040', 'evidenceRva': 0x1040, 'confidence': 0.98,
        'bindingSuggestion': 'bool_setter', 'isStatic': True,
        'semanticVerified': True, 'semanticStatus': 'verified-static-xref',
        'semanticConfidence': 0.91, 'semanticTags': ['debug'],
        'semanticEvidence': [{'kind': 'managed-incoming-direct-call', 'peer': 'Game.Debug::ToggleDebug'}],
        'signatureContract': {
            'signature': 'void X__EnableDebug (bool value, const MethodInfo* method);',
            'bindingSuggestion': 'bool_setter', 'isStatic': True,
            'suggestedControlType': 'toggle', 'managedValueType': 'System.Boolean',
        },
    }], 'findings': []}
    spec = spec_from_analysis(analysis)
    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    result = auto_confirm_bindings(spec, apk)
    assert result['promoted'] == [spec.controls[0].id]
    assert result['promotionRecords'][0]['semanticVerified'] is True
    assert 'semantic-xref' in result['promotionRecords'][0]['decision']


def test_dev15_explicit_context_failure_blocks_auto_confirm(tmp_path):
    import zipfile
    from modkit.menu import auto_confirm_bindings, spec_from_analysis
    from modkit.selftest import fixtures

    analysis = {'controlCandidates': [{
        'id': 'candidate.debug.ctx', 'title': 'Enable Debug', 'suggestedType': 'toggle',
        'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-metadata-callable',
        'location': 'RVA 0x1040', 'evidenceRva': 0x1040, 'confidence': 0.98,
        'bindingSuggestion': 'bool_setter', 'isStatic': True,
        'semanticVerified': True, 'semanticStatus': 'verified-static-xref',
        'contextVerified': False, 'contextStatus': 'review',
        'contextBlocker': 'method-local-context-verification-required',
        'signatureContract': {
            'signature': 'void X__EnableDebug (bool value, const MethodInfo* method);',
            'bindingSuggestion': 'bool_setter', 'isStatic': True,
            'suggestedControlType': 'toggle', 'managedValueType': 'System.Boolean',
        },
    }], 'findings': []}
    spec = spec_from_analysis(analysis)
    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    result = auto_confirm_bindings(spec, apk)
    assert result['promoted'] == []
    assert any(x['id'] == spec.controls[0].id and x['reason'] == 'method-local-context-verification-required'
               for x in result['skipped'])


def test_dev15_context_fields_survive_menu_seed():
    from modkit.menu import spec_from_analysis
    analysis = {'controlCandidates': [{
        'id': 'candidate.ctx', 'title': 'State', 'suggestedType': 'button',
        'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-metadata-callable',
        'evidenceRva': 0x2220, 'confidence': 0.95, 'bindingSuggestion': 'action',
        'isStatic': True, 'semanticVerified': True, 'contextVerified': True,
        'contextStatus': 'verified-method-context', 'contextConfidence': 0.82,
        'contextEvidence': [{'kind': 'method-local-managed-callee', 'peer': 'Game.State::Apply'}],
        'signatureContract': {'signature': 'void X (const MethodInfo* method);',
                              'bindingSuggestion': 'action', 'isStatic': True},
    }], 'findings': []}
    c = spec_from_analysis(analysis).controls[0]
    assert c.context_verified is True
    assert c.context_status == 'verified-method-context'
    assert c.context_confidence == 0.82
    assert c.context_evidence[0]['kind'] == 'method-local-managed-callee'
