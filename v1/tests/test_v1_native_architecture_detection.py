from __future__ import annotations

import zipfile
from pathlib import Path

from modkit.mobile import deep_gameplay, native_deep


def test_native_architecture_marker_profile_recognizes_injector_hook_overlay_and_il2cpp():
    strings = [
        {"text": "ptrace", "markers": native_deep._marker_tags("ptrace")},
        {"text": "dlopen", "markers": native_deep._marker_tags("dlopen")},
        {"text": "DobbyHook", "markers": native_deep._marker_tags("DobbyHook")},
        {"text": "ImGui_ImplOpenGL3", "markers": native_deep._marker_tags("ImGui_ImplOpenGL3")},
        {"text": "eglSwapBuffers", "markers": native_deep._marker_tags("eglSwapBuffers")},
        {"text": "il2cpp_class_from_name", "markers": native_deep._marker_tags("il2cpp_class_from_name")},
    ]
    profile = native_deep._architecture_profile(
        ["DobbyInstrument", "ANativeWindow"],
        strings,
        ["libdl.so"],
    )
    kinds = {row["kind"] for row in profile["features"]}
    assert "ROOT_OR_EXTERNAL_NATIVE_INJECTOR" in kinds
    assert "DOBBY_HOOK_FRAMEWORK" in kinds
    assert "IMGUI_EGL_OVERLAY" in kinds
    assert "IL2CPP_RUNTIME_RESOLVER" in kinds


def test_runtime_lookup_chain_requires_same_function_api_and_identifier():
    strings = [
        {
            "text": "il2cpp_class_from_name", "rva": 0x3000, "domain": "",
            "markers": ["il2cpp-runtime-api"], "lookupIdentifier": False, "lookupRole": None,
        },
        {
            "text": "LogicBattleManager", "rva": 0x3010, "domain": "",
            "markers": [], "lookupIdentifier": True, "lookupRole": "type",
        },
        {
            "text": "m_HeroHealth", "rva": 0x3020, "domain": "health",
            "markers": [], "lookupIdentifier": True, "lookupRole": "field",
        },
    ]
    xrefs = [
        {"sourceRva": 0x1000, "sourceFunction": "resolve_game", "targetRva": 0x3000, "xrefRva": 0x1010},
        {"sourceRva": 0x1000, "sourceFunction": "resolve_game", "targetRva": 0x3010, "xrefRva": 0x1020},
        {"sourceRva": 0x1000, "sourceFunction": "resolve_game", "targetRva": 0x3020, "xrefRva": 0x1030},
    ]
    chains = native_deep._runtime_lookup_chains(strings, xrefs, [])
    assert len(chains) == 1
    row = chains[0]
    assert row["sourceRva"] == 0x1000
    assert row["sourceFunction"] == "resolve_game"
    assert "il2cpp_class_from_name" in row["apiNames"]
    assert {x["value"] for x in row["candidateIdentifiers"]} == {"LogicBattleManager", "m_HeroHealth"}
    assert row["gameplayDomains"] == ["health"]
    assert row["confidence"] == "HIGH"
    assert row["exactManagedIdentityConfirmed"] is False
    assert row["automationExcluded"] is True

    # The same strings in different functions are not enough to claim a chain.
    split = [
        {"sourceRva": 0x1000, "sourceFunction": "api", "targetRva": 0x3000, "xrefRva": 0x1010},
        {"sourceRva": 0x2000, "sourceFunction": "name", "targetRva": 0x3010, "xrefRva": 0x2010},
    ]
    assert native_deep._runtime_lookup_chains(strings[:2], split, []) == []


def test_virtual_container_and_root_orchestrator_markers_are_detected_in_dex(tmp_path: Path):
    apk = tmp_path / "launcher.apk"
    dex = b"\0".join([
        b"Lcom/lody/virtual/client/NativeEngine;",
        b"VirtualCore",
        b"/data/local/tmp/",
        b"chmod 755",
        b"getInjectCommands",
    ])
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", dex)
    with zipfile.ZipFile(apk) as zf:
        profile = native_deep._container_marker_profile(zf, apk)
    kinds = {row["kind"] for row in profile["features"]}
    assert "VIRTUAL_CONTAINER_RUNTIME" in kinds
    assert "ROOT_INJECTOR_ORCHESTRATOR" in kinds
    assert profile["dexBytesScanned"] == len(dex)


def test_asset_elf_is_included_in_native_candidate_inventory(tmp_path: Path):
    apk = tmp_path / "injector.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"/data/local/tmp/\0chmod 755\0libsuperuser")
        zf.writestr("assets/execML", b"\x7fELF" + b"not-a-real-elf")
        zf.writestr("assets/libPayload.so", b"\x7fELF" + b"also-not-a-real-elf")
    report = native_deep.scan_apk_paths([apk], tmp_path / "cache")
    assert report["candidateElfCount"] == 2
    assert report["candidateLibraryCount"] == 2
    assert report["analyzedLibraryCount"] == 0
    error_entries = {row.get("entry") for row in report["errors"]}
    assert {"assets/execML", "assets/libPayload.so"} <= error_entries
    assert any(
        feature.get("kind") == "ROOT_INJECTOR_ORCHESTRATOR"
        for profile in report["containerProfiles"]
        for feature in profile.get("features", [])
    )


def test_deep_gameplay_preserves_runtime_lookup_as_review_only():
    row = {
        "id": "lookup-1",
        "kind": "IL2CPP_RUNTIME_LOOKUP_CHAIN",
        "title": "IL2CPP runtime lookup: PlayerStats, m_Health",
        "engineId": native_deep.ENGINE_ID,
        "entry": "lib/arm64-v8a/libmod.so",
        "library": "lib/arm64-v8a/libmod.so",
        "abi": "arm64-v8a",
        "sourceRva": 0x1234,
        "sourceFunction": "resolve",
        "gameplayDomains": ["health"],
        "runtimeLookup": {
            "candidateIdentifiers": [
                {"value": "PlayerStats", "role": "type"},
                {"value": "m_Health", "role": "field"},
            ],
            "apiNames": ["il2cpp_class_from_name", "il2cpp_class_get_field_from_name"],
            "confidence": "HIGH",
            "exactManagedIdentityConfirmed": False,
            "automationExcluded": True,
        },
        "ownershipKind": "APP_OR_GAME",
        "trustBoundary": "local",
    }
    findings = deep_gameplay._findings_from_runtime_lookup(row)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["gameplayDomain"] == "health"
    assert finding["status"] == "REVIEW"
    assert finding["automationExcluded"] is True
    assert finding["patchReady"] is False
    assert finding.get("rva") is None
    assert finding["sourceRva"] == 0x1234


def test_simple_mode_reads_native_architecture_reports():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/simple_mode.py").read_text(encoding="utf-8")
    assert '("native-deep.json", "NativeDeep")' in source
    assert '("deep-gameplay.json", "Gameplay")' in source
    assert 'source == "NativeDeep"' in source


def test_il2cpp_argument_flow_confirms_assembly_class_and_field_registers():
    import struct
    from types import SimpleNamespace

    def adrp(rd, pc, target):
        delta = (target & ~0xFFF) - (pc & ~0xFFF)
        imm21 = (delta >> 12) & ((1 << 21) - 1)
        return 0x90000000 | ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd

    def add(rd, rn, imm):
        return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

    def mov(rd, rm):
        return 0xAA0003E0 | (rm << 16) | rd

    BL = 0x94000000
    start = 0x1000
    words = []
    call_rows = []

    def emit(word):
        words.append(word)
        return start + (len(words) - 1) * 4

    emit(adrp(1, 0x1000, 0x3000))
    emit(add(1, 1, 0x000))
    pc = emit(BL)
    call_rows.append({"sourceRva": start, "sourceFunction": "resolve", "callRva": pc,
                      "targetFunction": "il2cpp_domain_assembly_open", "targetRva": 0x8000})
    emit(mov(19, 0))
    emit(mov(0, 19))
    pc = emit(BL)
    call_rows.append({"sourceRva": start, "sourceFunction": "resolve", "callRva": pc,
                      "targetFunction": "il2cpp_assembly_get_image", "targetRva": 0x8010})
    emit(mov(20, 0))
    emit(adrp(1, start + len(words) * 4, 0x3000))
    emit(add(1, 1, 0x020))
    emit(adrp(2, start + len(words) * 4, 0x3000))
    emit(add(2, 2, 0x040))
    emit(mov(0, 20))
    pc = emit(BL)
    call_rows.append({"sourceRva": start, "sourceFunction": "resolve", "callRva": pc,
                      "targetFunction": "il2cpp_class_from_name", "targetRva": 0x8020})
    emit(mov(21, 0))
    emit(adrp(1, start + len(words) * 4, 0x3000))
    emit(add(1, 1, 0x060))
    emit(mov(0, 21))
    pc = emit(BL)
    call_rows.append({"sourceRva": start, "sourceFunction": "resolve", "callRva": pc,
                      "targetFunction": "il2cpp_class_get_field_from_name", "targetRva": 0x8030})

    blob = b"".join(struct.pack("<I", word) for word in words)

    class FakeElf:
        def is_arm64(self):
            return True

        def read_at_rva(self, rva, size):
            assert rva == start
            return blob[:size]

    strings = [
        {"rva": 0x3000, "text": "Assembly-CSharp.dll", "domain": "", "lookupRole": "identifier"},
        {"rva": 0x3020, "text": "Game", "domain": "", "lookupRole": "identifier"},
        {"rva": 0x3040, "text": "PlayerStats", "domain": "", "lookupRole": "type"},
        {"rva": 0x3060, "text": "m_Health", "domain": "health", "lookupRole": "field"},
    ]
    functions = [SimpleNamespace(value=start, size=len(blob), name="resolve", shndx=1)]

    flows = native_deep._il2cpp_argument_register_flow(FakeElf(), functions, strings, call_rows)
    kinds = [row["lookupKind"] for row in flows]
    assert kinds == ["assembly", "image", "type", "field"]

    type_flow = next(row for row in flows if row["lookupKind"] == "type")
    assert type_flow["assembly"] == "Assembly-CSharp.dll"
    assert type_flow["namespace"] == "Game"
    assert type_flow["identifier"] == "PlayerStats"
    assert type_flow["identifierRegister"] == "X2"
    assert type_flow["argumentFlowConfirmed"] is True
    assert type_flow["exactManagedIdentityConfirmed"] is False

    field_flow = next(row for row in flows if row["lookupKind"] == "field")
    assert field_flow["assembly"] == "Assembly-CSharp.dll"
    assert field_flow["namespace"] == "Game"
    assert field_flow["type"] == "PlayerStats"
    assert field_flow["identifier"] == "m_Health"
    assert field_flow["identifierRegister"] == "X1"
    assert field_flow["classObjectFlowConfirmed"] is True
    assert field_flow["gameplayDomain"] == "health"
    assert field_flow["argumentFlowConfirmed"] is True
    assert field_flow["exactManagedIdentityConfirmed"] is True
    assert field_flow["automationExcluded"] is True


def test_il2cpp_argument_flow_drops_caller_saved_state_across_unknown_call():
    import struct
    from types import SimpleNamespace

    def adrp(rd, pc, target):
        delta = (target & ~0xFFF) - (pc & ~0xFFF)
        imm21 = (delta >> 12) & ((1 << 21) - 1)
        return 0x90000000 | ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd

    def add(rd, rn, imm):
        return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

    BL = 0x94000000
    start = 0x1000
    words = [
        adrp(1, 0x1000, 0x3000),
        add(1, 1, 0),
        BL,  # unknown call: X1 must be invalidated
        BL,  # class_get_field_from_name
    ]
    blob = b"".join(struct.pack("<I", word) for word in words)

    class FakeElf:
        def is_arm64(self):
            return True

        def read_at_rva(self, rva, size):
            return blob[:size]

    functions = [SimpleNamespace(value=start, size=len(blob), name="resolve", shndx=1)]
    calls = [{
        "sourceRva": start, "sourceFunction": "resolve", "callRva": start + 12,
        "targetFunction": "il2cpp_class_get_field_from_name", "targetRva": 0x8030,
    }]
    strings = [{"rva": 0x3000, "text": "m_Health", "domain": "health", "lookupRole": "field"}]
    assert native_deep._il2cpp_argument_register_flow(FakeElf(), functions, strings, calls) == []


def test_deep_gameplay_promotes_argument_flow_strength_without_buildability():
    row = {
        "id": "arg-flow-1",
        "kind": "IL2CPP_RUNTIME_ARGUMENT_FLOW",
        "title": "IL2CPP argument flow: Assembly-CSharp.dll :: Game :: PlayerStats :: m_Health",
        "engineId": native_deep.ENGINE_ID,
        "entry": "assets/libCEZ.so",
        "library": "assets/libCEZ.so",
        "abi": "arm64-v8a",
        "sourceRva": 0x1110,
        "sourceFunction": "resolve",
        "callRva": 0x1190,
        "gameplayDomain": "health",
        "runtimeArgumentFlow": {
            "lookupKind": "field",
            "identifier": "m_Health",
            "identifierRegister": "X1",
            "assembly": "Assembly-CSharp.dll",
            "namespace": "Game",
            "type": "PlayerStats",
            "classObjectFlowConfirmed": True,
            "argumentFlowConfirmed": True,
            "exactManagedIdentityConfirmed": True,
            "automationExcluded": True,
        },
        "ownershipKind": "APP_OR_GAME",
        "trustBoundary": "local",
    }
    findings = deep_gameplay._findings_from_runtime_argument_flow(row)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["gameplayDomain"] == "health"
    assert finding["status"] == "CORRELATED_EVIDENCE"
    assert finding["semanticConfidence"] == "VERY_HIGH"
    assert finding["argumentFlowConfirmed"] is True
    assert finding["exactManagedIdentityConfirmed"] is True
    assert finding["automationExcluded"] is True
    assert finding["patchReady"] is False
    assert finding.get("rva") is None
