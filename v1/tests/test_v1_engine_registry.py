from modkit.engines import build_default_registry, catalog_json
from modkit.engines.base import ArtifactKind, EngineKind, EngineState


def test_engine_ids_are_unique_and_deterministic():
    registry = build_default_registry()
    ids = [engine.engine_id for engine in registry.all()]
    assert len(ids) == len(set(ids))
    assert ids == [engine.engine_id for engine in registry.all()]


def test_required_builtin_engines_are_registered():
    registry = build_default_registry()
    required = {
        "apkset.inventory",
        "runtime.profiler",
        "runtime.engine-router",
        "protection.deobfuscator",
        "elf.universal-inventory",
        "dotnet.static",
        "dotnet.metadata-embedded",
        "unreal.static",
        "unreal.deep-embedded",
        "godot.static",
        "godot.deep-embedded",
        "defold.static",
        "defold.deep-embedded",
        "qt.qml-static",
        "qt.qml-deep-embedded",
        "webassembly.static",
        "webassembly.deep-embedded",
        "jsc.deep-embedded",
        "apktool.android",
        "dex.structural",
        "jadx.android",
        "elf.static",
        "il2cpp.rodroid",
        "unity.discovery",
        "hermes.deep-embedded",
        "semantic.gameplay",
        "security.passive",
        "runtime.root-procfs",
        "report.evidence-bundle",
    }
    assert required.issubset({engine.engine_id for engine in registry.all() if engine.bundled})


def test_optional_entry_points_are_not_reported_as_bundled():
    registry = build_default_registry()
    for engine_id in ("ghidra.external", "rizin.external", "frida.external", "flutter.external", "hermes.external"):
        engine = registry.get(engine_id)
        assert engine.state in {EngineState.ENTRY_POINT, EngineState.OPTIONAL}
        assert not engine.bundled


def test_embedded_engines_replace_manual_import_as_primary_path():
    registry = build_default_registry()
    apktool = registry.get("apktool.android")
    hermes = registry.get("hermes.deep-embedded")
    assert apktool.bundled and apktool.state == EngineState.BUILTIN
    assert hermes.bundled and hermes.state == EngineState.BUILTIN
    assert registry.get("apktool.bridge").state == EngineState.ENTRY_POINT
    assert registry.get("hermes.deep-bridge").state == EngineState.ENTRY_POINT


def test_process_and_dex_capabilities_are_queryable():
    registry = build_default_registry()
    runtime = registry.for_artifact(ArtifactKind.PROCESS)
    assert any(engine.kind == EngineKind.RUNTIME and engine.engine_id == "runtime.root-procfs" for engine in runtime)
    dex = registry.for_artifact(ArtifactKind.DEX)
    assert {"dex.structural", "jadx.android", "apktool.android"}.issubset({engine.engine_id for engine in dex})


def test_catalog_json_has_stable_schema():
    payload = catalog_json()
    assert '"schema": "modkit-engine-catalog-1.0"' in payload
    assert '"runtime.root-procfs"' in payload
    assert '"apktool.android"' in payload
    assert '"hermes.deep-embedded"' in payload
    assert '"frida.external"' in payload


def test_universal_runtime_and_deobfuscation_engines_are_bundled():
    registry = build_default_registry()
    profiler = registry.get("runtime.profiler")
    router = registry.get("runtime.engine-router")
    deob = registry.get("protection.deobfuscator")
    assert profiler.bundled and "multi-runtime" in profiler.capabilities
    assert router.bundled and "coverage-gaps" in router.capabilities
    assert deob.bundled and "stable-aliases" in deob.capabilities
    assert "packer-markers" in deob.capabilities


def test_universal_artifact_inventory_engines_are_bundled():
    registry = build_default_registry()
    expected = {
        "elf.universal-inventory",
        "dotnet.static",
        "unreal.static",
        "godot.static",
        "defold.static",
        "qt.qml-static",
        "webassembly.static",
    }
    assert expected.issubset({engine.engine_id for engine in registry.all() if engine.bundled})


def test_unreal_and_godot_deep_engines_are_bundled():
    registry = build_default_registry()
    unreal = registry.get("unreal.deep-embedded")
    godot = registry.get("godot.deep-embedded")
    assert unreal.bundled and "iostore-pairs" in unreal.capabilities
    assert godot.bundled and "text-scene-graph" in godot.capabilities


def test_defold_and_qml_deep_engines_are_bundled():
    registry = build_default_registry()
    defold = registry.get("defold.deep-embedded")
    qml = registry.get("qt.qml-deep-embedded")
    assert defold.bundled and "archive-pair" in defold.capabilities
    assert qml.bundled and "properties" in qml.capabilities


def test_jsc_and_webassembly_deep_engines_are_bundled():
    registry = build_default_registry()
    jsc = registry.get("jsc.deep-embedded")
    wasm = registry.get("webassembly.deep-embedded")
    assert jsc.bundled and "jsc-binary-inventory" in jsc.capabilities
    assert wasm.bundled and "exports" in wasm.capabilities
