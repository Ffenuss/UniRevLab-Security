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
        "dex.structural",
        "jadx.android",
        "elf.static",
        "il2cpp.rodroid",
        "unity.discovery",
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


def test_process_and_dex_capabilities_are_queryable():
    registry = build_default_registry()
    runtime = registry.for_artifact(ArtifactKind.PROCESS)
    assert any(engine.kind == EngineKind.RUNTIME and engine.engine_id == "runtime.root-procfs" for engine in runtime)
    dex = registry.for_artifact(ArtifactKind.DEX)
    assert {"dex.structural", "jadx.android"}.issubset({engine.engine_id for engine in dex})


def test_catalog_json_has_stable_schema():
    payload = catalog_json()
    assert '"schema": "modkit-engine-catalog-1.0"' in payload
    assert '"runtime.root-procfs"' in payload
    assert '"frida.external"' in payload
