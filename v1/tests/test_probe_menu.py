import json
from pathlib import Path

from modkit.menu import MenuSpec, probe_spec_from_gameplay, review_preflight, write_project
from modkit.menu.runtime_config import decode_runtime_config, encode_runtime_config


def _coverage():
    return {
        "schema": "modkit-gameplay-coverage-test",
        "cards": [
            {"domain": "health", "status": "FIELD OBSERVED", "fields": [
                {"declaringType": "Game.Unit", "name": "alive", "runtimeOffset": 0x19,
                 "primitive": "bool", "fieldDefinitionIndex": 1, "declaringTypeIndex": 10},
            ]},
            {"domain": "progression", "status": "FIELD OBSERVED", "fields": [
                {"declaringType": "Game.HeroData", "name": "level", "runtimeOffset": 0x14,
                 "primitive": "int32", "fieldDefinitionIndex": 2, "declaringTypeIndex": 11},
            ]},
            {"domain": "movement", "status": "CONFIRMED", "fields": [
                {"declaringType": "Game.AvatarActor", "name": "actionSpeed", "runtimeOffset": 0x8C,
                 "primitive": "float", "fieldDefinitionIndex": 3, "declaringTypeIndex": 12},
            ]},
        ],
    }


def test_probe_spec_is_read_only_and_preserves_exact_field_identity():
    spec = probe_spec_from_gameplay(_coverage(), title="Probe")
    assert len(spec.controls) == 3
    assert all(c.binding is None for c in spec.controls)
    assert all(c.probe_kind == "watch" for c in spec.controls)
    got = {(c.probe_owner, c.probe_field, c.probe_offset, c.probe_primitive) for c in spec.controls}
    assert ("Game.Unit", "alive", 0x19, "bool") in got
    assert ("Game.HeroData", "level", 0x14, "int32") in got
    assert ("Game.AvatarActor", "actionSpeed", 0x8C, "float") in got


def test_probe_spec_encodes_into_runtime_v4_without_executable_binding():
    spec = probe_spec_from_gameplay(_coverage(), title="Probe")
    decoded = decode_runtime_config(encode_runtime_config(spec))
    assert decoded["version"] == 4
    assert len(decoded["controls"]) == 3
    assert all(c["probeReadOnly"] for c in decoded["controls"])
    assert not any(c["resolverRva"] for c in decoded["controls"])


def test_probe_project_uses_builtin_probe_runtime(tmp_path: Path):
    spec = probe_spec_from_gameplay(_coverage(), title="Probe")
    report = write_project(spec, tmp_path / "menu")
    assert report["executableBindings"] == 0
    assert report["readOnlyProbes"] == 3
    assert report["runtimeMode"] == "built-in-generic-probe-config"
    assert Path(report["runtimeProject"], "MENU-SPEC.json").is_file()


def test_probe_preflight_ready_without_executable_bindings(tmp_path: Path):
    # validate_bindings does not need a real APK when no source hash or executable binding is present;
    # review_preflight still needs a Path object but never opens it in this case.
    spec = probe_spec_from_gameplay(_coverage(), title="Probe")
    fake = tmp_path / "base.apk"
    report = review_preflight(spec, fake)
    assert report["readyForPayload"] is True
    assert report["counts"]["bound"] == 0
    assert report["counts"]["probeReadOnly"] == 3
    assert any(i["code"] == "READ_ONLY_RUNTIME_PROBES" for i in report["issues"])
