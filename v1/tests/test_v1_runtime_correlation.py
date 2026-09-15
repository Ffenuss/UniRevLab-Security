import json
from pathlib import Path

from modkit.mobile.runtime_correlate import correlate, build_workspace_correlation

ROOT = Path(__file__).resolve().parents[1]


def test_exact_library_rva_maps_to_runtime_va_without_promoting_buildability():
    catalog = {"cards": [{
        "id": "Gameplay:hp",
        "title": "Player::SetHealth",
        "source": "Gameplay",
        "verificationStage": "LOCATOR_CONFIRMED",
        "buildable": False,
        "locator": {"rva": 0x1234, "library": "libil2cpp.so"},
    }]}
    session = {
        "process": {"pid": 4242, "uid": 10123, "name": "game"},
        "moduleImages": [{
            "path": "/data/app/pkg/lib/arm64/libil2cpp.so",
            "loadBaseHex": "0x70000000",
            "mappingCount": 3,
            "executableMappings": 1,
        }],
        "mappings": [{
            "startHex": "0x70000000",
            "endHex": "0x70100000",
            "offsetHex": "0x0",
            "perms": "r-xp",
            "path": "/data/app/pkg/lib/arm64/libil2cpp.so",
        }],
    }
    out = correlate(catalog, session)
    assert out["correlationCount"] == 1
    row = out["correlations"][0]
    assert row["runtimeVaHex"] == "0x70001234"
    assert row["mapped"] is True
    assert row["matchMode"] == "EXACT_LIBRARY_BASENAME"
    assert row["promotesBuildability"] is False
    assert out["promotesBuildability"] is False
    assert out["writesTargetMemory"] is False
    assert out["injectsCode"] is False


def test_missing_library_does_not_guess_when_multiple_executable_modules_exist():
    catalog = {"cards": [{
        "id": "native:x",
        "title": "Native locator",
        "source": "RE",
        "verificationStage": "LOCATOR_CONFIRMED",
        "locator": {"rva": 0x40},
    }]}
    session = {
        "moduleImages": [
            {"path": "/a/libfoo.so", "loadBaseHex": "0x10000000", "executableMappings": 1},
            {"path": "/a/libbar.so", "loadBaseHex": "0x20000000", "executableMappings": 1},
        ],
        "mappings": [],
    }
    out = correlate(catalog, session)
    assert out["correlationCount"] == 0
    assert out["unresolvedCount"] == 1
    assert out["unresolved"][0]["reason"] == "MODULE_UNRESOLVED"


def test_workspace_correlation_writes_evidence_file(tmp_path):
    (tmp_path / "simple-catalog.json").write_text(json.dumps({"cards": [{
        "id": "x", "title": "Foo", "source": "RE", "verificationStage": "LOCATOR_CONFIRMED",
        "locator": {"rva": "0x80", "library": "libfoo.so"},
    }]}), encoding="utf-8")
    session = {
        "moduleImages": [{"path": "/lib/libfoo.so", "loadBaseHex": "0x50000000", "executableMappings": 1}],
        "mappings": [{"startHex": "0x50000000", "endHex": "0x50010000", "perms": "r-xp", "path": "/lib/libfoo.so"}],
    }
    (tmp_path / "runtime-session.json").write_text(json.dumps(session), encoding="utf-8")
    out = build_workspace_correlation(tmp_path)
    stored = json.loads((tmp_path / "runtime-correlation.json").read_text(encoding="utf-8"))
    assert out["schema"] == "modkit-runtime-correlation-1.0"
    assert stored["correlations"][0]["runtimeVaHex"] == "0x50000080"


def test_android_runtime_backend_exports_module_load_bias_and_never_writes_memory():
    engine = (ROOT / "android/app/src/main/java/dev/modkit/mobile/RootProcessEngine.java").read_text(encoding="utf-8")
    lab = (ROOT / "android/app/src/main/java/dev/modkit/mobile/ProcessLabActivity.java").read_text(encoding="utf-8")
    assert '"moduleImages"' in engine
    assert '"loadBaseHex"' in engine
    assert 'start-fileOffset' in engine or 'start - fileOffset' in engine
    assert '"mappings"' in engine
    assert 'writesTargetMemory",false' in engine
    assert 'getModule("modkit.mobile.runtime_correlate")' in lab
    assert 'runtime-correlation.json' in lab
    assert '/mem' not in engine
    assert 'process_vm_writev' not in engine
