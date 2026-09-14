"""Codegen: the emitted tree must be internally consistent with the plan."""

from __future__ import annotations

import json
import re
import struct

import pytest

from modkit.codegen.gen import Generator, c_type, jni_mangle, width_of
from modkit.codegen.project import BuildOptions, write_project


@pytest.fixture
def gen(plan):
    return Generator(plan, package="com.neondrift.game", app_name="neondrift",
                     overlay=True, imgui=False, dobby=False)


@pytest.fixture
def files(gen):
    return gen.files()


def test_every_expected_file_is_emitted(files):
    for path in ("app/src/main/cpp/game.cpp", "app/src/main/cpp/game.hpp",
                 "app/src/main/cpp/features.inc", "app/src/main/cpp/modkit.cpp",
                 "app/src/main/cpp/jni_main.cpp", "app/src/main/cpp/CMakeLists.txt",
                 "app/src/main/modkit/features.json", "app/src/main/modkit/patch_plan.json",
                 "app/src/main/assets/modkit.properties", "app/build.gradle", "build.sh"):
        assert path in files, f"missing {path}"


def test_feature_table_matches_the_plan(files, plan):
    inc = files["app/src/main/cpp/features.inc"]
    rows = re.findall(r"^  \{(\d+),", inc, re.M)
    assert len(rows) == len(plan.features) == 21
    assert rows == [str(i) for i in range(len(plan.features))]
    for f in plan.features:
        assert f'"{f.id}"' in inc


def test_rvas_are_copied_verbatim(files, plan):
    inc = files["app/src/main/cpp/features.inc"]
    for f in plan.features:
        if f.rva and f.kind.value != "field_write":
            assert f"0x{f.rva:x}" in inc, f"{f.id}: rva missing"
        if f.kind.value == "field_write":
            assert f.rva is None


def decode_mov_imm_seq(raw: bytes) -> tuple[int, int]:
    """(value, dst_reg) for a MOVZ/MOVK chain — the same decode the CPU does."""
    value = 0
    dst = -1
    for w in struct.unpack(f"<{len(raw) // 4}I", raw):
        kind, imm, hw, rd = (w & 0x7F800000), (w >> 5) & 0xFFFF, (w >> 21) & 3, w & 0x1F
        if kind == 0x52800000:            # MOVZ (w or x, sf is bit 31 and masked out)
            value = imm << (16 * hw)
        elif kind == 0x72800000:          # MOVK
            value = (value & ~(0xFFFF << (16 * hw))) | (imm << (16 * hw))
        else:
            assert w == 0xD65F03C0, f"unexpected instruction 0x{w:08x} in a const-return stub"
        dst = rd
    return value, dst


def test_const_return_payloads_are_valid_arm64(files, plan):
    inc = files["app/src/main/cpp/features.inc"]
    blobs = dict((name, bytes(int(v, 16) for v in body.split(",")))
                 for name, body in re.findall(r"static const uint8_t (patch_\d+)\[\] = \{([^}]*)\}", inc))
    assert blobs, "the plan must contain patched getters"
    for name, raw in blobs.items():
        assert len(raw) % 4 == 0 and len(raw) >= 8, name
        assert struct.unpack("<I", raw[-4:])[0] == 0xD65F03C0, f"{name} must end in `ret`"
    for f in plan.features:
        if not f.patch:
            continue
        value, dst = decode_mov_imm_seq(f.patch.bytes[:-4])
        assert dst == 0, "the constant must land in x0/w0 (the return register)"
        assert value == int(f.value) & 0xFFFFFFFFFFFFFFFF, f"{f.id}: patched value mismatch"


def test_patch_plan_json_agrees_with_the_table(files, plan):
    plan_json = json.loads(files["app/src/main/modkit/patch_plan.json"])
    feats = [f for f in plan.features if f.patch]
    assert len(plan_json["patches"]) == len(feats)
    for item, f in zip(plan_json["patches"], feats):
        assert item["rva"] == f"0x{f.rva:x}"
        assert bytes.fromhex(item["bytes"]) == f.patch.bytes
    assert plan_json["abi"] == "arm64-v8a"


def test_features_json_roundtrips(files, plan):
    payload = json.loads(files["app/src/main/modkit/features.json"])
    assert payload["summary"]["classes"] == len(plan.program.classes)
    assert len(payload["features"]) == len(plan.features)
    assert payload["instance_hooks"], "the plan needs object-capturing hooks"
    for f, raw in zip(plan.features, payload["features"]):
        assert raw["kind"] == f.kind.value
        assert raw["rva"] == (f"0x{f.rva:x}" if f.rva else None)


def test_generated_cpp_declares_the_callbacks_it_references(files, plan):
    """features.inc names the callbacks and the callbacks read the table: both sides must
    be visible where they are used, or the TU will not compile."""
    src = files["app/src/main/cpp/game.cpp"]
    head = src[: src.index('#include "features.inc"')]
    for h in plan.instance_hooks:
        assert f"static void rep_{h.slot_name}(void *_this);" in head, h.slot_name
        assert f"void *g_orig_{h.slot_name} = nullptr;" in head, h.slot_name
    for i, f in enumerate(plan.features):
        if f.kind.value == "hook" and f.rva:
            assert re.search(rf"static [\w* ]+hk_{i}\(", head), f"missing forward decl for hk_{i}"
            assert f"void *g_hk{i}_orig = nullptr;" in head


def test_capture_and_feature_hooks_are_installed(files):
    src = files["app/src/main/cpp/game.cpp"]
    assert re.search(r"install_hooks\(g_capture_hooks, \d+\)", src)
    assert re.search(r"install_hooks\(g_feature_hooks, \d+\)", src)
    assert "game_install" in src and 'extern "C"' in src


def test_jni_symbols_match_the_java_package(files):
    assert f"Java_{jni_mangle('com.neondrift.game.loader')}_ModKit_nativeInit" in \
        files["app/src/main/cpp/jni_main.cpp"]
    assert "package com.neondrift.game.loader;" in files[
        "app/src/main/java/com/neondrift/game/loader/ModKit.java"]


def test_config_file_lists_every_feature_key(files, plan):
    props = files["app/src/main/assets/modkit.properties"]
    for f in plan.features:
        assert re.search(rf"^{re.escape(f.id)} = ", props, re.M)


def test_cmake_and_gradle_are_consistent(files):
    cmake = files["app/src/main/cpp/CMakeLists.txt"]
    assert "add_library(neondrift SHARED" in cmake
    assert 'MODKIT_TARGET_SO="libil2cpp.so"' in cmake
    assert "-D_GNU_SOURCE" in cmake
    assert "max-page-size=16384" in cmake          # 16 KB pages on newer devices
    assert "namespace 'com.neondrift.game.loader'" in files["app/build.gradle"]
    assert "arm64-v8a" in files["app/build.gradle"]


def test_readme_table_has_a_row_per_feature(files, plan):
    readme = files["app/src/main/modkit/README-BUILD.md"]
    assert readme.count("\n| ") >= len(plan.features)
    assert "Only `arm64` encodings" in readme


def test_types_and_widths_map_the_way_il2cpp_expects():
    assert c_type("System.Int32") == "int32_t"
    assert c_type("System.Boolean") == "bool"
    assert c_type("System.String") == "void*"
    assert c_type("NeonDrift.Play.Weapon") == "void*"
    assert c_type("System.Void") == "void"
    assert (width_of("System.Int64"), width_of("System.Single"), width_of("System.Byte")) == (8, 4, 1)


def test_project_is_written_and_guarded_against_overwrite(plan, tmp_path):
    out = tmp_path / "mod"
    written = write_project(plan, out, BuildOptions(package="com.neondrift.game",
                                                    app_name="neondrift"))
    assert (out / "app/src/main/cpp/game.cpp").exists()
    assert (out / "third_party/README.md").exists()
    assert (out / "build.sh").stat().st_mode & 0o111
    with pytest.raises(SystemExit):
        write_project(plan, out, BuildOptions(package="com.neondrift.game", app_name="neondrift"))
    write_project(plan, out, BuildOptions(package="com.neondrift.game", app_name="neondrift",
                                          force=True))


def test_non_arm64_abi_is_refused(plan, tmp_path):
    with pytest.raises(SystemExit, match="arm64"):
        write_project(plan, tmp_path / "x", BuildOptions(abi="armeabi-v7a"))

# ------------------------------------------------------- degenerate plans still compile

def test_plan_without_hooks_emits_valid_hook_tables(plan):
    """An empty C++ array is ill-formed; the tables must keep one inert slot."""
    from modkit.codegen.gen import Generator
    from modkit.ir import FeatureKind

    plan.features = [f for f in plan.features if f.kind is not FeatureKind.HOOK]
    assert plan.features, "fixture should still yield non-hook features"
    plan.instance_hooks = []
    gen = Generator(plan, package="com.neondrift.game", app_name="NeonDrift", imgui=True)
    src = gen.files()["app/src/main/cpp/features.inc"]
    for name in ("g_feature_hooks", "g_capture_hooks"):
        rows = src.split(f"static modkit::HookDef {name}[] = {{")[1].split("};")[0]
        assert rows.strip(), f"{name} must not be an empty initializer list"


def test_mixed_case_app_name_uses_same_native_library_name(plan):
    gen = Generator(plan, package="dev.modkit.generated", app_name="ModKitMenu")
    files = gen.files()
    cmake = files["app/src/main/cpp/CMakeLists.txt"]
    java = files["app/src/main/java/dev/modkit/generated/loader/ModKit.java"]
    assert "add_library(modkitmenu SHARED" in cmake
    assert 'System.loadLibrary("modkitmenu")' in java
