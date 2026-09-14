"""The CLI end to end, in a subprocess, exactly as a user runs it."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None, expect=0, timeout=180):
    proc = subprocess.run([sys.executable, "-m", "modkit", *args], cwd=cwd or ROOT,
                          capture_output=True, text=True, timeout=timeout)
    assert proc.returncode == expect, f"{args} -> {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return proc


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    from modkit.selftest import fixtures
    return fixtures.write_all(tmp_path_factory.mktemp("cli-target"))


def test_version_and_help():
    assert "modkit" in run("--version").stdout
    assert "offline Il2Cpp mod-menu generator" in run("--help").stdout
    for cmd in ("inspect", "dump", "analyze", "build", "verify", "apply", "rules", "selftest"):
        assert cmd in run("--help").stdout


def test_inspect_reports_both_files(target):
    out = json.loads(run("inspect", "-m", str(target["metadata"]), "-s", str(target["so"])).stdout)
    assert out["global-metadata.dat"]["version"] == 27
    assert out["global-metadata.dat"]["unity"] == "2020.3 - 2021.1"
    assert out["libil2cpp.so"]["arch"] == "aarch64"
    assert "liblog.so" in out["libil2cpp.so"]["needed"]


def test_inspect_survives_a_bogus_metadata(tmp_path):
    bad = tmp_path / "global-metadata.dat"
    bad.write_bytes(b"garbage" * 40)
    out = json.loads(run("inspect", "-m", str(bad)).stdout)
    assert "error" in out["global-metadata.dat"]
    assert "magic" in out["global-metadata.dat"]["error"]


def test_analyze_prints_the_plan(target):
    stdout = run("analyze", "-d", str(target["dump"]), "--no-dumper", "--limit", "3").stdout
    assert "[Economy]" in stdout and "conf=" in stdout
    assert "…" in stdout, "--limit 3 should truncate the group"


def test_analyze_json(target, tmp_path):
    out = tmp_path / "plan.json"
    run("analyze", "-d", str(target["dump"]), "--no-dumper", "--json", str(out))
    payload = json.loads(out.read_text())
    assert payload["generator"] == "modkit"
    assert payload["features"] and all("kind" in f for f in payload["features"])


def test_build_writes_a_project_and_verifies(target, tmp_path):
    out = tmp_path / "project"
    stdout = run("build", "-d", str(target["dump"]), "-m", str(target["metadata"]),
                 "-s", str(target["so"]), "--no-dumper", "--out", str(out),
                 "--package", "com.neondrift.game", "--app", "neondrift", "--verify").stdout
    assert "features" in stdout and "verify" in stdout
    assert "ok:" in stdout, stdout
    assert (out / "app/src/main/cpp/game.cpp").exists()
    assert (out / "app/src/main/modkit/patch_plan.json").exists()


def test_build_refuses_a_dirty_out_dir(target, tmp_path):
    out = tmp_path / "project"
    run("build", "-d", str(target["dump"]), "--no-dumper", "--out", str(out))
    res = run("build", "-d", str(target["dump"]), "--no-dumper", "--out", str(out), expect=1)
    assert "not empty" in res.stderr
    run("build", "-d", str(target["dump"]), "--no-dumper", "--out", str(out), "--force")


def test_build_from_metadata_only_names_targets_without_addresses(target, tmp_path):
    """No dump.cs and no dumper: the plan is empty, but the run must explain why."""
    res = run("build", "-m", str(target["metadata"]), "-s", str(target["so"]), "--no-dumper",
              "--out", str(tmp_path / "names"), expect=0)
    assert "no features matched" in res.stderr or "names-only" in res.stdout


def test_apply_bakes_the_patches_into_a_copy(target, tmp_path):
    plan = tmp_path / "patch_plan.json"
    out = tmp_path / "project"
    run("build", "-d", str(target["dump"]), "--no-dumper", "--out", str(out))
    plan.write_text((out / "app/src/main/modkit/patch_plan.json").read_text())
    so_copy = tmp_path / "libil2cpp.so"
    so_copy.write_bytes(target["so"].read_bytes())
    run("apply", "--so", str(so_copy), "--plan", str(plan), "--out", str(tmp_path / "patched.so"))
    patched = (tmp_path / "patched.so").read_bytes()
    assert patched != so_copy.read_bytes()
    # 0x1210 is Weapon.get_Ammo -> "mov w0, #999; ret"
    from modkit.arch import arm64
    expected = None
    plan_payload = json.loads(plan.read_text())
    for item in plan_payload["patches"]:
        if item["rva"] == "0x1210":
            expected = bytes.fromhex(item["bytes"])
    assert expected, "Weapon.get_Ammo must be in the patch plan"
    assert patched[0x1210:0x1210 + len(expected)] == expected
    assert expected == arm64.const_return(999, width=4)


def test_rules_lint_and_init(tmp_path):
    good = tmp_path / "rules.json"
    good.write_text(json.dumps({"groups": [{"id": "x", "label": "X", "class": "(a|b)",
                                            "member": "^(c|d)$"}]}))
    assert "ok" in run("rules", "-r", str(good)).stdout
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"groups": [{"id": "x", "label": "X", "class": "(a|b", "member": "c"}]}))
    res = run("rules", "-r", str(bad), expect=1)
    assert "bad regex" in res.stdout
    init = tmp_path / "init.json"
    run("rules", "--init", str(init))
    assert json.loads(init.read_text())["groups"]


def test_selftest_passes(tmp_path):
    out = run("selftest", "--keep", str(tmp_path / "st"), "--no-compile").stdout
    assert "selftest ok" in out
    assert (tmp_path / "st" / "module" / "app" / "src" / "main" / "cpp" / "game.cpp").exists()


@pytest.mark.skipif(not __import__("shutil").which("g++"), reason="needs a host g++")
def test_selftest_with_compile_check(tmp_path):
    out = run("selftest", "--keep", str(tmp_path / "stc"), timeout=600).stdout
    assert "selftest ok" in out
    assert "game.cpp imgui=1" in out


def test_dump_without_dumper_explains_the_fallback(tmp_path):
    from modkit.selftest import fixtures
    d = tmp_path
    fixtures.write_all(d)
    env_off = run("dump", "-m", str(d / "global-metadata.dat"), "-s", str(d / "libil2cpp.so"),
                  "--out", str(d / "d"), expect=2)
    assert "Il2CppDumper" in env_off.stderr or "not found" in env_off.stderr


@pytest.mark.skipif(not __import__("shutil").which("g++"), reason="needs a host g++")
def test_no_overlay_build_still_compiles(target, tmp_path):
    """--no-overlay drops overlay.hpp, so every other include must be self-sufficient."""
    out = tmp_path / "proj"
    run("build", "--dump", str(target["dump"]), "--so", str(target["so"]),
        "--metadata", str(target["metadata"]), "--out", str(out), "--app", "neondrift",
        "--no-overlay", "--force", timeout=600)
    cpp = out / "app/src/main/cpp"
    stubs = ROOT / "tests" / "stubs"
    defs = ["-DMODKIT_OVERLAY=0", '-DMODKIT_TARGET_SO="libil2cpp.so"',
            "-DMODKIT_HAVE_DOBBY=0", '-DMODKIT_TAG="neondrift"']
    assert "--no-overlay" in (cpp / "CMakeLists.txt").read_text() or "MODKIT_OVERLAY" in (cpp / "CMakeLists.txt").read_text()
    for unit in ("modkit.cpp", "game.cpp", "jni_main.cpp"):
        for imgui in (0, 1):
            proc = subprocess.run(
                ["g++", "-std=c++20", "-fsyntax-only", "-Wall", "-D_GNU_SOURCE",
                 f"-I{cpp}", f"-I{stubs}", *defs, f"-DMODKIT_HAS_IMGUI={imgui}", str(cpp / unit)],
                capture_output=True, text=True)
            assert proc.returncode == 0, f"{unit} imgui={imgui}\n{proc.stderr}"
