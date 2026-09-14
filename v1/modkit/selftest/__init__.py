"""End-to-end self-check: synthetic target -> parse -> analyze -> generate -> verify.

Run it with `modkit selftest` (use `--no-compile` only to skip host type-checking of C++
with a host compiler). It is the same code path a real target goes through, so a green
selftest means the generator itself is healthy even without a device attached.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from modkit.selftest import fixtures


def build(tmp: Path) -> dict:
    """Full pipeline against the synthetic 'NeonDrift' target. Raises on inconsistency."""
    from modkit.analyze.features import analyze
    from modkit.analyze.rules import load as load_rules
    from modkit.codegen.project import BuildOptions, verify_plan, write_project
    from modkit.dumper.dumpcs import DumpParser
    from modkit.elf.reader import ElfFile
    from modkit.metadata.reader import MetadataFile

    inputs = fixtures.write_all(tmp)
    report: dict = {"inputs": {k: str(v) for k, v in inputs.items()}}

    meta = MetadataFile.open(inputs["metadata"])
    ident = meta.identify()
    assert ident["magic_ok"] and ident["version"] == 27, ident
    assert ident["typedefs"] == len(fixtures.neon_drift()), ident
    report["metadata"] = ident

    elf = ElfFile.open(inputs["so"])
    info = elf.info()
    assert info["arch"] == "aarch64" and info["pie"], info
    assert "liblog.so" in info["needed"], info
    report["elf"] = info

    prog = DumpParser().parse_file(inputs["dump"])
    assert prog.summary()["classes"] == len(fixtures.neon_drift()), prog.summary()
    report["dump"] = prog.summary()

    rules = load_rules(Path(__file__).resolve().parents[2] / "rules" / "default.json")
    plan = analyze(prog, rules)
    ids = {f.id for f in plan.features}
    assert plan.features, "the analyzer found nothing in a dump that clearly has gold/gems/ammo"
    for expected in ("economy.PlayerSave.gold", "economy.PlayerSave.gold.lock",
                    "infinite_ammo.Weapon.get_Ammo", "no_damage.PlayerController.TakeDamage"):
        assert any(expected in i for i in ids), f"missing {expected} in {sorted(ids)}"
    assert not any("UnityEngine" in f.cls or "System." in f.cls for f in plan.features), \
        "engine types leaked into the plan"
    report["features"] = [{"id": f.id, "kind": f.kind.value, "rva": f.rva, "conf": round(f.confidence, 2)}
                          for f in plan.features]
    report["instance_hooks"] = [f"{h.cls}.{h.method}" for h in plan.instance_hooks]

    out = tmp / "module"
    written = write_project(plan, out, BuildOptions(package="com.neondrift.game",
                                                     app_name="neondrift", force=True))
    report["files"] = sorted(str(p.relative_to(out)) for p in written)
    problems = verify_plan(plan, inputs["so"])
    hard = [p for p in problems if not p.startswith("ok:")]
    assert not hard, f"verify failed: {hard}"
    report["verify"] = problems

    # the feature table and the json plan must agree, byte for byte
    inc = (out / "app/src/main/cpp/features.inc").read_text()
    assert f"constexpr size_t kFeatureCount" in (out / "app/src/main/cpp/game.hpp").read_text()
    for f in plan.features:
        assert f'"{f.id}"' in inc, f"{f.id} missing from features.inc"
        if f.rva and f.kind.value != "field_write":
            assert f"0x{f.rva:x}" in inc
    plan_json = plan.to_json()
    assert str(len(plan.features)) in plan_json
    return report


def compile_check(tmp: Path, *, imgui: bool = True) -> list[str]:
    """`g++ -fsyntax-only` over the generated + runtime sources with host stubs."""
    src = tmp / "module" / "app/src/main/cpp"
    stubs = Path(__file__).resolve().parents[2] / "tests/stubs"
    if not shutil.which("g++"):
        return ["SKIPPED: no host g++"]
    if not (src / "game.cpp").exists():
        return [f"SKIPPED: {src} not built"]
    units = ["modkit.cpp", "game.cpp", "jni_main.cpp", "overlay.cpp"]
    ok: list[str] = []
    for unit in units:
        for with_imgui in ((False, True) if imgui else (False,)):
            defs = ["-DMODKIT_OVERLAY=1", '-DMODKIT_TARGET_SO="libil2cpp.so"',
                    "-DMODKIT_HAVE_DOBBY=0", "-DMODKIT_TAG=\"modkit\"",
                    f"-DMODKIT_HAS_IMGUI={1 if with_imgui else 0}"]
            cmd = (["g++", "-std=c++20", "-fsyntax-only", f"-I{src}", f"-I{stubs}", "-Wall",
                    "-Wno-unused-function", "-Wno-unused-variable"] + defs + [str(src / unit)])
            proc = subprocess.run(cmd, capture_output=True, text=True)
            tag = f"{unit} imgui={int(with_imgui)}"
            if proc.returncode != 0:
                raise AssertionError(f"{tag} failed:\n{proc.stdout}\n{proc.stderr}")
            ok.append(tag)
    return ok



def compile_builtin_runtime() -> list[str]:
    """Strict host compile of the exact Android generic runtime v2 source."""
    root = Path(__file__).resolve().parents[2]
    src = root / "android/app/src/main/cpp/modkit_runtime.cpp"
    stubs = root / "tests/stubs"
    compiler = shutil.which("clang++") or shutil.which("g++")
    if not compiler:
        return ["SKIPPED: no host C++ compiler"]
    proc = subprocess.run([
        compiler, "-std=c++17", "-D_GNU_SOURCE", f"-I{stubs}",
        "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(src),
    ], capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(f"built-in runtime v2 failed host compile:\n{proc.stdout}\n{proc.stderr}")
    return [f"builtin-runtime-v4 {Path(compiler).name} strict"]


def runtime_v2_check(tmp: Path) -> dict:
    """Round-trip the exact v2 ABI including instance resolver and numeric setter."""
    from modkit.elf.reader import ElfFile
    from modkit.menu import MenuControl, MenuSpec
    from modkit.menu.runtime_config import decode_runtime_config, encode_runtime_config, patch_runtime_blob

    spec = MenuSpec("Selftest Menu", controls=[
        MenuControl("cheat", "Cheat", "toggle", rva=0x1040, binding="bool_setter",
                    call_abi="il2cpp", is_static=False, resolver_rva=0x1044,
                    resolver_kind="out_ptr_bool", resolver_verified=True,
                    resolver_match="selftest-exact-type"),
        MenuControl("speed", "Speed", "slider_float", rva=0x1048, binding="number_setter",
                    min_value=0.5, max_value=3.0, default=1.0, call_abi="il2cpp"),
    ])
    cfg = encode_runtime_config(spec)
    decoded = decode_runtime_config(cfg)
    assert decoded["version"] == 4 and len(decoded["controls"]) == 2
    assert decoded["controls"][0]["resolverRva"] == 0x1044
    assert decoded["controls"][0]["isStatic"] is False
    patched, report = patch_runtime_blob(fixtures.runtime_so_blob(), cfg)
    sec = ElfFile(patched).section(".modkitcfg")
    assert sec is not None and report["location"] == ".modkitcfg"
    (tmp / "runtime-v2-configured.so").write_bytes(patched)
    return {
        "configVersion": decoded["version"],
        "controls": len(decoded["controls"]),
        "bytesUsed": decoded["bytesUsed"],
        "runtimeSha256": report["sha256"] if "sha256" in report else None,
    }

def run(dest: Path | None = None, *, compile: bool = True) -> dict:
    tmp = Path(dest) if dest else Path(tempfile.mkdtemp(prefix="modkit-selftest-"))
    tmp.mkdir(parents=True, exist_ok=True)
    report = build(tmp)
    report["runtimeV2"] = runtime_v2_check(tmp)
    if compile:
        try:
            report["compile"] = compile_check(tmp) + compile_builtin_runtime()
        except FileNotFoundError:
            report["compile"] = ["SKIPPED: host compiler unavailable"]
    report["ok"] = True
    return report
