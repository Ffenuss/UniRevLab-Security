from pathlib import Path
import re

from modkit.menu.runtime_config import VERSION, ENTRY, F_ABI_IL2CPP, F_INSTANCE, F_RESOLVER_RETURN_PTR


def test_android_runtime_cpp_matches_python_config_v4_contract():
    src = Path("android/app/src/main/cpp/modkit_runtime.cpp").read_text(encoding="utf-8")
    assert VERSION == 4
    assert ENTRY.size == 168
    assert "uint64_t resolver_rva;" in src
    assert 'static_assert(sizeof(ConfigEntry) == 168' in src
    assert "h->version != 2 && h->version != 3 && h->version != 4" in src
    assert "F_ABI_IL2CPP = 1u << 8" in src
    assert "F_INSTANCE = 1u << 9" in src
    assert "F_RESOLVER_RETURN_PTR = 1u << 10" in src
    assert "F_PROBE_READ_ONLY = 1u << 11" in src
    assert "process_vm_readv" in src and "il2cpp_class_from_name" in src
    assert "scan_heap_for_class" in src and "refresh_probe" in src
    assert "TAB_COUNT = 6" in src
    assert "g_menu_x" in src and "g_menu_y" in src
    assert "handle_touch" in src
    assert F_ABI_IL2CPP == 1 << 8
    assert F_INSTANCE == 1 << 9
    assert F_RESOLVER_RETURN_PTR == 1 << 10
    assert "bool (*)(void **, const void *)" in src
    assert "void *(*)(const void *)" in src
    assert "void (*)(void *, bool, const void *)" in src


def test_android_runtime_cpp_host_compiles_with_strict_warnings():
    import shutil
    import subprocess

    compiler = shutil.which("clang++") or shutil.which("g++")
    if not compiler:
        import pytest
        pytest.skip("no host C++ compiler available")
    proc = subprocess.run([
        compiler,
        "-std=c++17",
        "-D_GNU_SOURCE",
        "-Itests/stubs",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fsyntax-only",
        "android/app/src/main/cpp/modkit_runtime.cpp",
    ], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_runtime_cpp_preflights_target_and_instance_resolver_before_ready():
    src = Path("android/app/src/main/cpp/modkit_runtime.cpp").read_text(encoding="utf-8")
    assert "bool executable_rva(const Module &m, uint64_t rva" in src
    assert "m.base > UINTPTR_MAX - urva" in src
    runtime_main = src[src.index("void *runtime_main"):src.index("}  // namespace")]
    ready_pos = runtime_main.index("g_ready.store(true)")
    target_pos = runtime_main.index("!executable_rva(g_target, e.rva)")
    resolver_pos = runtime_main.index("!executable_rva(g_target, e.resolver_rva)")
    assert target_pos < ready_pos and resolver_pos < ready_pos
