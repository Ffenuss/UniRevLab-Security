from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source_text():
    return (ROOT / "android/app/src/main/java/dev/modkit/mobile/RootModuleAddressResolver.java").read_text(encoding="utf-8")


def test_module_rva_resolution_is_live_and_fail_closed():
    source = source_text()
    assert "modkit-instrumentation-address-1.0" in source
    assert '"cat /proc/" + pid + "/maps"' in source
    assert "maps.truncated" in source
    assert "module selector is ambiguous across mapped paths" in source
    assert "module load bias is ambiguous across mappings" in source
    assert "RVA address overflow" in source
    assert "resolved RVA is outside the selected module mappings" in source
    assert "resolved module mapping is not writable" in source
    assert "module mapping changed during RVA resolution" in source


def test_resolved_address_is_revalidated_before_read_or_write():
    source = source_text()
    assert '"freshnessPolicy", "RE_RESOLVE_EXACT_MODULE_BEFORE_ACCESS"' in source
    assert "ResolvedAddress fresh = revalidate(resolved, false)" in source
    assert "ResolvedAddress fresh = revalidate(resolved, true)" in source
    assert "fresh.loadBias != previous.loadBias" in source
    assert "fresh.address != previous.address" in source
    assert "RootMemoryInstrumentation.read(fresh.lease, fresh.address, fresh.length)" in source
    assert "RootMemoryInstrumentation.guardedWrite(fresh.lease, fresh.address, expectedOriginal, replacement)" in source


def test_module_selector_never_becomes_shell_input():
    source = source_text()
    assert "normalizeSelector(moduleSelector)" in source
    assert "basename(normalizedPath).equals(selector)" in source
    assert "RootAccess.runSu(moduleSelector" not in source
    assert "RootAccess.runSu(selector" not in source
