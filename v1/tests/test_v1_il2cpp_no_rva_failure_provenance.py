from pathlib import Path

from modkit.mobile.il2cpp_no_rva_native import _evidence, _unresolved_status


ROOT = Path(__file__).resolve().parents[1]


def test_pointer_blockers_have_explicit_fail_closed_statuses():
    assert _unresolved_status("MODULE_UNRESOLVED") == "NATIVE_RVA_MODULE_UNRESOLVED"
    assert _unresolved_status("TOKEN_OUT_OF_MODULE_RANGE") == "NATIVE_RVA_TOKEN_OUT_OF_MODULE_RANGE"
    assert _unresolved_status("NULL_METHOD_POINTER") == "NATIVE_RVA_POINTER_ABSENT"
    assert _unresolved_status("NON_EXECUTABLE_METHOD_POINTER") == "NATIVE_RVA_NON_EXECUTABLE_POINTER"


def test_unresolved_evidence_never_becomes_actionable_or_buildable():
    row = _evidence(
        17,
        0x06000012,
        "Assembly-CSharp.dll",
        "Game.Player",
        "SetHealth",
        "NATIVE_RVA_AMBIGUOUS_MODULE",
        ["multiple-codegenmodule-candidates-after-exact-method-count"],
        identityConfirmed=True,
    )
    assert row["rva"] is None
    assert row["addressConfirmed"] is False
    assert row["associationConfirmed"] is False
    assert row["uniqueExecutablePointer"] is False
    assert row["actionable"] is False
    assert row["buildable"] is False
    assert row["promotesBuildability"] is False
    assert row["blockers"]


def test_recovery_keeps_failures_out_of_compact_automod_rows_file():
    source = (ROOT / "modkit/mobile/il2cpp_no_rva_native.py").read_text(encoding="utf-8")
    assert 'failures_path = rows_path.with_name("il2cpp-no-rva-native.failures.jsonl")' in source
    assert 'sink = success_sink if success else failure_sink' in source
    assert '"failureRowsFile": failures_path.name' in source
    assert '"failuresAreFileBacked": True' in source
    for status in (
        "NATIVE_RVA_IDENTITY_UNAVAILABLE",
        "NATIVE_RVA_TOKEN_MISMATCH",
        "NATIVE_RVA_IDENTITY_CONFLICT",
        "NATIVE_RVA_NONCONTIGUOUS_TOKEN_DOMAIN",
        "NATIVE_RVA_AMBIGUOUS_MODULE",
        "NATIVE_RVA_MODULE_UNRESOLVED",
        "NATIVE_RVA_POINTER_ABSENT",
        "NATIVE_RVA_NON_EXECUTABLE_POINTER",
        "NATIVE_RVA_SHARED_EXECUTABLE_POINTER",
    ):
        assert status in source
