import os
from pathlib import Path

from modkit.mobile import menu_native_recovery


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def test_prepare_fingerprint_changes_on_same_size_same_mtime_mutation(tmp_path):
    target = tmp_path / "metadata.bin"
    target.write_bytes(b"A" * 4096)
    first = menu_native_recovery._fingerprint("metadata", target)
    stat = target.stat()

    target.write_bytes(b"B" * 4096)
    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    second = menu_native_recovery._fingerprint("metadata", target)

    assert first["role"] == second["role"] == "metadata"
    assert first["size"] == second["size"] == 4096
    assert first["sha256"] != second["sha256"]


def test_prepare_audit_binds_all_exact_inputs_and_never_uses_mtime():
    source = Path("modkit/mobile/menu_native_recovery.py").read_text(encoding="utf-8")

    assert '"freshnessPolicy": "EXACT_INPUT_SHA256"' in source
    assert '"inputFingerprints": input_fingerprints' in source
    for role in ("metadata", "library", "catalog", "sourceApk"):
        assert f'_fingerprint("{role}"' in source
    assert "engine.digest(file, cb)" in source
    assert "mtime" not in source.lower()


def test_java_verifier_rehashes_all_inputs_and_is_cancellable():
    source = (ANDROID / "AutoModAuditVerifier.java").read_text(encoding="utf-8")

    assert '"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))' in source
    for role in ("metadata", "library", "catalog", "sourceApk"):
        assert f'verify(rows,"{role}"' in source
    assert 'expectedSha.equalsIgnoreCase(actual)' in source
    assert 'Thread' not in source  # cancellation is injected by the caller, not global process state
    assert 'gate.isCancelled()' in source
    assert 'sha.matches("(?i)[0-9a-f]{64}")' in source


def test_prepare_service_independently_verifies_python_audit_before_ready_message():
    source = (ANDROID / "AutoModPrepareService.java").read_text(encoding="utf-8")

    prepare = source.index('callAttr("prepare_workspace"')
    verify = source.index("AutoModAuditVerifier.verifyCurrent", prepare)
    ready = source.index("exact SHA verified", verify)
    assert prepare < verify < ready
    assert '()->app.cancelled.get()' in source


def test_patch_lab_requires_sha_bound_audit_for_build_gate():
    source = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")

    assert 'AutoModAuditVerifier.structurallyReady(read("menu-native-recovery.json"))' in source
    assert "Exact SHA audit:" in source
    assert "не SHA-bound" in source
    assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady&&exactPrepareAuditReady())' in source


def test_automod_build_routes_through_final_sha_guard_only_for_automod_path():
    activity = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")
    guard = (ANDROID / "AutoModBuildGuardService.java").read_text(encoding="utf-8")
    manifest = Path("android/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")

    assert '"menu_build_apk".equals(op)?AutoModBuildGuardService.class:WorkerService.class' in activity
    assert '<service android:name=".AutoModBuildGuardService"' in manifest

    verify = guard.index("AutoModAuditVerifier.verifyCurrent")
    preflight = guard.index('read("menu-preflight.json")', verify)
    worker = guard.index('new Intent(this,WorkerService.class)', preflight)
    assert verify < preflight < worker
    assert 'preflight.optBoolean("readyForAutoBuild")' in guard
    assert '.putExtra("op","menu_build_apk")' in guard
    assert '()->app.cancelled.get()' in guard
