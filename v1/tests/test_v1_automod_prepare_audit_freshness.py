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


def test_prepare_audit_binds_all_exact_inputs_and_generated_menu_spec():
    source = Path("modkit/mobile/menu_native_recovery.py").read_text(encoding="utf-8")

    assert '"freshnessPolicy": "EXACT_INPUT_SHA256"' in source
    assert '"inputFingerprints": input_fingerprints' in source
    assert '"outputFingerprints": []' in source
    for role in ("metadata", "library", "catalog", "sourceApk"):
        assert f'_fingerprint("{role}"' in source
    assert 'outputs = [_fingerprint("menuSpec", menu_json_path, cb)]' in source
    assert 'outputs.append(_fingerprint("menuPreflight", output_preflight, cb))' in source
    assert 'audit["outputFingerprints"] = outputs' in source
    assert "engine.digest(file, cb)" in source
    assert "mtime" not in source.lower()


def test_java_verifier_rehashes_all_inputs_and_menu_spec_and_is_cancellable():
    source = (ANDROID / "AutoModAuditVerifier.java").read_text(encoding="utf-8")

    assert '"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))' in source
    for role in ("metadata", "library", "catalog", "sourceApk"):
        assert f'verify(rows,"{role}"' in source
    assert 'verify(outputs,"menuSpec",app.file("menu-spec.json"),gate)' in source
    assert 'validFingerprint(fingerprint(outputs,"menuSpec"))' in source
    assert 'expectedSha.equalsIgnoreCase(actual)' in source
    assert 'gate.isCancelled()' in source
    assert 'sha.matches("(?i)[0-9a-f]{64}")' in source


def test_canonical_preflight_refresh_rebuilds_before_rebinding_sha():
    source = (ANDROID / "AutoModAuditVerifier.java").read_text(encoding="utf-8")
    py = Path("modkit/menu/callable_preflight.py").read_text(encoding="utf-8")

    stable = source.index("verifyStableInputs(app,sourceApk,audit,gate)")
    base = source.index('callAttr("menu_review_preflight"', stable)
    augment = source.index('callAttr("augment_preflight_json"', base)
    bind = source.index("bindPhase7Inputs(app,gate)", augment)
    verify = source.index("verifyCurrent(app,sourceApk,gate)", bind)
    assert stable < base < augment < bind < verify
    assert "augment_preflight_json" in py
    assert "return json.dumps(result, ensure_ascii=False)" in py


def test_prepare_service_independently_verifies_python_audit_before_ready_message():
    source = (ANDROID / "AutoModPrepareService.java").read_text(encoding="utf-8")

    prepare = source.index('callAttr("prepare_workspace"')
    bind = source.index("AutoModAuditVerifier.bindPhase7Inputs", prepare)
    verify = source.index("AutoModAuditVerifier.verifyCurrent", bind)
    journal = source.index('"AUTOMOD_PREPARE_READY"', verify)
    ready = source.index("Phase 7 plan/catalog SHA verified", journal)
    assert prepare < bind < verify < journal < ready
    assert '()->app.cancelled.get()' in source
    assert '"menu-native-recovery.json.tmp"' in source


def test_patch_lab_requires_sha_bound_audit_for_build_gate():
    source = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")

    assert 'AutoModAuditVerifier.structurallyReady(read("menu-native-recovery.json"))' in source
    assert "Phase 7 audit:" in source
    assert "не SHA-bound" in source
    assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady&&exactPrepareAuditReady())' in source


def test_patch_lab_plan_refresh_fails_closed_if_old_prepare_state_cannot_be_deleted():
    source = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")

    assert "private boolean invalidatePreparedState()" in source
    assert '"menu-native-recovery.json.tmp"' in source
    assert "if(file.exists()&&!file.delete())return false;" in source
    gate = source.index("if(!invalidatePreparedState())")
    planning = source.index("planning=true", gate)
    assert gate < planning
    assert "refresh заблокирован fail-closed" in source


def test_automod_build_routes_through_final_sha_guard_only_for_automod_path():
    activity = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")
    guard = (ANDROID / "AutoModBuildGuardService.java").read_text(encoding="utf-8")
    manifest = Path("android/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")

    assert 'boolean buildOp="menu_build_apk".equals(op);' in activity
    assert 'Class<?> service=buildOp?AutoModBuildGuardService.class:WorkerService.class;' in activity
    assert '<service android:name=".AutoModBuildGuardService"' in manifest

    refresh = guard.index("AutoModAuditVerifier.refreshCanonicalPreflight")
    verify = guard.index("AutoModAuditVerifier.verifyCurrent", refresh)
    ready = guard.index('preflight.optBoolean("readyForAutoBuild")', verify)
    worker = guard.index('new Intent(this,WorkerService.class)', ready)
    assert refresh < verify < ready < worker
    assert 'preflight.optBoolean("readyForModificationPayload")' in guard
    assert 'preflight.optBoolean("readyForProbePayload")' in guard
    assert 'preflight.optInt("parameterPolicyPending",0)' in guard
    assert '.putExtra("op","menu_build_apk")' in guard
    assert '()->app.cancelled.get()' in guard


def test_patch_lab_cleans_saf_destination_and_busy_state_when_build_service_does_not_start():
    activity = (ANDROID / "AutoModActivity.java").read_text(encoding="utf-8")

    assert "DocumentsContract.deleteDocument(getContentResolver(),uri)" in activity
    assert "if(!canStart()){if(buildOp)deleteCreatedDocument(uri);return false;}" in activity
    assert "catch(Exception e){app.busy.set(false);app.revision++;if(buildOp)deleteCreatedDocument(uri);" in activity
    assert "try{startForegroundService(new Intent(this,AutoModPrepareService.class));}" in activity
    assert "catch(Exception e){app.busy.set(false);app.revision++;" in activity


def test_blocked_prebuild_guard_removes_created_saf_destination():
    guard = (ANDROID / "AutoModBuildGuardService.java").read_text(encoding="utf-8")

    assert "Uri destination=null;" in guard
    assert "destination=Uri.parse(uriText);" in guard
    assert "if(destination!=null&&!handedOff)" in guard
    assert "DocumentsContract.deleteDocument(getContentResolver(),destination)" in guard
    handoff = guard.index("handedOff=true;")
    cleanup = guard.index("DocumentsContract.deleteDocument")
    assert handoff < cleanup
