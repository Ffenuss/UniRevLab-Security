from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_exact_prepare_adapter_persists_fail_closed_audit():
    source = (ROOT / "modkit/mobile/menu_native_recovery.py").read_text(encoding="utf-8")
    assert 'SCHEMA = "modkit-menu-native-recovery-adapter-1.0"' in source
    assert 'audit_path=root / "menu-native-recovery.json"' in source
    assert '"normalBindingRequired": True' in source
    assert '"preflightRequired": True' in source
    assert '"addressRecoveryPromotesBuildability": False' in source
    assert '"promotesBuildability": False' in source
    assert 'audit["completed"] = True' in source
    assert 'audit["errorType"] = type(exc).__name__' in source
    assert '_write_audit(audit_path, audit)' in source
    assert 'finally:\n            engine.Elf.modules = original' in source
    assert '"moduleResolution": stats.get("modules")' in source


def test_automod_service_requires_completed_exact_prepare_audit_and_cleans_partial_state():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModPrepareService.java").read_text(encoding="utf-8")
    verifier = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java").read_text(encoding="utf-8")
    assert 'AutoModAuditVerifier.verifyCurrent' in source
    assert 'app.file("menu-native-recovery.json")' in verifier
    assert 'if(!audit.optBoolean("completed"))' in verifier
    assert 'if(!audit.optBoolean("normalBindingRequired")||!audit.optBoolean("preflightRequired"))' in verifier
    assert 'if(audit.optBoolean("promotesBuildability")||audit.optBoolean("addressRecoveryPromotesBuildability"))' in verifier
    assert '"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))' in verifier
    assert 'catch(Exception e){\n                String cleanup="";\n                try{invalidatePreparedState();}' in source
    assert '"menu-native-recovery.json"' in source


def test_automod_ui_build_gate_requires_exact_prepare_audit_plus_preflight():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    verifier = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java").read_text(encoding="utf-8")
    assert 'private boolean exactPrepareAuditReady()' in source
    assert 'AutoModAuditVerifier.structurallyReady' in source
    assert 'audit.optBoolean("completed")' in verifier
    assert 'audit.optBoolean("normalBindingRequired")' in verifier
    assert 'audit.optBoolean("preflightRequired")' in verifier
    assert 'audit.optBoolean("promotesBuildability")||audit.optBoolean("addressRecoveryPromotesBuildability")' in verifier
    assert 'if(!exactPrepareAuditReady())' in source
    assert 'preflightReady&&exactPrepareAuditReady()' in source
    assert '"menu-native-recovery.json"' in source


def test_exact_prepare_audit_is_target_scoped_and_visible_in_storage():
    reset = (ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")
    storage = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AnalysisStorageActivity.java").read_text(encoding="utf-8")
    assert '"menu-native-recovery.json"' in reset
    assert '"menu-native-recovery.json".equals(name)' in storage
    assert '"menu-native-recovery.json","menu-spec.json"' in storage
