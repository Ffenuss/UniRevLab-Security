from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android" / "app" / "src" / "main" / "java" / "dev" / "modkit" / "mobile"


def text(name: str) -> str:
    return (JAVA / name).read_text(encoding="utf-8")


def test_target_resolver_verifies_current_member_bytes():
    src = text("TargetResolver.java")
    assert "static JSONObject verify(Target target" in src
    assert "sha256(member.file,cancelled)" in src
    assert '"sha256-mismatch"' in src
    assert "static JSONObject requireVerified" in src
    # Digest must bind actual bytes, not only trust the SHA stored in the manifest.
    digest_body = src.split("static String targetDigest", 1)[1]
    assert "new FileInputStream(member.file)" in digest_body


def test_native_workspace_can_open_library_from_any_target_split():
    activity = text("NativeWorkspaceActivity.java")
    locator = text("NativeTargetLocator.java")
    service = text("NativeTargetImportService.java")
    assert "Открыть .so из текущего APK / APK-set" in activity
    assert "NativeTargetLocator.list(target" in activity
    assert "TargetResolver.requireVerified(target" in activity
    assert "for(TargetResolver.Member member:target.members)" in locator
    assert 'low.endsWith(".so")' in locator
    assert "TargetResolver.requireVerified(target" in service
    assert 'put("targetDigest"' in service
    assert 'put("splitIndex"' in service
    assert 'put("entry"' in service


def test_automod_prepare_and_build_use_same_verified_target():
    prepare = text("AutoModPrepareService.java")
    guard = text("AutoModBuildGuardService.java")
    for src in (prepare, guard):
        assert "TargetResolver.resolve(app)" in src
        assert "TargetResolver.requireVerified(target" in src
        assert "target.patchOwnerApk()" in src
    assert "AutoModAuditVerifier.verifyCurrent(app,source" in prepare
    assert "AutoModAuditVerifier.verifyCurrent(app,source" in guard


def test_manifest_registers_native_target_import_service():
    manifest = (ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert '.NativeTargetImportService' in manifest
