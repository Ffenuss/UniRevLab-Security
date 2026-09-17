from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android" / "app" / "src" / "main" / "java" / "dev" / "modkit" / "mobile"


def read(name: str) -> str:
    return (JAVA / name).read_text(encoding="utf-8")


def test_workspace_patch_records_target_and_split_identity():
    src = read("FileWorkspaceActivity.java")
    assert '"modkit-workspace-source-1.1"' in src
    for key in (
        '"targetId"',
        '"targetFingerprint"',
        '"targetDigest"',
        '"sourceSplitIndex"',
        '"sourceSplitName"',
        '"sourceSplitExpectedSha256"',
        '"targetEntry"',
        '"originalEntrySha256"',
        '"editedEntrySha256"',
    ):
        assert f"put({key}" in src
    assert "TargetResolver.requireVerified(target,app.cancelled)" in src
    assert "sourceMember(target)" in src


def test_workspace_source_entry_identity_survives_working_copy_saves():
    src = read("FileWorkspaceActivity.java")
    assert 'private String sourceEntrySha256="";' in src

    opened = src.split("private void setOpened", 1)[1].split("private void openUri", 1)[0]
    assert 'sourceEntrySha256=apk!=null&&entry!=null?sha256(data):""' in opened

    saved = src.split("private void saveWorking()", 1)[1].split("private void exportEdited", 1)[0]
    assert "original=b" in saved
    assert "sourceEntrySha256=" not in saved

    prepare = src.split("private void preparePatch()", 1)[1].split("private void buildPatched", 1)[0]
    assert 'if(sourceEntrySha256.isEmpty())throw new IOException' in prepare
    assert 'String originalSha=sourceEntrySha256,editedSha=sha256(b)' in prepare
    assert "sha256(original)" not in prepare


def test_workspace_build_goes_through_guard_not_direct_worker():
    src = read("FileWorkspaceActivity.java")
    start_build = src.split("private void startBuild(Uri uri)", 1)[1].split("private boolean startWork", 1)[0]
    assert "WorkspaceBuildGuardService.class" in start_build
    assert 'putExtra("uri",uri.toString())' in start_build
    assert 'putExtra("op","workspace_build")' not in start_build


def test_workspace_guard_rehashes_target_and_checks_source_membership():
    guard = read("WorkspaceBuildGuardService.java")
    assert "TargetResolver.resolve(app)" in guard
    assert "TargetResolver.requireVerified(target,app.cancelled)" in guard
    assert "verifyBinding(target,verification,binding)" in guard
    assert '"modkit-workspace-source-1.1".equals(binding.optString("schema"))' in guard
    assert 'binding.getString("targetId")' in guard
    assert 'binding.getString("targetFingerprint")' in guard
    assert 'requireSha(binding,"targetDigest")' in guard
    assert 'binding.getInt("sourceSplitIndex")' in guard
    assert "member.file.getCanonicalPath().equals(canonical)" in guard
    assert 'found.name.equals(expectedName)' in guard
    assert 'safe(found.sha256).equals(expectedMemberSha)' in guard
    assert 'putExtra("op","workspace_build")' in guard


def test_workspace_guard_binds_current_patch_zip_manifest_and_payload_sha():
    guard = read("WorkspaceBuildGuardService.java")

    target = guard.index("TargetResolver.requireVerified(target,app.cancelled)")
    binding = guard.index("verifyBinding(target,verification,binding)", target)
    patch = guard.index("verifyPatchArtifact(patch,member.file,binding)", binding)
    worker = guard.index('new Intent(this,WorkerService.class).putExtra("op","workspace_build")', patch)
    assert target < binding < patch < worker
    assert '"modkit-workspace-patch-1.1".equals(manifest.optString("schema"))' in guard
    assert '"files/edit.bin".equals(name)' in guard
    assert '"modkit-workspace.json".equals(name)' in guard
    assert 'rows.length()!=1' in guard
    assert 'verifyEmbeddedBinding(binding,embedded)' in guard
    assert 'sha256Stream(zip.getInputStream(edit),MAX_EDIT_BYTES)' in guard
    assert 'sha256ApkEntry(sourceApk,targetEntry)' in guard
    assert 'requireSha(binding,"originalEntrySha256")' in guard
    assert 'requireSha(binding,"editedEntrySha256")' in guard
    assert 'validateTargetEntry(binding.getString("targetEntry"))' in guard
    assert 'put("patchSha256",patchVerification.getString("patchSha256"))' in guard


def test_workspace_guard_rejects_missing_identity_fields_instead_of_weakening_checks():
    guard = read("WorkspaceBuildGuardService.java")
    required = guard.index('for(String key:new String[]{"targetId","targetFingerprint","targetDigest"')
    missing = guard.index('if(!binding.has(key)||binding.isNull(key))', required)
    compare_id = guard.index('if(!expectedId.equals(target.targetId))', missing)
    compare_fingerprint = guard.index('if(!expectedFingerprint.equals(target.fingerprint))', compare_id)
    compare_digest = guard.index('if(!expectedDigest.equalsIgnoreCase(verification.optString("currentTargetDigest","")))', compare_fingerprint)
    assert required < missing < compare_id < compare_fingerprint < compare_digest


def test_workspace_patch_zip_validation_is_bounded_and_cancellable():
    guard = read("WorkspaceBuildGuardService.java")
    assert "MAX_MANIFEST_BYTES=1024*1024" in guard
    assert "MAX_EDIT_BYTES=16L*1024L*1024L" in guard
    assert "if(total>maxBytes)throw new IOException" in guard
    assert "check();total+=n" in guard
    assert 'if(!names.add(name))throw new IOException("Workspace Patch Pack содержит duplicate ZIP entry: "+name)' in guard


def test_manifest_registers_workspace_guard():
    manifest = (ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert '.WorkspaceBuildGuardService' in manifest
