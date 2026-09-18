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


def test_workspace_editor_mode_switch_preserves_current_bytes_and_unsaved_edits():
    src = read("FileWorkspaceActivity.java")
    assert 'private String renderedEditorText="";' in src
    assert 'modeButton=button("Режим: AUTO",root,v->switchMode())' in src

    render = src.split("private void render()", 1)[1].split("private byte[] editedBytes()", 1)[0]
    assert "renderedEditorText=hexMode?toHex(original):new String(original,StandardCharsets.UTF_8)" in render
    assert "editor.setText(renderedEditorText)" in render
    assert "suppressEditorChange=true" in render
    assert "suppressEditorChange=false" in render

    edited = src.split("private byte[] editedBytes()", 1)[1].split("private void switchMode()", 1)[0]
    assert "if(s.equals(renderedEditorText))return original" in edited

    switch = src.split("private void switchMode()", 1)[1].split("private void saveWorking()", 1)[0]
    assert "byte[] current=editedBytes()" in switch
    assert "original=current" in switch
    assert "hexMode=!hexMode" in switch
    assert "render()" in switch


def test_workspace_invalidates_prepared_patch_when_source_or_editor_changes():
    src = read("FileWorkspaceActivity.java")
    assert "workspace-patch-stale" in src
    assert "preparedPatchStale=false" in src
    assert "patchIsStale()" in src
    assert 'afterTextChanged(android.text.Editable e){if(!suppressEditorChange)invalidatePreparedPatch("Текущие правки изменились после подготовки Patch Pack.")' in src

    opened = src.split("private void setOpened", 1)[1].split("private void openUri", 1)[0]
    assert 'invalidatePreparedPatch("Открыт новый файл или APK entry.")' in opened

    buttons = src.split("private void updateButtons()", 1)[1].split("private boolean specialRouteSupported", 1)[0]
    assert 'app.file("workspace-source.json").isFile()' in buttons
    assert "!patchIsStale()" in buttons

    prepare = src.split("private void preparePatch()", 1)[1].split("private void buildPatched", 1)[0]
    assert 'beginPatchTransaction("Patch Pack пересобирается из текущих правок.")' in prepare
    assert "finishPatchTransaction()" in prepare

    build = src.split("private void buildPatched()", 1)[1].split("private boolean isInstalledSet", 1)[0]
    assert "if(patchIsStale())" in build
    start = src.split("private void startBuild(Uri uri)", 1)[1].split("private boolean startWork", 1)[0]
    assert "if(patchIsStale())" in start


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


def test_workspace_guard_rejects_stale_marker_before_and_after_artifact_verification():
    guard = read("WorkspaceBuildGuardService.java")
    assert 'app.file("workspace-patch-stale").isFile()' in guard
    first = guard.index("requirePreparedPatchFresh();JSONObject binding")
    verify = guard.index("verifyPatchArtifact(patch,member.file,binding)", first)
    second = guard.index("requirePreparedPatchFresh();String source", verify)
    worker = guard.index('new Intent(this,WorkerService.class).putExtra("op","workspace_build")', second)
    assert first < verify < second < worker


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


def test_workspace_worker_reverifies_exact_guard_handoff_before_apply_and_export():
    guard = read("WorkspaceBuildGuardService.java")
    worker = read("WorkerService.java")

    for extra in (
        '"workspaceGuardTargetId"',
        '"workspaceGuardTargetFingerprint"',
        '"workspaceGuardTargetDigest"',
        '"workspaceGuardSplitIndex"',
        '"workspaceGuardSplitName"',
        '"workspaceGuardPatchSha256"',
    ):
        assert f"putExtra({extra}" in guard

    verify = worker.split("private TargetResolver.Member verifyWorkspaceHandoff", 1)[1].split("private void workspaceBuild", 1)[0]
    assert "TargetResolver.resolve(app)" in verify
    assert "TargetResolver.requireVerified(target,app.cancelled)" in verify
    assert '"workspaceGuardTargetDigest"' in verify
    assert '"workspaceGuardPatchSha256"' in verify
    assert "currentTargetDigest" in verify
    assert "found.index!=expectedIndex" in verify
    assert "!found.name.equals(expectedName)" in verify
    assert "sha256WorkspaceArtifact(pack,WORKSPACE_PATCH_MAX_BYTES)" in verify

    hasher = worker.split("private String sha256WorkspaceArtifact", 1)[1].split("private TargetResolver.Member verifyWorkspaceHandoff", 1)[0]
    assert "check();total+=n" in hasher
    assert "if(total>maxBytes)" in hasher

    build = worker.split("private void workspaceBuild(Intent request,Uri uri)", 1)[1].split("private long simpleStartedAt", 1)[0]
    first = build.index("verifyWorkspaceHandoff(request,src,pack)")
    apply = build.index('callAttr("patchpack_apply_unsigned"', first)
    second = build.index("verifyWorkspaceHandoff(request,src,pack)", first + 1)
    export = build.index("exportSignedTargetForSource", second)
    assert first < apply < second < export

    signed = worker.split("private void exportSignedTargetForSource", 1)[1].split("private void splitDiscovery", 1)[0]
    assert "guardedSource=verifyWorkspaceHandoff" in signed
    assert "ownerIndex!=guardedSource.index" in signed
    assert "guardedSource.name.equals" in signed
    assert signed.count("verifyWorkspaceHandoff(guardRequest,sourceApk") >= 3


def test_workspace_apkset_export_uses_canonical_members_and_emits_signed_manifest():
    worker = read("WorkerService.java")
    signed = worker.split("private void exportSignedTargetForSource", 1)[1].split("private void splitDiscovery", 1)[0]

    assert "TargetResolver.resolve(app)" in signed
    assert "TargetResolver.requireVerified(canonical,app.cancelled)" in signed
    assert "canonical.members.size()<2" in signed
    assert "for(int i=0;i<canonical.members.size();i++)" in signed
    assert "member.index==guardedSource.index" in signed
    assert "patchedCount!=1" in signed
    assert "signedFiles.size()!=canonical.members.size()" in signed

    # File Workspace must not fall back to the package-target-only verifier here:
    # prepared selection manifests are already canonical and are verified by TargetResolver.
    assert "verifyInstalledTarget()" not in signed

    # The exported .apks contains every canonical member plus a manifest which
    # fingerprints the exact signed APK bytes written into the archive.
    assert 'new ZipEntry(member.name)' in signed
    assert 'MessageDigest.getInstance("SHA-256")' in signed
    assert 'digest.update(buf,0,n);z.write(buf,0,n)' in signed
    assert '"modkit-workspace-export-target-1.0"' in signed
    assert '"sourceTargetDigest"' in signed
    assert '"patchedSplitIndex"' in signed
    assert '"signedSha256"' in signed
    assert '"certificateSha256"' in signed
    assert 'new ZipEntry("modkit-target.json")' in signed

    # Guard freshness is checked again both before publishing and after copying.
    assert signed.count("verifyWorkspaceHandoff(guardRequest,sourceApk") >= 3
