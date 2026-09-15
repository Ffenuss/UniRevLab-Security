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
    assert "verifyBinding(target,binding)" in guard
    assert 'binding.optString("targetId"' in guard
    assert 'binding.optString("targetFingerprint"' in guard
    assert 'binding.optInt("sourceSplitIndex"' in guard
    assert "member.file.getCanonicalPath().equals(canonical)" in guard
    assert 'putExtra("op","workspace_build")' in guard


def test_manifest_registers_workspace_guard():
    manifest = (ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert '.WorkspaceBuildGuardService' in manifest
