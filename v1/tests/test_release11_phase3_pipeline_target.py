from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android" / "app" / "src" / "main" / "java" / "dev" / "modkit" / "mobile"


def read(name: str) -> str:
    return (JAVA / name).read_text(encoding="utf-8")


def test_full_analysis_verifies_target_before_inventory_and_binds_reconstruction():
    src = read("FullAnalysisService.java")
    verification = src.index("TargetResolver.requireVerified(target,app.cancelled)")
    inventory = src.index('stage(1,4,"Inventory')
    assert verification < inventory
    assert 'getString("currentTargetDigest")' in src
    assert 'put("targetId",target.targetId)' in src
    assert 'put("targetDigest",digest)' in src
    assert "targetDigest(List<File>" not in src


def test_automatic_evidence_uses_same_resolver_and_rechecks_at_finish():
    src = read("AutomaticEvidenceService.java")
    assert "TargetResolver.resolve(app)" in src
    assert "TargetResolver.requireVerified(target,app.cancelled)" in src
    assert "TargetResolver.prepareAnalysisContainer(target" in src
    assert 'put("targetDigest",targetVerification.optString("currentTargetDigest"))' in src
    assert "Canonical target изменился во время Evidence pipeline" in src
    assert "private File targetForReAnalysis" not in src


def test_target_resolver_never_falls_back_when_manifest_exists():
    src = read("TargetResolver.java")
    manifest_branch = src.split("if(manifest!=null){", 1)[1].split("}else{", 1)[0]
    assert "fallback на base.apk запрещён" in manifest_branch
    assert "Target split #" in manifest_branch
    assert "duplicate split index" in manifest_branch
    assert "expectedApkCount" in src


def test_complete_il2cpp_target_requires_patch_owner():
    src = read("TargetResolver.java")
    assert 'fullIl2cppPair=target.manifest.optBoolean("fullIl2cppPair",false)' in src
    assert "fullIl2cppPair&&patchOwnerIndex<0" in src


def test_target_resolver_rejects_malformed_manifest_identity_before_use():
    src = read("TargetResolver.java")
    resolve = src.split("static Target resolve(App app)", 1)[1].split("static JSONObject verify", 1)[0]

    assert '"modkit-target-selection-1.1".equals(schema)' in resolve
    assert '"modkit-package-target-1.1".equals(schema)' in resolve
    assert 'requireNonNegativeInt(manifest,"expectedApkCount")' in resolve
    assert 'requireNonNegativeInt(manifest,"copiedApkCount")' in resolve
    assert 'requireNonNegativeInt(row,"index")' in resolve
    assert 'requireSha256(row,"sha256")' in resolve
    assert 'validateMemberName(name)' in resolve
    assert 'canonical.startsWith(installedRoot)' in resolve
    assert '"COMPLETE".equals(manifest.optString("scanCompleteness",""))' in resolve
    assert 'copyErrors==null||copyErrors.length()!=0' in resolve
    assert 'manifestFingerprint(packageName,versionCode,splits)' in resolve
    assert 'actualFingerprint.substring(0,24).equals(targetId)' in resolve

    assert 'row.optInt("index",i)' not in resolve
    assert 'manifest.optInt("expectedApkCount"' not in resolve
