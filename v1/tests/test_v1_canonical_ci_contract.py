from pathlib import Path


def test_canonical_ci_runs_full_validation_before_artifact_upload():
    workflow = Path("../.github/workflows/modkit-v1-ci.yml").read_text(encoding="utf-8")

    required = (
        "python -m pytest tests -q",
        "python -m modkit selftest",
        "python -m modkit runtime-check",
        ":app:testDebugUnitTest",
        ":app:compileDebugJavaWithJavac",
        ":app:lintDebug",
        ":app:assembleDebug",
        "zipalign",
        "apksigner",
        "sha256sum",
        "actions/upload-artifact@v4",
        "if-no-files-found: error",
    )
    for token in required:
        assert token in workflow

    assemble = workflow.index(":app:assembleDebug")
    verify = workflow.index("Verify APK container, alignment, signature and release hygiene")
    upload = workflow.index("Upload validated APK artifact")
    assert assemble < verify < upload


def test_canonical_ci_stays_scoped_to_modkit1_and_v1():
    workflow = Path("../.github/workflows/modkit-v1-ci.yml").read_text(encoding="utf-8")

    assert "branches: [ Modkit1 ]" in workflow
    assert "working-directory: v1" in workflow
    assert "working-directory: v1/android" in workflow
    assert "id: release_meta" in workflow
    assert "versionName" in workflow
    assert "name: ${{ steps.release_meta.outputs.artifact }}" in workflow
    assert "ModKit-Android-1.1.0-dev1-debug" not in workflow
