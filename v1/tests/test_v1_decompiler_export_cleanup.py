from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/DecompilerActivity.java")
FILE_WORKSPACE = Path("android/app/src/main/java/dev/modkit/mobile/FileWorkspaceActivity.java")


def test_decompiler_export_checks_cancel_during_copy_and_removes_failed_saf_output():
    source = SOURCE.read_text(encoding="utf-8")
    assert "DocumentsContract.deleteDocument" in source
    export = source.split("private void exportTo(Uri uri)", 1)[1].split("private void setControls", 1)[0]
    assert "cancelSearch.get()||Thread.currentThread().isInterrupted()" in export
    assert 'throw new InterruptedIOException("export cancelled")' in export
    catch = export.split("catch(Throwable t)", 1)[1]
    assert "deleteCreatedDocument(uri)" in catch


def test_file_workspace_direct_export_removes_failed_saf_output():
    source = FILE_WORKSPACE.read_text(encoding="utf-8")
    method = source.split("private void writeEdited(Uri uri)", 1)[1].split("private void preparePatch", 1)[0]
    assert "deleteCreatedDocument(uri)" in method
    assert "DocumentsContract.deleteDocument" in source
