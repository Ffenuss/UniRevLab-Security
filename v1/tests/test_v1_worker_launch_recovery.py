from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def _read(name: str) -> str:
    return (ANDROID / name).read_text(encoding="utf-8")


def test_full_mode_recovers_global_busy_when_analysis_service_launch_fails():
    source = _read("FullModeActivity.java")
    start = source.index("app.busy.set(true)")
    launch = source.index("startForegroundService(new Intent(this,FullAnalysisService.class))", start)
    recovery = source.index("app.busy.set(false)", launch)
    assert start < launch < recovery
    assert "catch(Exception e)" in source[launch:recovery + 200]
    assert "app.revision++" in source[launch:recovery + 250]


def test_manual_worker_workspaces_recover_busy_on_launch_failure():
    for name in (
        "MenuBuilderActivity.java",
        "PatchPackActivity.java",
        "ReWorkspaceActivity.java",
        "NativeWorkspaceActivity.java",
        "FileWorkspaceActivity.java",
    ):
        source = _read(name)
        assert "app.busy.set(true)" in source, name
        assert "try{startForegroundService" in source, name
        assert "catch(Exception e){app.busy.set(false);app.revision++" in source, name


def test_worker_service_always_releases_global_busy_after_started_operation():
    source = _read("WorkerService.java")
    finally_block = source.split("} finally {", 1)[1].split("},\"modkit-work\")", 1)[0]
    assert "if (wake != null && wake.isHeld()) wake.release();" in finally_block
    assert 'putBoolean("running",false)' in finally_block
    assert "app.busy.set(false); app.revision++;" in finally_block
    assert "stopForeground(true); stopSelf();" in finally_block


def test_created_saf_outputs_are_removed_when_worker_cannot_start():
    menu = _read("MenuBuilderActivity.java")
    patch = _read("PatchPackActivity.java")
    native = _read("NativeWorkspaceActivity.java")
    workspace = _read("FileWorkspaceActivity.java")

    assert "createdOutputOp" in menu
    assert "DocumentsContract.deleteDocument" in menu
    for op in (
        "menu_export",
        "menu_payload_export",
        "menu_build_apk",
        "menu_auto_build_apk",
        "menu_auto_build_apk_deep",
        "menu_autopilot_build_apk",
        "menu_probe_build_apk",
        "menu_smart_build_apk",
    ):
        assert f'"{op}"' in menu

    assert '"patchpack_build".equals(op)' in patch
    assert "DocumentsContract.deleteDocument" in patch
    assert '"native_save_uri".equals(op)' in native
    assert "DocumentsContract.deleteDocument" in native
    assert 'buildOp="workspace_build".equals' in workspace
    assert "deleteCreatedDocument(output)" in workspace


def test_input_documents_are_not_classified_as_created_outputs():
    menu = _read("MenuBuilderActivity.java")
    patch = _read("PatchPackActivity.java")
    native = _read("NativeWorkspaceActivity.java")

    created_helper = menu.split("private boolean createdOutputOp", 1)[1].split("private void deleteCreatedDocument", 1)[0]
    assert "menu_runtime_import" not in created_helper
    assert 'if(!"patchpack_build".equals(op)' in patch
    assert 'if(!"native_save_uri".equals(op)' in native


def test_new_native_import_clears_all_old_derived_search_disasm_and_xref_evidence():
    source = _read("NativeWorkspaceActivity.java")
    helper = source.split("private void clearDerivedForImport()", 1)[1].split("private void deleteCreatedDocument", 1)[0]
    for name in ("native-search.json", "native-disasm.json", "native-xrefs.json"):
        assert f'"{name}"' in helper
    result = source.index("if(request==100)")
    clear = source.index("clearDerivedForImport();", result)
    launch = source.index('putExtra("op","native_import")', clear)
    assert result < clear < launch
