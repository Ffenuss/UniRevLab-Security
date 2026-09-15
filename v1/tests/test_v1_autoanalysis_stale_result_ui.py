from pathlib import Path


def test_rerun_labels_cached_catalog_as_previous_result():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java"
    ).read_text(encoding="utf-8")

    assert "Предыдущий сохранённый результат — текущий анализ ещё выполняется." in source
    assert "Показан предыдущий сохранённый каталог — текущий прогон не сформировал новый каталог." in source
    assert 'app.file("simple-catalog.json").lastModified()' in source
    assert 'run.optLong("startedAtMs",0L)' in source


def test_automod_button_requires_current_terminal_success_or_partial_catalog_epoch():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java"
    ).read_text(encoding="utf-8")

    gate = source.split("private boolean autoModAllowedForRun", 1)[1].split("private void renderCatalog", 1)[0]
    assert 'if(run==null||!current)return false' in gate
    assert '"SUCCESS".equals(state)||"PARTIAL".equals(state)' in gate
    assert 'autoModAllowedForRun(run,current)' in source
    assert 'catalogFromCurrentRun(run)' in source


def test_final_pipeline_status_is_visible_on_main_analysis_screen():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java"
    ).read_text(encoding="utf-8")

    assert '"PARTIAL".equals(state)' in source
    assert '"FAILED".equals(state)' in source
    assert '"CANCELLED".equals(state)' in source
    assert '"RUNNING".equals(state)' in source
    assert 'run.optJSONArray("degradedReasons")' in source
    assert 'json("automatic-evidence.json")' in source
