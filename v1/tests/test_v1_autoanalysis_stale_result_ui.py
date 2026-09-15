from pathlib import Path


def test_rerun_labels_cached_catalog_as_previous_result():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java"
    ).read_text(encoding="utf-8")

    assert "Предыдущий сохранённый результат — текущий анализ ещё выполняется." in source
    assert 'String prefix=app.busy.get()?' in source
    assert 'mod.setEnabled(!app.busy.get()' in source


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
