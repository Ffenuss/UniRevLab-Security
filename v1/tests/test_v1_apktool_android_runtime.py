from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_apktool_seeds_desktop_jvm_properties_before_config_init():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/ApktoolEngine.java").read_text(encoding="utf-8")
    prepare = source.index("prepareApktoolJvmProperties(context);")
    config = source.index("Config config = new Config();")
    assert prepare < config
    assert 'setIfBlank("os.name", "Linux")' in source
    assert 'System.getProperty("sun.arch.data.model")' in source
    assert 'System.setProperty("sun.arch.data.model", has64 ? "64" : "32")' in source
    assert 'setIfBlank("user.home", context.getFilesDir().getAbsolutePath())' in source
    assert 'setIfBlank("java.io.tmpdir", context.getCacheDir().getAbsolutePath())' in source


def test_apktool_failure_report_keeps_exception_and_root_cause_classes():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/ApktoolEngine.java").read_text(encoding="utf-8")
    assert 'row.put("errorClass", error.getClass().getName())' in source
    assert 'row.put("rootCauseClass", root.getClass().getName())' in source
    assert 'row.put("rootCause",' in source
    assert '"modkit-apktool-analysis-1.1"' in source
