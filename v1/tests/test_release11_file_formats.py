from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android" / "app" / "src" / "main" / "java" / "dev" / "modkit" / "mobile"


def read(name: str) -> str:
    return (JAVA / name).read_text(encoding="utf-8")


def test_detector_has_all_release11_text_formats():
    src = read("FileFormatDetector.java")
    for kind in ("JSON", "XML", "YAML", "TOML", "INI", "PROPERTIES"):
        assert kind in src.split("enum Kind", 1)[1].split("}", 1)[0]
    assert 'name.endsWith(".yaml")' in src
    assert 'name.endsWith(".yml")' in src
    assert 'name.endsWith(".toml")' in src
    assert 'name.endsWith(".ini")' in src
    assert 'name.endsWith(".properties")' in src


def test_binary_magic_precedes_text_heuristics():
    src = read("FileFormatDetector.java")
    dex = src.index("Kind.DEX")
    elf = src.index("Kind.ELF")
    unity = src.index("Kind.UNITY_BUNDLE")
    text = src.index("boolean text=looksText")
    assert dex < text
    assert elf < text
    assert unity < text


def test_structural_inspector_covers_special_binary_families():
    src = read("BinaryFormatInspector.java")
    for token in (
        "case DEX", "case ELF", "case IL2CPP_METADATA", "case SQLITE",
        "case PNG", "case WEBP", "case UNITY_BUNDLE", "case AXML", "case ARSC",
        "case APK_ZIP", "case ZIP", "case UNITY_ASSET", "case BINARY",
    ):
        assert token in src


def test_file_workspace_uses_magic_detector_before_render():
    src = read("FileWorkspaceActivity.java")
    assert "FileFormatDetector.detect(" in src
    assert "format.defaultHex" in src
    assert "BinaryFormatInspector.inspect(format" in src
