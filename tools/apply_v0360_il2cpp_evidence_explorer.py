#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"
BUILD = ROOT / "app/build.gradle.kts"
MODEL = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppEvidenceExplorerModel.kt"
PANEL = ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppEvidenceExplorerPanel.kt"
TEST = ROOT / "app/src/test/java/org/unirevlab/security/analysis/Il2CppEvidenceExplorerModelTest.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_product() -> None:
    text = PRODUCT.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '    RUNTIME("Runtime / Game Engines", "IL2CPP, Unity Mono, Flutter, Hermes and Unreal", "RUN"),\n',
        '    RUNTIME("Runtime / Game Engines", "IL2CPP evidence explorer, Unity Mono, Flutter, Hermes and Unreal", "RUN"),\n',
        "runtime subtitle",
    )
    text = replace_once(
        text,
        '''        risk.candidates.take(40).forEach { candidate ->\n            InfoCard(\n                "${candidate.category} · ${candidate.kind} · ${candidate.confidence}\\n${candidate.managedIdentity}" +\n                    (candidate.nativeFunctionName?.let { "\\nNative correlation: $it" } ?: "") +\n                    (candidate.metadataToken?.let { "\\nmetadata token 0x${it.toString(16)}" } ?: ""),\n            )\n        }\n        risk.recommendations.take(5).forEach { InfoCard("Hardening: $it") }\n''',
        '''        risk.recommendations.take(5).forEach { InfoCard("Hardening: $it") }\n        Il2CppEvidenceExplorerPanel(report)\n''',
        "runtime evidence explorer panel",
    )
    text = replace_once(
        text,
        '        ProductTool.RUNTIME -> "Profiles ${report.runtimes?.profiles?.size ?: 0} · IL2CPP ${report.il2cpp?.detected ?: false} →"\n',
        '        ProductTool.RUNTIME -> "IL2CPP ${report.il2cpp?.detected ?: false} · native links ${report.correlations?.il2cppMethods?.size ?: 0} · evidence explorer →"\n',
        "runtime dashboard metric",
    )
    PRODUCT.write_text(text, encoding="utf-8")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    if "versionCode = 47" not in text:
        text = text.replace("versionCode = 46", "versionCode = 47", 1)
    if 'versionName = "0.36.0-preview-il2cpp-evidence-explorer"' not in text:
        text = text.replace(
            'versionName = "0.35.0-preview-il2cpp-native-evidence"',
            'versionName = "0.36.0-preview-il2cpp-evidence-explorer"',
            1,
        )
    if "versionCode = 47" not in text or 'versionName = "0.36.0-preview-il2cpp-evidence-explorer"' not in text:
        raise RuntimeError("v0.36 version update failed")
    BUILD.write_text(text, encoding="utf-8")


def verify_sources() -> None:
    missing = [path for path in (MODEL, PANEL, TEST) if not path.is_file()]
    if missing:
        raise RuntimeError("Missing v0.36 source files: " + ", ".join(str(path.relative_to(ROOT)) for path in missing))
    model = MODEL.read_text(encoding="utf-8")
    panel = PANEL.read_text(encoding="utf-8")
    test = TEST.read_text(encoding="utf-8")
    if "object Il2CppEvidenceExplorerModel" not in model:
        raise RuntimeError("Evidence explorer model declaration missing")
    if "fun Il2CppEvidenceExplorerPanel" not in panel:
        raise RuntimeError("Evidence explorer panel declaration missing")
    if "class Il2CppEvidenceExplorerModelTest" not in test:
        raise RuntimeError("Evidence explorer tests missing")


def main() -> None:
    verify_sources()
    patch_product()
    patch_build()
    print("v0.36.0 IL2CPP Evidence Explorer integration applied")


if __name__ == "__main__":
    main()
