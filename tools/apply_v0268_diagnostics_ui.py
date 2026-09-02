#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text
    text = replace_once(
        text,
        '    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),\n',
        '    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),\n'
        '    DIAGNOSTICS("Diagnostics / Self-Test", "Analyzer consistency, indexes, graph and coverage checks", "TEST"),\n',
        "diagnostics enum",
    )
    text = replace_once(
        text,
        "                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)\n",
        "                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)\n"
        "                ProductTool.DIAGNOSTICS -> DiagnosticsPanel(report)\n",
        "diagnostics route",
    )
    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.26.8 diagnostics UI applied")
    else:
        print("v0.26.8 diagnostics UI already present")


if __name__ == "__main__":
    main()
