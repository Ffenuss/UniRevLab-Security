#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"

ENUM_LINE = '    DIAGNOSTICS("Diagnostics / Self-Test", "Analyzer consistency, indexes, graph and coverage checks", "TEST"),'
ROUTE_LINE = '                ProductTool.DIAGNOSTICS -> DiagnosticsPanel(report)'


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    if ENUM_LINE not in text:
        anchor = '    PROTECTION("Protection Matrix", "Root, emulator, debug, hook, signature, integrity", "SHIELD"),'
        if anchor not in text:
            raise RuntimeError("diagnostics enum anchor not found")
        text = text.replace(anchor, anchor + "\n" + ENUM_LINE, 1)

    if ROUTE_LINE not in text:
        anchor = "                ProductTool.PROTECTION -> ProtectionMatrixPanel(report)"
        if anchor not in text:
            raise RuntimeError("diagnostics route anchor not found")
        text = text.replace(anchor, anchor + "\n" + ROUTE_LINE, 1)

    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.26.8 diagnostics UI applied")
    else:
        print("v0.26.8 diagnostics UI already present")


if __name__ == "__main__":
    main()
