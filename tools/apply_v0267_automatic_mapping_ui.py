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
        '    DEOBFUSCATION("Deobfuscation", "Obfuscation score, semantic aliases and R8 mapping", "DEOB"),\n',
        '    DEOBFUSCATION("Deobfuscation", "Automatic score, analyst mapping and optional exact R8 mapping", "DEOB"),\n',
        "deobfuscation subtitle",
    )
    text = replace_once(
        text,
        "                ProductTool.DEOBFUSCATION -> DeobfuscationToolPanel(report)\n",
        "                ProductTool.DEOBFUSCATION -> AutomaticDeobfuscationPanel(report)\n",
        "automatic deobfuscation route",
    )
    if text != original:
        UI.write_text(text, encoding="utf-8")
        print("v0.26.7 automatic analyst mapping UI applied")
    else:
        print("v0.26.7 automatic analyst mapping UI already present")


if __name__ == "__main__":
    main()
