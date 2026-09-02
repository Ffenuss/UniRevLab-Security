#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"

CANONICAL_ENUM = '    DEOBFUSCATION("Deobfuscation", "Automatic score, analyst mapping and optional exact R8 mapping", "DEOB"),'
DEX_ENUM = '    DEX("DEX / Logic", "Methods, strings, xrefs, call graph and code index", "DEX"),'
CANONICAL_ROUTE = '                ProductTool.DEOBFUSCATION -> AutomaticDeobfuscationPanel(report)'
DEX_ROUTE = '                ProductTool.DEX -> DexToolPanel(report)'


def canonicalize_unique(lines: list[str], predicate, canonical: str, anchor: str, label: str) -> list[str]:
    cleaned = [line for line in lines if not predicate(line)]
    try:
        anchor_index = cleaned.index(anchor)
    except ValueError as exc:
        raise RuntimeError(f"{label}: anchor not found") from exc
    cleaned.insert(anchor_index + 1, canonical)
    if sum(1 for line in cleaned if line == canonical) != 1:
        raise RuntimeError(f"{label}: canonicalization did not produce exactly one entry")
    return cleaned


def main() -> None:
    original = UI.read_text(encoding="utf-8")
    had_final_newline = original.endswith("\n")
    lines = original.splitlines()

    lines = canonicalize_unique(
        lines,
        predicate=lambda line: line.startswith('    DEOBFUSCATION("Deobfuscation"'),
        canonical=CANONICAL_ENUM,
        anchor=DEX_ENUM,
        label="deobfuscation enum",
    )
    # Only normalize the UI routing branch. Do not strip ProductTool.DEOBFUSCATION
    # branches from helper when-expressions such as productToolMetric(). The old
    # strip()-based predicate matched both and could leave an orphaned block.
    lines = canonicalize_unique(
        lines,
        predicate=lambda line: line.startswith("                ProductTool.DEOBFUSCATION ->"),
        canonical=CANONICAL_ROUTE,
        anchor=DEX_ROUTE,
        label="deobfuscation route",
    )

    updated = "\n".join(lines) + ("\n" if had_final_newline else "")
    if updated != original:
        UI.write_text(updated, encoding="utf-8")
        print("v0.27.0 normalized DEOBFUSCATION enum/route to one canonical entry")
    else:
        print("v0.27.0 deobfuscation migration guard already canonical")


if __name__ == "__main__":
    main()
