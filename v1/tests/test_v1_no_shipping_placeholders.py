from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIPPING_ROOTS = (ROOT / "modkit", ROOT / "android/app/src/main")
SOURCE_SUFFIXES = {".py", ".java", ".kt", ".cpp", ".cc", ".c", ".h", ".hpp", ".xml", ".gradle"}
FORBIDDEN = (
    "todo",
    "fixme",
    "placeholder",
    "notimplementederror",
    "dev40",
    "0.9.0-dev40",
    "для глупых",
    "simple mode",
)
# These words are checked as identifiers/labels, not arbitrary substrings such as
# JSON's "stubbed" user data. They must not describe shipped implementation paths.
FORBIDDEN_WORDS = ("stub", "mock")


def _shipping_files():
    for root in SHIPPING_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and "__pycache__" not in path.parts:
                yield path


def test_shipping_code_has_no_legacy_or_placeholder_markers():
    problems: list[str] = []
    for path in _shipping_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        low = text.casefold()
        for marker in FORBIDDEN:
            if marker in low:
                for no, line in enumerate(text.splitlines(), 1):
                    if marker in line.casefold():
                        problems.append(f"{path.relative_to(ROOT)}:{no}: forbidden {marker!r}: {line.strip()[:180]}")
        import re
        for word in FORBIDDEN_WORDS:
            rx = re.compile(rf"\b{word}\b", re.I)
            for no, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    problems.append(f"{path.relative_to(ROOT)}:{no}: forbidden {word!r}: {line.strip()[:180]}")
    assert not problems, "Shipping-code cleanup required:\n" + "\n".join(problems[:200])
