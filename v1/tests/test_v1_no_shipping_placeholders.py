from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SHIPPING_ROOTS = (ROOT / "modkit", ROOT / "android/app/src/main")
SOURCE_SUFFIXES = {".py", ".java", ".kt", ".cpp", ".cc", ".c", ".h", ".hpp", ".xml", ".gradle"}

# Legacy UI names and explicit unfinished-implementation markers must never ship.
# Do not ban generic RE/codegen terminology such as an ARM64 "stub" or a template
# "placeholder": those words describe real implemented mechanisms in this project.
FORBIDDEN_LITERAL = (
    "notimplementederror",
    "dev40",
    "0.9.0-dev40",
    "для глупых",
    "simple mode",
    "coming soon",
    "not implemented",
    "dummy implementation",
    "mock implementation",
    "placeholder implementation",
    "temporary placeholder",
)
FORBIDDEN_LINE_PATTERNS = (
    re.compile(r"\bTODO\b", re.I),
    re.compile(r"\bFIXME\b", re.I),
    re.compile(r"throw\s+new\s+UnsupportedOperationException\s*\(\s*[\"'](?:TODO|not implemented)", re.I),
    re.compile(r"raise\s+NotImplementedError\b", re.I),
)


def _shipping_files():
    for root in SHIPPING_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and "__pycache__" not in path.parts:
                yield path


def test_shipping_code_has_no_legacy_or_placeholder_markers():
    problems: list[str] = []
    for path in _shipping_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for no, line in enumerate(text.splitlines(), 1):
            low = line.casefold()
            for marker in FORBIDDEN_LITERAL:
                if marker in low:
                    problems.append(f"{path.relative_to(ROOT)}:{no}: forbidden {marker!r}: {line.strip()[:180]}")
            for pattern in FORBIDDEN_LINE_PATTERNS:
                if pattern.search(line):
                    problems.append(f"{path.relative_to(ROOT)}:{no}: unfinished implementation marker: {line.strip()[:180]}")
    assert not problems, "Shipping-code cleanup required:\n" + "\n".join(problems[:200])
