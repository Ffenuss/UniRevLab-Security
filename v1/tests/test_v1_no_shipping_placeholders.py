from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SHIPPING_ROOTS = (ROOT / "modkit", ROOT / "android/app/src/main")
SOURCE_SUFFIXES = {".py", ".java", ".kt", ".cpp", ".cc", ".c", ".h", ".hpp", ".xml", ".gradle"}

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

# `simple_*` filenames and WorkerService operation IDs are persisted compatibility contracts used by
# existing reports/caches. Their historical internal phrase may remain only in these implementation
# files; user-facing screens/resources must not expose it. App.java contains the one normalization
# boundary which converts the compatibility status to the current UI label.
INTERNAL_COMPAT_SIMPLE_MODE = {
    "modkit/mobile/simple_mode.py",
    "modkit/mobile/simple_cache.py",
    "modkit/mobile/security_scan.py",
    "android/app/src/main/java/dev/modkit/mobile/WorkerService.java",
    "android/app/src/main/java/dev/modkit/mobile/App.java",
}


def _shipping_files():
    for root in SHIPPING_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and "__pycache__" not in path.parts:
                yield path


def test_shipping_code_has_no_legacy_or_placeholder_markers():
    problems: list[str] = []
    for path in _shipping_files():
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        text = path.read_text(encoding="utf-8", errors="replace")
        for no, line in enumerate(text.splitlines(), 1):
            low = line.casefold()
            for marker in FORBIDDEN_LITERAL:
                if marker == "simple mode" and rel in INTERNAL_COMPAT_SIMPLE_MODE:
                    continue
                if marker in low:
                    problems.append(f"{rel}:{no}: forbidden {marker!r}: {line.strip()[:180]}")
            for pattern in FORBIDDEN_LINE_PATTERNS:
                if pattern.search(line):
                    problems.append(f"{rel}:{no}: unfinished implementation marker: {line.strip()[:180]}")
    assert not problems, "Shipping-code cleanup required:\n" + "\n".join(problems[:200])
