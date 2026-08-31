#!/usr/bin/env python3
"""Small offline preflight for obvious committed credentials.

This intentionally complements, rather than replaces, provider-side secret scanning.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
SKIP_DIRS = {".git", ".gradle", ".idea", "build", "target", ".venv", "__pycache__", "test-corpus"}
MAX_BYTES = 2 * 1024 * 1024
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "openai-api-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
}


def is_intentional_detector_literal(relative: Path, line: str, kind: str) -> bool:
    """Allow only the PEM signatures used by the defensive scanner itself.

    This remains deliberately path- and syntax-specific so an actual credential elsewhere in the
    repository, or even elsewhere in the detector source, is still rejected by preflight.
    """
    if kind != "private-key":
        return False
    if relative.name not in {"TamperAssessmentEngine.kt", "TamperAssessmentEngine.kt.txt"}:
        return False
    return "text.contains(" in line and "PRIVATE KEY-----" in line


findings: list[tuple[str, int, str]] = []
for path in ROOT.rglob("*"):
    relative = path.relative_to(ROOT)
    if not path.is_file() or any(part in SKIP_DIRS for part in relative.parts):
        continue
    try:
        if path.stat().st_size > MAX_BYTES:
            continue
        text = path.read_text("utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line) and not is_intentional_detector_literal(relative, line, name):
                findings.append((str(relative), lineno, name))

if findings:
    for file, line, kind in findings:
        print(f"potential secret: {file}:{line}: {kind}")
    raise SystemExit(1)
print("secret preflight: no obvious credentials found")
