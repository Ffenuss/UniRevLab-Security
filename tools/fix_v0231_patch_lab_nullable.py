#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
path = ROOT / "app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt"
text = path.read_text(encoding="utf-8")
replacements = {
    "if (selectedReplacementEntry !in ws.archiveEntries) {": "if (selectedReplacementEntry?.let { it in ws.archiveEntries } != true) {",
    "enabled = selectedReplacementEntry in ws.archiveEntries && !busy,": "enabled = selectedReplacementEntry?.let { it in ws.archiveEntries } == true && !busy,",
}
changed = False
for old, new in replacements.items():
    if new in text:
        continue
    if old not in text:
        raise SystemExit(f"missing PatchLabScreen marker: {old}")
    text = text.replace(old, new, 1)
    changed = True
if changed:
    path.write_text(text, encoding="utf-8")
    print("patched nullable replacement-entry checks")
else:
    print("nullable replacement-entry checks already patched")
