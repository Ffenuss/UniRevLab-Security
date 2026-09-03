#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one occurrence of {old!r}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    ROOT / "app/build.gradle.kts",
    'versionCode = 47\n        versionName = "0.36.0-preview-il2cpp-evidence-explorer"',
    'versionCode = 48\n        versionName = "0.36.1-preview-il2cpp-large-files"',
)

replace_once(
    ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt",
    'private const val MAX_METADATA_BYTES = 64L * 1024L * 1024L\nprivate const val MAX_LIBRARY_BYTES = 128L * 1024L * 1024L',
    'private const val MAX_METADATA_BYTES = 128L * 1024L * 1024L\nprivate const val MAX_LIBRARY_BYTES = 2L * 1024L * 1024L * 1024L',
)

replace_once(
    ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppScanner.kt",
    'val maxMetadataBytes: Long = 64L * 1024L * 1024L,',
    'val maxMetadataBytes: Long = 128L * 1024L * 1024L,',
)

replace_once(
    ROOT / "app/src/main/java/org/unirevlab/security/analysis/ElfNativeScanner.kt",
    'val maxElfBytes: Long = 128L * 1024L * 1024L,',
    'val maxElfBytes: Long = 2L * 1024L * 1024L * 1024L,',
)

print("v0.36.1 large IL2CPP file limits applied")
