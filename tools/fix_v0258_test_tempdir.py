from pathlib import Path

p = Path("app/src/test/java/org/unirevlab/security/analysis/NestedApkSetTest.kt")
s = p.read_text(encoding="utf-8")
replacements = {
    'val root = createTempDir(prefix = "apkset-test-")': 'val root = java.nio.file.Files.createTempDirectory("apkset-test-").toFile()',
    'val root = createTempDir(prefix = "apkset-plain-")': 'val root = java.nio.file.Files.createTempDirectory("apkset-plain-").toFile()',
}
for old, new in replacements.items():
    if old not in s:
        if new in s:
            continue
        raise SystemExit(f"missing NestedApkSetTest anchor: {old}")
    s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8")
print("v0.25.8 NestedApkSet temp-dir tests fixed")
