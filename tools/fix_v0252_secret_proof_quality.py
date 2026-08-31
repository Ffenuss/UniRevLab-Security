from pathlib import Path

ROOT = Path('.')


def replace_once(path: str, old: str, new: str):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if new in text:
        return
    if old not in text:
        raise SystemExit(f'patch state mismatch: {path}: anchor not found')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')


engine = 'app/src/main/java/org/unirevlab/security/analysis/SecretExposureEngine.kt'
replace_once(engine, 'import java.io.ByteArrayOutputStream\n', '')
replace_once(
    engine,
    '        val dedupeKey = "$entryName|$offset|$kind|$rawSha"',
    '        // Prefer the concrete detector that runs first; generic assignment detection must not\n        // duplicate the same bytes under a second kind.\n        val dedupeKey = "$entryName|$offset|$rawSha"',
)

panel = 'app/src/main/java/org/unirevlab/security/ui/SecretExposurePanel.kt'
replace_once(
    panel,
    '                                if (hit.editableTextEntry) {',
    '                                if (hit.editableTextEntry && revealUnlocked) {',
)

test = 'app/src/test/java/org/unirevlab/security/analysis/SecretExposureEngineTest.kt'
replace_once(
    test,
    '        assertTrue(report.hits.any { it.kind == "GOOGLE_API_KEY" && it.exposure == "PLAINTEXT_EXPOSED" })\n        val encoded = report.hits.first { it.kind == "CLIENT_SECRET" }',
    '        val google = report.hits.first { it.kind == "GOOGLE_API_KEY" && it.exposure == "PLAINTEXT_EXPOSED" }\n        assertEquals(1, report.hits.count { it.entryName == google.entryName && it.valueSha256 == google.valueSha256 })\n        val encoded = report.hits.first { it.kind == "CLIENT_SECRET" }',
)

print('v0.25.2 Secret Exposure Proof quality fix applied')
