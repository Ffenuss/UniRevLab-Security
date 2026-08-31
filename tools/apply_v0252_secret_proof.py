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


build = ROOT / 'app/build.gradle.kts'
text = build.read_text(encoding='utf-8')
if 'versionName = "0.25.2-dev-secret-proof"' not in text:
    if 'versionName = "0.25.1-dev-target-quality"' not in text:
        raise SystemExit('v0.25.2 expects v0.25.1 source')
    text = text.replace('versionCode = 30', 'versionCode = 31', 1)
    text = text.replace('versionName = "0.25.1-dev-target-quality"', 'versionName = "0.25.2-dev-secret-proof"', 1)
    build.write_text(text, encoding='utf-8')

panel = 'app/src/main/java/org/unirevlab/security/ui/TamperAssessmentPanel.kt'
replace_once(
    panel,
    '"Ищет client-side trust/state/config, значения, файлы и redacted secret candidates. Авто-hooks только наблюдают выполнение и не генерируют обход лицензий/IAP.",',
    '"Ищет client-side trust/state/config, значения и файлы. Предварительные secret candidates можно перепроверить через Secret Exposure Proof; авто-hooks только наблюдают выполнение.",',
)
replace_once(
    panel,
    'Text("Ключи / секреты (только redacted)", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)',
    'Text("Предварительные ключи / секреты (redacted candidates)", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)',
)
replace_once(
    panel,
    '''                if (a.hookProposals.isNotEmpty()) {''',
    '''                SecretExposurePanel(
                    workspace = workspace,
                    busy = busy,
                    onStatus = onStatus,
                    onError = onError,
                )
                if (a.hookProposals.isNotEmpty()) {''',
)

print('v0.25.2 Secret Exposure Proof patch applied')
