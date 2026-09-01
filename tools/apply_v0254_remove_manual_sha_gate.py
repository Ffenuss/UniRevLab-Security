#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one match in {path}: found {count}\n--- needle ---\n{old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


secret_panel = ROOT / "app/src/main/java/org/unirevlab/security/ui/SecretExposurePanel.kt"
automod_panel = ROOT / "app/src/main/java/org/unirevlab/security/ui/AutoModPanel.kt"
gradle = ROOT / "app/build.gradle.kts"

replace_once(
    secret_panel,
    '    var shaConfirmation by remember(workspace.artifactSha256) { mutableStateOf("") }\n',
    '',
)
replace_once(
    secret_panel,
    '    val confirmationSuffix = workspace.artifactSha256.takeLast(8).lowercase()\n',
    '',
)
replace_once(
    secret_panel,
    '''                            Text(\n                                "Полный reveal привязывается к SHA-256 этой цели. До подтверждения ниже отображаются только proof metadata и fingerprints.",\n                                style = MaterialTheme.typography.bodySmall,\n                            )\n''',
    '''                            Text(\n                                "После подтверждения полный просмотр доступен для текущей открытой цели. До подтверждения отображаются proof metadata и fingerprints.",\n                                style = MaterialTheme.typography.bodySmall,\n                            )\n''',
)
replace_once(
    secret_panel,
    '''                            OutlinedTextField(\n                                value = shaConfirmation,\n                                onValueChange = {\n                                    shaConfirmation = it.filter(Char::isLetterOrDigit).take(8).lowercase()\n                                    if (revealUnlocked && shaConfirmation != confirmationSuffix) {\n                                        revealUnlocked = false\n                                        revealed = emptyMap()\n                                    }\n                                },\n                                modifier = Modifier.fillMaxWidth(),\n                                singleLine = true,\n                                label = { Text("Последние 8 символов SHA-256 цели") },\n                                supportingText = { Text("Для этой цели: …$confirmationSuffix") },\n                            )\n''',
    '',
)
replace_once(
    secret_panel,
    '''                            Button(\n                                onClick = {\n                                    revealUnlocked = true\n                                    onStatus("Полный Secret Proof локально разблокирован для SHA …$confirmationSuffix")\n                                },\n                                enabled = authorizationChecked && shaConfirmation == confirmationSuffix && !busy && !running,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text(if (revealUnlocked) "✓ Полный просмотр разблокирован" else "Разблокировать полный просмотр") }\n''',
    '''                            Button(\n                                onClick = {\n                                    revealUnlocked = true\n                                    onStatus("Полный Secret Proof локально разблокирован для текущей цели")\n                                },\n                                enabled = authorizationChecked && !busy && !running,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text(if (revealUnlocked) "✓ Полный просмотр разблокирован" else "Разблокировать полный просмотр") }\n''',
)

replace_once(
    automod_panel,
    '''            Text(\n                "Привязка: SHA-256 ${workspace.artifactSha256}",\n                style = MaterialTheme.typography.bodySmall,\n            )\n''',
    '',
)

replace_once(
    gradle,
    '''        versionCode = 32\n        versionName = "0.25.3-dev-classifier-automod"\n''',
    '''        versionCode = 33\n        versionName = "0.25.4-dev-simplified-authorization"\n''',
)

# Guard against accidentally leaving the manual challenge in product UI.
secret_text = secret_panel.read_text(encoding="utf-8")
automod_text = automod_panel.read_text(encoding="utf-8")
for forbidden in (
    "shaConfirmation",
    "confirmationSuffix",
    "Последние 8 символов SHA-256 цели",
):
    if forbidden in secret_text:
        raise SystemExit(f"Manual SHA challenge still present: {forbidden}")
if "Привязка: SHA-256" in automod_text:
    raise SystemExit("Visible AutoMod SHA binding still present")

print("Applied v0.25.4 simplified authorization UI")
