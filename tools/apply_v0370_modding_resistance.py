#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
app_path = ROOT / "app" / "build.gradle.kts"
app = app_path.read_text(encoding="utf-8")
app = re.sub(r"versionCode\s*=\s*\d+", "versionCode = 49", app, count=1)
app = re.sub(
    r'versionName\s*=\s*"[^"]+"',
    'versionName = "0.37.0-preview-modding-resistance"',
    app,
    count=1,
)
app_path.write_text(app, encoding="utf-8")

required = {
    "app/src/main/java/org/unirevlab/security/analysis/Il2CppManagedDumpExporter.kt": [
        "reconstructed managed dump v3",
        "TypeRef#",
        "analyst-alias",
    ],
    "app/src/main/java/org/unirevlab/security/analysis/Il2CppModdingResistanceEngine.kt": [
        "CLIENT_AUTHORITATIVE",
        "SERVER_GATED",
        "hardeningActions",
    ],
    "app/src/main/java/org/unirevlab/security/analysis/Il2CppPairAssessmentEngine.kt": [
        "moddingResistance",
        "Il2CppManagedDumpExporter.export(report, metadataFile)",
    ],
    "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt": [
        "Modding Resistance Assessment",
        "Сохранить C#-подобный dump",
    ],
    "app/src/test/java/org/unirevlab/security/analysis/Il2CppModdingResistanceEngineTest.kt": [
        "localPremiumFieldWithoutValidationIsClientAuthoritative",
    ],
}
for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"v0.37 migration: missing required file {rel}")
    text = path.read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"v0.37 migration: {rel} missing markers: {missing}")

print("v0.37 modding-resistance migration: PASS")
