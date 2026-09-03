#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
root_build = (ROOT / "build.gradle.kts").read_text(encoding="utf-8")
workflow_dir = ROOT / ".github" / "workflows"
workflow_path = workflow_dir / "bootstrap-v022.yml"
if not workflow_path.is_file():
    candidates = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
    candidates = [p for p in candidates if "assembleDebug" in p.read_text(encoding="utf-8", errors="replace")]
    if len(candidates) != 1:
        raise SystemExit(f"Expected exactly one Android debug CI workflow, found {len(candidates)}")
    workflow_path = candidates[0]
workflow = workflow_path.read_text(encoding="utf-8")
elf_scanner = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/ElfNativeScanner.kt").read_text(encoding="utf-8")
il2cpp_scanner = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppScanner.kt").read_text(encoding="utf-8")
pair_workspace = (ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt").read_text(encoding="utf-8")
managed_dump = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppManagedDumpExporter.kt").read_text(encoding="utf-8")
resistance = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppModdingResistanceEngine.kt").read_text(encoding="utf-8")
pair_engine = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppPairAssessmentEngine.kt").read_text(encoding="utf-8")

checks = [
    ("compileSdk 37.0", app, r"version\s*=\s*release\(37\)[\s\S]*minorApiLevel\s*=\s*0"),
    ("targetSdk 36", app, r"targetSdk\s*=\s*36"),
    ("v0.37.0 preview versionCode", app, r"versionCode\s*=\s*49"),
    ("v0.37.0 modding resistance versionName", app, r'versionName\s*=\s*"0\.37\.0-preview-modding-resistance"'),
    ("release signing input gate", app, r'tasks\.register\("verifyReleaseSigningInputs"\)'),
    ("AGP 9.3.0", root_build, r'id\("com\.android\.application"\) version "9\.3\.0"'),
    ("Kotlin Compose 2.3.21", root_build, r'id\("org\.jetbrains\.kotlin\.plugin\.compose"\) version "2\.3\.21"'),
    ("CI Android platform 37.0", workflow, r'platforms;android-37\.0'),
    ("CI build-tools 36.0.0", workflow, r'build-tools;36\.0\.0'),
    ("CI pinned NDK 28.2", workflow, r'ndk;28\.2\.13676358'),
    ("CI NDK env normalized", workflow, r'ANDROID_NDK_HOME:[^\n]*28\.2\.13676358[\s\S]*ANDROID_NDK_ROOT:[^\n]*28\.2\.13676358'),
    ("CI pinned cargo-ndk", workflow, r'cargo install cargo-ndk --version 4\.1\.2 --locked'),
    ("CI Rust four ABIs", workflow, r'cargo ndk[\s\S]*?-t arm64-v8a[\s\S]*?-t armeabi-v7a[\s\S]*?-t x86_64[\s\S]*?-t x86'),
    ("CI Rust working directory", workflow, r'working-directory:\s*native-core'),
    ("CI Gradle 9.5", workflow, r'gradle/actions/setup-gradle@v4[\s\S]*gradle-version:\s*[\'\"]9\.5\.0[\'\"]'),
    ("CI unit tests", workflow, r':app:testDebugUnitTest'),
    ("CI lint", workflow, r':app:lintDebug'),
    ("CI debug build", workflow, r':app:assembleDebug'),
    ("CI APK integrity verify", workflow, r'unzip -t .*APK'),
    ("CI APK SHA-256", workflow, r'sha256sum .*UniRevLab-Security-v0\.37\.0-modding-resistance-preview-debug\.apk'),
    ("CI artifact upload", workflow, r'actions/upload-artifact@v4'),
    ("CI current v0.37 migration", workflow, r'python tools/apply_v0370_modding_resistance\.py'),
    ("CI current migration runs before Java", workflow, r'(?s)Apply v0\.37\.0 modding resistance integration.*Set up Java 17'),
    ("CI modding resistance engine persisted", workflow, r'Il2CppModdingResistanceEngine\.kt'),
    ("CI modding resistance tests persisted", workflow, r'Il2CppModdingResistanceEngineTest\.kt'),
    ("pair workspace libil2cpp limit 2 GiB", pair_workspace, r'MAX_LIBRARY_BYTES\s*=\s*2L\s*\*\s*1024L\s*\*\s*1024L\s*\*\s*1024L'),
    ("ELF scanner max input 2 GiB", elf_scanner, r'maxElfBytes:\s*Long\s*=\s*2L\s*\*\s*1024L\s*\*\s*1024L\s*\*\s*1024L'),
    ("ELF ASCII scan remains bounded", elf_scanner, r'maxAsciiScanBytes:\s*Long\s*=\s*64L\s*\*\s*1024L\s*\*\s*1024L'),
    ("IL2CPP metadata max 128 MiB", il2cpp_scanner, r'maxMetadataBytes:\s*Long\s*=\s*128L\s*\*\s*1024L\s*\*\s*1024L'),
    ("C#-like managed dump v3", managed_dump, r'reconstructed managed dump v3'),
    ("managed dump parameter reconstruction", managed_dump, r'parameterStart'),
    ("modding resistance client authority", resistance, r'CLIENT_AUTHORITATIVE'),
    ("modding resistance server gate", resistance, r'SERVER_GATED'),
    ("pair assessment integrates resistance", pair_engine, r'val moddingResistance: Il2CppModdingResistanceEngine\.Result'),
    ("pair UI shows resistance", pair_workspace, r'Modding Resistance Assessment'),
]

failed = []
for name, text, pattern in checks:
    ok = bool(re.search(pattern, text))
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failed.append(name)

legacy_migrations = [
    "apply_v0300_",
    "apply_v0310_",
    "apply_v0320_",
    "apply_v0330_",
    "apply_v0340_il2cpp_semantic_mapping.py",
    "apply_v0350_il2cpp_native_evidence.py",
    "apply_v0360_il2cpp_evidence_explorer.py",
    "apply_v0361_large_il2cpp_files.py",
]
legacy_found = [marker for marker in legacy_migrations if marker in workflow]
legacy_ok = not legacy_found
print(f"{'PASS' if legacy_ok else 'FAIL'}: CI legacy migration replay disabled")
if not legacy_ok:
    failed.append("CI legacy migration replay disabled (found: " + ", ".join(legacy_found) + ")")

current_migration_count = workflow.count("python tools/apply_v0370_modding_resistance.py")
current_once = current_migration_count == 1
print(f"{'PASS' if current_once else 'FAIL'}: CI current migration applied exactly once")
if not current_once:
    failed.append(f"CI current migration applied exactly once (count={current_migration_count})")

if failed:
    raise SystemExit("Android build-config preflight failed: " + ", ".join(failed))
print(f"Android build-config preflight: PASS ({workflow_path.relative_to(ROOT)})")
