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

checks = [
    ("compileSdk 37.0", app, r"version\s*=\s*release\(37\)[\s\S]*minorApiLevel\s*=\s*0"),
    ("targetSdk 36", app, r"targetSdk\s*=\s*36"),
    ("v0.35.0 preview versionCode", app, r"versionCode\s*=\s*46"),
    ("v0.35.0 IL2CPP native evidence versionName", app, r'versionName\s*=\s*"0\.35\.0-preview-il2cpp-native-evidence"'),
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
    ("CI APK SHA-256", workflow, r'sha256sum .*UniRevLab-Security-v0\.35\.0-il2cpp-native-evidence-preview-debug\.apk'),
    ("CI artifact upload", workflow, r'actions/upload-artifact@v4'),
    ("CI current IL2CPP native evidence migration", workflow, r'python tools/apply_v0350_il2cpp_native_evidence\.py'),
    ("CI current migration runs before Java", workflow, r'(?s)Apply v0\.35\.0 IL2CPP native evidence integration.*Set up Java 17'),
    ("CI IL2CPP native evidence tests persisted", workflow, r'Il2CppNativeEvidenceEngineTest\.kt'),
    ("CI IL2CPP native evidence engine persisted", workflow, r'Il2CppNativeEvidenceEngine\.kt'),
    ("CI IL2CPP semantic tests persisted", workflow, r'Il2CppSemanticMappingEngineTest\.kt'),
    ("CI IL2CPP semantic engine persisted", workflow, r'Il2CppSemanticMappingEngine\.kt'),
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
]
legacy_found = [marker for marker in legacy_migrations if marker in workflow]
legacy_ok = not legacy_found
print(f"{'PASS' if legacy_ok else 'FAIL'}: CI legacy migration replay disabled")
if not legacy_ok:
    failed.append("CI legacy migration replay disabled (found: " + ", ".join(legacy_found) + ")")

current_migration_count = workflow.count("python tools/apply_v0350_il2cpp_native_evidence.py")
current_once = current_migration_count == 1
print(f"{'PASS' if current_once else 'FAIL'}: CI current migration applied exactly once")
if not current_once:
    failed.append(f"CI current migration applied exactly once (count={current_migration_count})")

if failed:
    raise SystemExit("Android build-config preflight failed: " + ", ".join(failed))
print(f"Android build-config preflight: PASS ({workflow_path.relative_to(ROOT)})")
