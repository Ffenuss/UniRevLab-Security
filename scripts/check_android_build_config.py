#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
root_build = (ROOT / "build.gradle.kts").read_text(encoding="utf-8")
workflow_dir = ROOT / ".github" / "workflows"
workflow_path = workflow_dir / "v038-auto-audit.yml"
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
audit_worker = (ROOT / "app/src/main/java/org/unirevlab/security/work/AuditWorker.kt").read_text(encoding="utf-8")
inspector = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt").read_text(encoding="utf-8")
readable_offsets = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/OffsetReadableExporter.kt").read_text(encoding="utf-8")
offset_evidence = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/OffsetEvidenceExporter.kt").read_text(encoding="utf-8")
modification_surfaces = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/ModificationSurfaceClassifier.kt").read_text(encoding="utf-8")
il2cpp_merger = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppSummaryMerger.kt").read_text(encoding="utf-8")
gradle_evidence = (ROOT / "app/src/main/java/org/unirevlab/security/analysis/GradleModuleEvidenceExporter.kt").read_text(encoding="utf-8")
gradle_evidence_test = (ROOT / "app/src/test/java/org/unirevlab/security/analysis/GradleModuleEvidenceExporterTest.kt").read_text(encoding="utf-8")
ai_chat = (ROOT / "app/src/main/java/org/unirevlab/security/ui/ReportChatScreen.kt").read_text(encoding="utf-8")
openrouter_client = (ROOT / "app/src/main/java/org/unirevlab/security/ai/OpenRouterClient.kt").read_text(encoding="utf-8")
openrouter_secret = (ROOT / "app/src/main/java/org/unirevlab/security/ai/OpenRouterSecretStore.kt").read_text(encoding="utf-8")
report_context = (ROOT / "app/src/main/java/org/unirevlab/security/ai/ReportContextEngine.kt").read_text(encoding="utf-8")
report_import = (ROOT / "app/src/main/java/org/unirevlab/security/ai/ReportImportStore.kt").read_text(encoding="utf-8")

checks = [
    ("compileSdk 37.0", app, r"version\s*=\s*release\(37\)[\s\S]*minorApiLevel\s*=\s*0"),
    ("targetSdk 36", app, r"targetSdk\s*=\s*36"),
    ("v0.43 preview versionCode", app, r"versionCode\s*=\s*57"),
    ("v0.43 real dumper versionName", app, r'versionName\s*=\s*"0\.43\.0-preview-real-il2cpp-dumper"'),
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
    ("CI APK SHA-256", workflow, r'sha256sum .*UniRevLab-Security-v0\.43\.0-real-il2cpp-dumper-debug\.apk'),
    ("CI artifact upload", workflow, r'actions/upload-artifact@v4'),
    ("WorkManager persistent audit", audit_worker, r'OneTimeWorkRequestBuilder<AuditWorker>'),
    ("full report streamed to disk", audit_worker, r'ReportJsonExporter\.write\(report, output\)'),
    ("real IL2CPP dump streamed by file path", audit_worker, r'RealIl2CppDumpEngine\.dump\(metadata, library, outputDirectory\)'),
    ("analysis cache invalidated for v0.43", inspector, r'ENGINE_VERSION\s*=\s*"0\.43\.0-real-il2cpp-dumper"'),
    ("split IL2CPP evidence merger wired", inspector, r'Il2CppSummaryMerger\.merge\(values\)'),
    ("split IL2CPP metadata/library merge", il2cpp_merger, r'SPLIT_EVIDENCE_MERGED'),
    ("human offset report streamed", audit_worker, r'OffsetReadableExporter\.write\(report, output\)'),
    ("human offset search and filters", readable_offsets, r'function applyFilters\(\)'),
    ("human offset C++ name decoding", readable_offsets, r'readableSymbolName'),
    ("game/application surface classifier", modification_surfaces, r'GAME_LIKELY[\s\S]*APPLICATION_LIKELY'),
    ("resolved and metadata-only surfaces separated", modification_surfaces, r'resolvedOffsets[\s\S]*unresolvedManagedCandidates'),
    ("human prioritized surface section", readable_offsets, r'Приоритетные поверхности модификации'),
    ("JSON prioritized surface export", offset_evidence, r'modificationSurfacePrioritization'),
    ("Gradle/module exporter wired", audit_worker, r'GradleModuleEvidenceExporter\.export'),
    ("Gradle split manifest parsing", gradle_evidence, r'configForSplit[\s\S]*isFeatureSplit'),
    ("Gradle dynamic feature classification", gradle_evidence, r'DYNAMIC_FEATURE'),
    ("Gradle evidence regression test", gradle_evidence_test, r'recoversDynamicFeatureAndAgpMetadata'),
    ("AI chat accepts JSON and signed ZIP", ai_chat, r'Выбрать JSON / ZIP'),
    ("OpenRouter dynamic free model catalog", ai_chat, r'fetchFreeModels'),
    ("OpenRouter explicit provider data policy", openrouter_client, r'data_collection[^\n]*dataPolicy\.apiValue'),
    ("OpenRouter strict mode remains default", openrouter_client, r'dataPolicy:\s*OpenRouterDataPolicy\s*=\s*OpenRouterDataPolicy\.STRICT'),
    ("OpenRouter policy conflict has safe fallback", ai_chat, r'canUseStrictFallback[\s\S]*OpenRouterModelCatalog\.defaultModel'),
    ("OpenRouter training policy requires customer consent", ai_chat, r'Подтверждаю разрешение заказчика'),
    ("OpenRouter key encrypted with Android Keystore", openrouter_secret, r'AndroidKeyStore[\s\S]*AES/GCM/NoPadding'),
    ("full report context is streamed", report_context, r'InputStreamReader[\s\S]*MAX_SELECTED_CHUNKS'),
    ("large report import is bounded", report_import, r'MAX_REPORT_BYTES[\s\S]*copyBoundedTo|copyBoundedTo[\s\S]*MAX_REPORT_BYTES'),
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
    ("real IL2CPP JNI dump", pair_engine, r'RealIl2CppDumpEngine\.dump'),
    ("real dump UI truth state", pair_workspace, r'REAL DUMP: COMPLETE'),
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

in_memory_exports = [
    marker
    for marker in (
        "ReportJsonExporter.export(report)",
        "Il2CppManagedDumpExporter.export(report, metadataFile)",
    )
    if marker in audit_worker
]
streaming_only_ok = not in_memory_exports
print(f"{'PASS' if streaming_only_ok else 'FAIL'}: worker avoids artifact-sized in-memory exports")
if not streaming_only_ok:
    failed.append("worker avoids artifact-sized in-memory exports (found: " + ", ".join(in_memory_exports) + ")")

if failed:
    raise SystemExit("Android build-config preflight failed: " + ", ".join(failed))
print(f"Android build-config preflight: PASS ({workflow_path.relative_to(ROOT)})")
