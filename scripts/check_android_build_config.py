#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "app/build.gradle.kts").read_text()
root_build = (ROOT / "build.gradle.kts").read_text()
workflow = (ROOT / ".github/workflows/android.yml").read_text()
release_workflow = (ROOT / ".github/workflows/release.yml").read_text()

checks = {
    "compileSdk 37.0": r"version\s*=\s*release\(37\)[\s\S]*minorApiLevel\s*=\s*0",
    "targetSdk 36": r"targetSdk\s*=\s*36",
    "versionCode 18": r"versionCode\s*=\s*18",
    "versionName v0.22": r'versionName\s*=\s*"0\.22\.0-dev-performance-ux"',
    "AGP 9.3.0": r'id\("com\.android\.application"\) version "9\.3\.0"',
    "Kotlin Compose 2.3.21": r'id\("org\.jetbrains\.kotlin\.plugin\.compose"\) version "2\.3\.21"',
    "CI Android platform 37.0": r'platforms;android-37\.0',
    "CI build-tools 36.0.0": r'build-tools;36\.0\.0',
    "CI NDK 28.2.13676358": r'ndk;28\.2\.13676358',
    "CI Gradle 9.5.0": r"gradle-version:\s*'9\.5\.0'",
    "CI unit tests": r':app:testDebugUnitTest',
    "CI lint": r':app:lintDebug',
    "CI debug build": r':app:assembleDebug',
    "CI release compile": r':app:assembleRelease',
    "release tag trigger": r"tags:\s*\n\s*- ['\"]v\*['\"]",
    "release signing input gate": r':app:verifyReleaseSigningInputs',
    "release lint": r':app:lintRelease',
    "release APK": r':app:assembleRelease',
    "release AAB": r':app:bundleRelease',
    "release APK signature verify": r'apksigner verify --verbose --print-certs',
    "release deterministic manifest": r'make_release_manifest\.py',
    "release Ghidra dependency": r'needs:\s*ghidra-release-gate',
    "release Ghidra multi-ABI gate": r'assert_ghidra_multiabi_result\.py',
    "release toolchain evidence": r'capture_release_toolchain\.py',
    "release signer evidence": r'release-signing-evidence\.txt',
    "release hashes": r'sha256sum[\s\S]*app-release\.apk[\s\S]*app-release\.aab[\s\S]*release-manifest\.json',
    "release connected attestation": r'make_release_attestation\.py',
    "release attestation signature": r'sign_detached_ed25519\.py',
    "release Ghidra evidence download": r'actions/download-artifact@v4[\s\S]*release-ghidra-',
}
texts = {
    "compileSdk 37.0": app, "targetSdk 36": app, "versionCode 18": app, "versionName v0.22": app,
    "AGP 9.3.0": root_build, "Kotlin Compose 2.3.21": root_build,
}
for key in list(checks):
    if key.startswith("release "):
        texts.setdefault(key, release_workflow)
    else:
        texts.setdefault(key, workflow)
failed=[]
for name, pattern in checks.items():
    ok=bool(re.search(pattern, texts[name]))
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok: failed.append(name)
if failed:
    raise SystemExit("Android build-config preflight failed: " + ", ".join(failed))
print("Android build-config preflight: PASS")
