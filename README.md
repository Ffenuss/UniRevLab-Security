# UniRevLab Security

Open-source Android-first platform for **authorized** mobile application security assessment and reverse engineering.

## Current milestone: v0.26.0-auto-audit

The Android client now exposes one primary workflow: save the customer profile once, confirm the
scope for the current target, then select an installed application or APK. A persistent WorkManager
job performs the bounded analysis and prepares a signed customer evidence package without further
file hunting or manual result assembly.

Implemented now:

- persistent one-selection Auto Audit workflow with progress, cancellation and recovery after UI/process recreation;
- automatic base/split APK discovery for installed applications;
- automatic evidence extraction for AndroidManifest/resources, DEX, ELF/native libraries, IL2CPP `global-metadata.dat`, managed assemblies and supported runtime containers;
- `offset-evidence.json` with static ELF RVA evidence, IL2CPP metadata table offsets/tokens and attached Ghidra evidence when available;
- Russian customer report, defensive verification plan and an independently verifiable ECDSA-signed evidence package;
- Android client with first-run authorized-use agreement and signed local acceptance receipt;
- explicit per-assessment scope and authority confirmation;
- Storage Access Framework artifact selection (no broad storage permission);
- local SHA-256 fingerprinting and bounded APK/ZIP inspection;
- manifest, permission, exported-component, deep-link and signing analysis;
- bounded DEX strings/types/classes/methods/native-method index;
- DEX `code_item` parsing with method→method/string/type/field xrefs, bounded CFG/basic blocks and conservative invoke-argument observations;
- privacy-safe URL/secret evidence handling;
- code-level review signals for dynamic loading, process execution and sensitive WebView APIs;
- non-executing ELF32/ELF64 native analysis, hardening inventory and JNI correlation;
- Unity IL2CPP structured metadata inventory for validated v27–v31 layouts, native API inventory and registration-symbol address evidence when present;
- passive runtime profiles for Unity Mono/IL2CPP, Unreal, Flutter, React Native/Hermes, Xamarin/.NET and Cordova;
- Flutter AOT/assets/snapshot fingerprints, deeper Hermes HBC header/function inventory, Unity Mono PE/CLI/ECMA-335 reconstruction and Unreal container fingerprints;
- passive supply-chain inventory with exact Maven version evidence from packaged `pom.properties` where available;
- deterministic CycloneDX 1.6 and SPDX 3.0.1 JSON-LD SBOM export;
- deterministic static-analysis JSON report schema v1.19, including split/config resource provenance, normalized Ghidra deep-native evidence, cross-runtime correlation and upstream advisory-adapter provenance;
- real versioned Ghidra/PyGhidra headless worker launcher with artifact/scope hash verification, function/CFG/xref/decompiler export, enriched JNI FindClass/RegisterNatives context and architecture-aware IL2CPP registration-call/pointer-table evidence;
- FastAPI coordinator with SQLite WAL persistence, VIEWER/ANALYST/ADMIN RBAC, rotation-window API keys, immutable assessment/Ghidra revision history, tamper-evident hash-chained audit events, PostgreSQL migration DDL/export, Rust native-core foundation, worker boundaries and CI/security checks.
- self-hosted coordinator sync schema 1.1 with Bearer/X-API-Key authentication, immutable artifact/scope verification, bounded Ghidra revision pull and audit-tail evidence;
- split APK `resources.arsc` aggregation with per-source/configuration provenance and cross-split reference resolution;
- normalized offline advisory import plus bounded OSV, NVD CVE 2.0 and GitHub Global Advisory adapters; exact versions plus a conservative npm/NuGet/Maven-safe range subset can be correlated, while unsupported range grammar remains unknown;
- tag-triggered signed APK/AAB release workflow gated by multi-ABI Ghidra IL2CPP analysis, keystore-input verification, APK signer-certificate evidence, toolchain evidence, deterministic release manifest 1.1 metadata and a detached-Ed25519 signed connected-gate attestation.

## Android build baseline

- Android Gradle Plugin 9.3.0
- Gradle 9.5.0
- compileSdk 37
- targetSdk 36
- JDK 17+
- Compose BOM 2026.08.00

Build in Android Studio or connected CI with the required toolchain:

```bash
gradle :app:assembleDebug
```

A standard Gradle Wrapper should be generated once from a trusted Gradle 9.5.0 installation before the first public release (`gradle wrapper --gradle-version 9.5.0`).

## Safety boundary

The official project is designed for systems the user owns or is explicitly authorized to assess. Target APK/DEX/ELF/IL2CPP/HBC/managed inputs are treated as hostile data and are not executed by the local static analyzer. Active testing must be tied to an assessment scope. The official client does not rewrite/re-sign a third-party target APK and does not generate executable hooks, bypass patches or injected mod-menu payloads. Those actions are replaced with static evidence and a defensive verification plan for an owner-supplied test build. The official codebase will not include stealth persistence, credential theft, hidden remote control, indiscriminate exploitation, malware payload delivery, or security-product evasion.

See [V026_AUTO_AUDIT_PIPELINE.md](V026_AUTO_AUDIT_PIPELINE.md) for the workflow and output contract.

## Current M3/M3.1 work

1. headless Ghidra/PyGhidra runner now emits result schema v1.3 (legacy v1.1/v1.2 import remains supported);
2. function inventory, CFG, xrefs, decompiler previews, classic JNI exports and static `JNINativeMethod` recovery with bounded FindClass/RegisterNatives context are implemented;
3. Android report/domain models carry normalized Ghidra result evidence plus bounded cross-runtime correlation evidence;
4. RE Browser links DEX native declarations to recovered JNI RVAs and Ghidra functions back to DEX/IL2CPP identities;
5. Android can import bounded Ghidra result JSON and rejects mismatched assessment/artifact identities;
6. coordinator persists assessment and content-addressed Ghidra revision history in SQLite;
7. version diff includes native-function additions/removals and function-shape changes;
8. architecture-aware codegen-module/method-pointer evidence, multi-ABI fixtures, sparse/offset16/complex resources, intent/provider-to-DEX reachability, authenticated coordinator sync, split-resource provenance and upstream advisory adapters are implemented; range resolution, RBAC/key rotation, migration export and signed provenance are now implemented; next priority is executing the connected Android build to produce a current APK.
