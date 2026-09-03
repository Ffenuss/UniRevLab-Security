# Changelog

## 0.26.0-auto-audit

### Added
- one-selection installed-app/APK audit flow with persisted customer profile and per-target authority confirmation;
- persistent WorkManager foreground pipeline with stage progress, cancellation and result recovery;
- bounded automatic DEX/native/IL2CPP/managed/runtime evidence bundle;
- static RVA/metadata offset export, defensive verification plan and Russian customer report;
- device-keystore ECDSA manifest signature and all-in-one evidence ZIP.

### Changed
- replaced the previous manual dashboard/import sequence with an Auto Audit home screen;
- retained the v0.22 content-addressed cache, shared archive index and bounded parallel DEX/native analysis;
- engine/version provenance advanced to `0.26.0-auto-audit` (versionCode 30).

### Safety
- the target archive remains immutable and non-executing input;
- no hook implementation, bypass patch, injected mod menu, target re-signing or modified APK is produced;
- active checks are expressed as a verification plan for an owner-supplied test/source build.

## 0.21.0-dev-range-rbac-attestation

### Added
- conservative npm/NuGet/Maven-safe-subset advisory range resolution with explicit match-basis evidence;
- coordinator VIEWER/ANALYST/ADMIN RBAC and rotation-window API-key configuration;
- PostgreSQL schema v3 migration DDL and deterministic SQLite export bundle;
- detached Ed25519 feed/package-index provenance verification and signed connected-release attestation.

### Changed
- static analysis report schema to 1.19;
- Android versionCode to 17 and versionName to `0.21.0-dev-range-rbac-attestation`;
- connected release workflow now downloads all three Ghidra gate results and binds them into the release attestation.

### Verification
- v0.12-v0.21 host regressions PASS; coordinator 26/26; Ghidra worker 4/4.
- local APK build attempted but blocked before toolchain installation because `dl.google.com` cannot be resolved from this runtime.


## 0.20.0-dev-auth-feed-evidence

- Added fail-closed coordinator authentication using Bearer or `X-API-Key`; anonymous access now requires an explicit lab override.
- Added SQLite durability hardening plus append-only SHA-256 hash-chained audit events and authenticated audit/status endpoints.
- Advanced coordinator sync schema to 1.1 with audit-tail evidence; Android accepts legacy 1.0 and authenticated 1.1.
- Restricted cleartext coordinator URLs to literal localhost/loopback/Android-emulator lab hosts, avoiding DNS-based cleartext exceptions.
- Added bounded offline adapters for OSV, NVD CVE 2.0 and GitHub Global Advisory JSON. Only explicit/exact versions are normalized; unsupported range-only evidence is counted, not guessed.
- Advanced static report schema to 1.18 with advisory format/adapter/skipped-record provenance.
- Added release manifest schema 1.1, signer-certificate SHA-256 evidence and captured Java/Gradle/Rust/Android/Ghidra toolchain provenance.
- Tag release now depends on the real AArch64/ARM32/x86-64 Ghidra IL2CPP gate before the signed Android release job can run.
- Coordinator regression suite now passes 21 tests; v0.12-v0.20 host regressions remain passing.

## 0.19.0-dev-sync-advisory-release

- Added idempotent coordinator HTTP assessment registration/sync with immutable scope and artifact identity checks.
- Added Android self-hosted coordinator sync flow with bounded response handling and assessment/artifact validation.
- Added split/config `resources.arsc` aggregation with source archive and configuration SHA-256 provenance.
- Added normalized advisory feed schema 1.0, whole-feed SHA-256 provenance and exact component-version vulnerability correlation.
- Added advisory evidence to static report schema 1.17 and CycloneDX 1.6 vulnerability export.
- Added Android advisory-feed import/results UI and supply-chain provenance display.
- Added tag-triggered signed APK/AAB release workflow, signing-input verification, APK signature verification and deterministic release manifest/hash output.
- Coordinator regression suite now passes 16 tests; previous v0.12-v0.18 host regressions remain passing.

## 0.18.0-dev-connected-reachability

- Added manifest/provider/deep-link to DEX static reachability graph evidence.
- Added bounded resources.arsc reference-chain resolution and cycle detection.
- Added three-ABI structural IL2CPP/Ghidra fixtures and connected CI matrix.
- Hardened Android connected build gate with unit, lint, debug and release compile tasks.
- Advanced static report schema to 1.16 and corrected engine provenance version.

## 0.17.0-dev-codegen-resources-intent

- Advanced Ghidra result schema to 1.3 with structurally validated IL2CPP codegen-module and bounded method-pointer-slot evidence.
- Added evidence-gated managed MethodDef token to native RVA correlation by assembly/module identity and token RID.
- Added real SHA-256-pinned AArch64, ARM EABI5 and x86-64 benign ELF fixtures.
- Extended `resources.arsc` parsing for regular, sparse, offset16 and bounded complex/bag entries.
- Extended intent-filter and ContentProvider analysis for paths, MIME, authorities, URI grants and path-permissions.
- Advanced static report schema to 1.15 and preserved Ghidra 1.1/1.2 ingestion compatibility.
- Added deterministic Android build configuration preflight and CI schema/secret preflight.
- Coordinator regression suite now passes 13 tests; Ghidra worker suite passes 4 tests.

## 0.10.0-m3-ghidra-worker-dev

- Added real headless Ghidra/PyGhidra worker package and CLI.
- Ghidra job/result contracts advanced to schema 1.1.
- Added target and scope-receipt SHA-256 verification before analysis and target re-hash after analysis.
- Added function inventory, BasicBlockModel CFG, typed xrefs and selected/all-function decompiler mode.
- Added classic JNI export recovery and static `JNINativeMethod`-table recovery.
- Added IL2CPP CodeRegistration/MetadataRegistration/codegen symbol and callsite evidence.
- Added Ghidra 12.1.3 checksum-pinned bootstrap and connected integration CI.
- Added benign native regression fixture for JNI, CFG/xrefs and IL2CPP registration evidence.
- Added worker unit/fake-launcher regression suite.

## 0.9.0-m2-deep-metadata-sbom-dev

- Report schema advanced to 1.8.
- Added deeper bounded Hermes HBC fixed-header and `SmallFuncHeader` reconstruction.
- Added ECMA-335 `TypeRef`, `TypeDef`, `MethodDef`, `MemberRef`, `Assembly`, and `AssemblyRef` reconstruction through `#Strings` and `#~/#-` table layouts.
- Added exact managed assembly/version evidence and bounded method-to-type association.
- Added ELF dynamic-symbol address/size evidence and stronger validated IL2CPP registration-symbol candidates.
- Added exact Maven dependency versions/purls from packaged `META-INF/maven/**/pom.properties` when present.
- Added deterministic CycloneDX 1.6 JSON and SPDX 3.0.1 JSON-LD SBOM exporters.
- Added Android UI actions for both SBOM formats and supply-chain evidence summary.
- Added M2.5 synthetic regression fixtures for Hermes, ECMA-335, Maven version evidence, IL2CPP symbols, CycloneDX and SPDX.

## 0.8.0-m2-runtime-metadata-sbom-dev

- Report schema advanced to 1.7.
- Added Flutter snapshot/kernel SHA-256 fingerprints with bounded reads.
- Added ECMA-335 metadata stream directory parsing and selected table row counts.
- Added bounded Unreal container probe fingerprints.
- Added passive supply-chain component fingerprinting from DEX/runtime/IL2CPP/native evidence.
- Preserved runtime-specific artifact summaries from the previous checkpoint.
- Added Flutter AOT/assets/snapshot inventory without loading Dart/native target code.
- Added Hermes HBC magic and stable header parsing plus plain JS bundle separation.
- Split React Native and Hermes runtime fingerprints while preserving a combined profile when both are present.
- Added bounded PE/CLI validation for Unity Mono / managed assemblies.
- Added Unreal PAK/IoStore/OBB and native engine inventory.
- Added explicit IL2CPP CodeRegistration/MetadataRegistration/codegen symbol candidates as non-validated evidence.
- Added versioned Ghidra worker job/result contracts and sandbox requirements.
- Added runtime-specific Android dashboard summary and regression fixtures.

## 0.6.0-m2-flow-runtimes-dev

- Added DEX field xrefs and bounded CFG/basic-block construction.
- Added conservative intra-block constant propagation and invoke argument observations.
- Added stronger WebView finding when a risky option is statically enabled.
- Added structured IL2CPP metadata reconstruction inventory for validated v27-v31 layouts.
- Added passive runtime profiles: Unity Mono/IL2CPP, Unreal, Flutter, React Native/Hermes, Xamarin/.NET and Cordova.
- Added bounded local DEX class/method/string/field/call search in the Android dashboard.
- Report schema updated to 1.5.


## 0.5.0-m2-code-il2cpp-dev — DEX code xrefs and Unity IL2CPP baseline

### Added
- bounded DEX `code_item` parser with instruction-width validation and payload bounds checks;
- normalized method→method, method→string and method→type xrefs;
- privacy-safe string-xref evidence with URL query/fragment stripping and token redaction;
- xref-driven manual-review signals for dynamic code/native loading, process execution, and sensitive WebView APIs;
- Unity IL2CPP detector for `global-metadata.dat` + `libil2cpp.so`;
- IL2CPP metadata magic/version/header-pair inventory, assembly/managed-name candidates and Unity-version candidates;
- bounded `il2cpp_*` native API symbol inventory from the existing ELF scanner;
- `IL2CPP-APPLICATION-SURFACE` and unrecognized-metadata analysis findings;
- JSON report schema v1.4 and Android dashboard cards for DEX xrefs / IL2CPP;
- synthetic non-proprietary DEX code-xref and IL2CPP regression fixtures in host-side smoke tests.

### Safety properties
- target bytecode and `libil2cpp.so` remain non-executing inputs;
- xrefs are explicitly syntactic/static evidence, not claims of runtime reachability;
- unknown IL2CPP metadata layouts are not guessed;
- no runtime offset, patch, hook, or bypass generation is present in this checkpoint.

## 0.4.0-m2-native-dev — ELF/JNI static analysis

### Added
- bounded non-executing ELF32/ELF64 parser for APK native libraries;
- ABI/machine/file-type, Build-ID, `DT_NEEDED`, imports/exports and JNI symbol inventory;
- GNU RELRO, BIND_NOW, executable-stack, stack-canary and stripped-binary indicators;
- DEX native declarations ↔ classic JNI symbol correlation and dynamic-registration candidate classification;
- native URL/secret evidence with secret redaction;
- benign hardened/weak ELF regression fixtures and Android CI fixture rebuild;
- deterministic report schema v1.3.

## 0.3.0-m2-dev — Bounded DEX static inventory

### Added
- bounded DEX string-table reader that uses `RandomAccessFile` and never loads/executes target classes;
- defensive DEX header, top-level type/proto/field/method/class table ranges, string-count, per-string and decompression limits;
- hardcoded HTTP/HTTPS endpoint inventory with query/fragment stripping before evidence persistence;
- high-signal potential-secret detection for private-key material, JWT-like tokens, Google API-key-like tokens and AWS access-key-id-like tokens;
- strict secret evidence handling: raw candidate is never exported; report retains only type, DEX/string location, SHA-256, and length-only redaction;
- `DEX-HARDCODED-HTTP-URL`, `DEX-POTENTIAL-HARDCODED-SECRET`, and `ANALYSIS-DEX-PARTIAL` findings;
- DEX coverage/error counters in the Android dashboard;
- JSON report schema v1.2 with nullable DEX section;
- pure-Kotlin synthetic DEX smoke fixture and scanner unit tests;
- per-entry I/O failure accounting so malformed ZIP/DEX input cannot silently look clean.

### Verification
- pure-Kotlin synthetic DEX scan: pass;
- endpoint sanitization and secret redaction assertions: pass;
- generated JSON report validates against schema v1.2: pass;
- full Android/Rust build remains a connected-CI gate in this local environment.

## 0.2.1-m1 — Manifest attack-surface and agreement hardening

### Added
- versioned user agreement receipt with signer name, acceptance timestamp, SHA-256 of the exact agreement text, and ECDSA signature backed by Android Keystore;
- agreement receipt verification on subsequent launches; changed agreement text/version invalidates prior acceptance;
- AXML-derived browsable VIEW intent-filter inventory for web App Links and custom URL schemes;
- normalized deep-link declarations in report schema v1.1;
- app-declared custom-permission protection-level inventory;
- dedicated finding for exported unprotected ContentProviders (`MASTG-TEST-0355`);
- review finding for exported components protected only by broadly grantable normal/dangerous custom permissions;
- finding for HTTP(S) deep links without `android:autoVerify=true` (`MASTG-TEST-0393`);
- manual-review finding for custom URL scheme handlers (`MASTG-TEST-0394`);
- deterministic JSON export for declared permissions and deep links;
- unit coverage for App Links, custom schemes, provider exposure, and weak custom permissions.

### Verification
- pure-Kotlin rule/model/report smoke compilation: pass;
- deterministic JSON generated by Kotlin exporter validates against JSON Schema 2020-12 v1.1: pass;
- full Android SDK build remains a connected-CI gate in the current local environment.

## 0.2.0-m1 — APK Static Analysis Core (developer checkpoint)

### Added
- normalized `Finding`, `Evidence`, `Severity`, `Confidence`, `ManifestSummary`, and `StaticAnalysisReport` models;
- immutable assessment identity (`assessmentId`, creation timestamp) included in reports;
- bounded local APK copy and SHA-256 artifact identity;
- Android PackageManager manifest/component/signing-certificate inspection without target execution;
- SHA-256 signing-certificate fingerprints;
- dangerous-permission classification from the assessor Android platform;
- initial defensive manifest rules mapped to OWASP MASVS/MASTG concepts;
- deterministic JSON report export and JSON Schema 2020-12 validation contract;
- bounded Rust Android Binary XML parser with UTF-8/UTF-16 string-pool support and parser limits;
- narrow Android JNI bridge: binary manifest bytes to structured JSON AST;
- AXML overlay for Network Security Configuration / backup rule references;
- libFuzzer target and malformed APK/ZIP seed corpus;
- CI security hygiene: offline secret preflight, cargo-deny policy, OSV scanning;
- Android CI builds Rust JNI libraries for four Android ABIs before app tests/build.

### Safety properties
- target APK is never executed by the local analyzer;
- ZIP structural inspection reads central-directory metadata before any bounded manifest extraction;
- parser sizes/counts are capped;
- uncertain manifest state remains unknown and produces reduced-confidence/manual-review findings.
## 0.16.0-dev-structural-native-resources

- Ghidra result schema advanced to 1.2 with architecture, pointer-size and endianness provenance.
- Added decompiler P-code recovery of constant `il2cpp_codegen_register` arguments.
- Added bounded architecture-aware executable pointer-table candidates from recovered CodeRegistration structures without assuming method-index identity.
- Enriched dynamic JNI evidence with JNINativeMethod table RVA, RegisterNatives/FindClass callsite context and conservative class propagation across adjacent table rows.
- Added pure-Kotlin bounded `resources.arsc` resolver for ordinary type chunks and simple values.
- Network Security Config numeric manifest references can now resolve to an exact XML resource entry.
- Static report schema advanced to 1.14; RE Browser exposes structural IL2CPP pointer-table evidence.
- Coordinator accepts Ghidra result 1.2 and remains backward-compatible with 1.1; 12 coordinator tests pass.
- Added v0.16 synthetic resources/native regression fixture and smoke harness.
- No APK produced for this source checkpoint.

## 0.15.0-dev-cross-runtime

- Added evidence-backed DEX native declaration ↔ Ghidra JNI function correlation with explicit ambiguity rejection.
- Added IL2CPP registration cross-checks and conservative metadata method ↔ native RVA mapping from unique token/type+method evidence only.
- Added bounded Android Ghidra result JSON import plus assessment/artifact identity validation before report attachment.
- RE Browser now surfaces DEX→JNI targets and Ghidra→DEX/IL2CPP cross-runtime links.
- Static report schema advanced to 1.13 with deterministic correlation evidence.
- Version diff now reports native-function additions/removals and function-shape changes.
- Coordinator storage moved from process-local dictionaries to SQLite with content-addressed, idempotent Ghidra revisions and history queries.
- Coordinator regression suite expanded to 11 passing tests.
- No APK produced for this source checkpoint.

## 0.14.0-dev-ghidra-integration

- Added normalized Android domain models for Ghidra worker result schema 1.1.
- Static report schema advanced to 1.12 with bounded deep-native Ghidra evidence.
- RE Browser now indexes Ghidra functions, CFG coverage, incoming/outgoing xrefs, JNI registrations, IL2CPP registration evidence and decompiler previews.
- Coordinator now persists in-memory Ghidra results per assessment/library and rejects results with mismatched assessment identity, artifact SHA-256, or missing reverse-engineering authorization.
- Added coordinator regression tests and a v0.14 host-side Kotlin/schema smoke harness.
- No APK produced for this source checkpoint.

## 0.13.0-dev-re-browser-diff
- Added normalized DEX/native RE browser indexes.
- Added package/class/method browsing with caller/callee/string/field/type/basic-block evidence.
- Added native symbol/JNI/RVA browser model.
- Added in-session version diff for the same package: permissions, exported components, deep links, findings, dependencies, DEX methods/classes, native libraries/exports, and signer changes.
- Added structured X.509 signing certificate identity/lineage metadata (subject, issuer, serial, validity, algorithms, key size, current signer).
- Static report schema advanced to 1.11.
