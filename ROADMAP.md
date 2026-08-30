## Current engineering checkpoint — 0.22.0-dev-performance-ux

Completed on top of v0.21:

1. shared DEX structural/code pipeline with parity fallback;
2. bounded DEX/native parallelism and SHA-256 content reuse across base/split APKs;
3. versioned app-private normalized report cache for exact warm re-analysis;
4. one-pass archive/runtime/rule classification and lower-allocation bounded merges;
5. RE Browser background indexing, debounce and early-stop search;
6. launcher/round icon, dark Material 3 visual refresh and separate action controls;
7. dedicated `Справка и функции` screen;
8. interruptible analysis cancellation from the UI.

Next: real connected Android compile/lint/unit gate, bug-test pass on representative APK/game reports, private Git repository checkpoint, then portfolio work.

# UniRevLab Security Roadmap

## v0.21 range resolver + RBAC/key rotation + migration + signed provenance — completed

- Conservative npm/NuGet/Maven-safe-subset vulnerability range resolution; unsupported grammar fails closed instead of guessing.
- OSV/GitHub adapters preserve only safely resolvable ranges; exact-version evidence remains preferred and NVD CPE correlation stays exact-only.
- Static report schema 1.19 records exact-vs-range match basis plus verified detached-feed signature provenance.
- Coordinator DB schema 3 adds role-aware authentication (`VIEWER`/`ANALYST`/`ADMIN`) and rotation-window keysets while preserving legacy analyst keys.
- Admin/global audit and authenticated identity endpoints complement the existing hash-chained audit stream.
- Versioned PostgreSQL DDL plus deterministic SQLite migration export provide a concrete migration path.
- Signed advisory/package-index provenance uses detached Ed25519 envelopes; connected release evidence now includes an Ed25519-signed release attestation after Android + multi-ABI Ghidra gates pass.
- v0.12-v0.21/static-core/M2.4/M2.5 host regressions: PASS; Ghidra worker 4/4; coordinator 26/26.
- Local APK build was attempted but blocked by the runtime's inability to resolve/download from `dl.google.com`; no v0.21 APK is falsely claimed.
- Next: execute the connected Android build to obtain the first current APK, then add trusted package-index-backed range expansion where ecosystem metadata is required.

## v0.20 authenticated coordinator + upstream advisory adapters + release evidence — completed

- Coordinator API defaults fail closed unless API keys are configured; Bearer and `X-API-Key` are supported, while anonymous mode requires an explicit lab-only override.
- SQLite uses WAL/full-synchronous durability settings and stores a SHA-256 hash-chained append-only audit stream for assessment/result events; authenticated status/audit endpoints verify chain integrity.
- Android coordinator sync accepts legacy schema 1.0 and current 1.1, sends credentials only in headers, surfaces the remote audit-tail hash, and restricts cleartext HTTP to literal loopback/emulator hosts.
- Offline advisory importer auto-detects normalized UniRevLab 1.0, OSV, NVD CVE 2.0 and GitHub Global Advisory JSON. Exact/enumerated affected versions are preserved; range-only records without a safe ecosystem resolver are counted as skipped instead of guessed.
- Static report schema advances to 1.18 with adapter format/version/skipped-count provenance.
- Release manifest advances to 1.1 with signer-certificate SHA-256, signing-evidence hash, captured toolchain evidence and explicit connected-gate requirements.
- Tag-triggered signed release now depends on a real AArch64/ARM32/x86-64 headless Ghidra IL2CPP release gate.
- v0.20/v0.19/v0.18/v0.17/v0.16/v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Ghidra worker 4/4 and coordinator 21/21: PASS.
- This container still cannot execute the Android Gradle signed build or headless Ghidra download/run; those connected jobs are configured but are not reported as locally passing.
- Next (step 21): ecosystem-aware version-range resolution backed by package indexes/advisory semantics, coordinator RBAC/key rotation/PostgreSQL migration path, and execution/attestation of the connected release gates.

## v0.19 coordinator sync + split resources + advisory provenance + signed release — completed

- Coordinator adds idempotent fixed-ID assessment registration and a bounded sync response carrying latest/history Ghidra revisions; artifact SHA-256 and immutable authorization scope remain enforced.
- Android client can register the current authorized assessment with a self-hosted coordinator and pull matching Ghidra evidence; insecure HTTP is restricted to loopback/emulator lab hosts.
- `resources.arsc` summaries aggregate base/split APK tables without collapsing configuration variants and record source archive/configuration SHA-256 provenance for values and reference chains.
- Advisory feed schema 1.0 is imported offline, hashed in full, recorded as report provenance, and correlated only by exact normalized component ID + exact affected version.
- Static report schema advances to 1.17; CycloneDX 1.6 export carries evidence-backed vulnerability matches.
- Tag-triggered release CI requires explicit keystore secrets, builds APK+AAB, verifies the APK signature, and emits deterministic version/hash metadata.
- v0.19/v0.18/v0.17/v0.16/v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Ghidra worker 4/4 and coordinator 16/16: PASS.
- Android SDK/Gradle are unavailable in this container, so the signed Android release build is configured but is not claimed as locally executed.
- Next (step 20): execute/close connected Android+Ghidra gates, durable authenticated coordinator transport/storage, normalized upstream advisory adapters and release hardening/reproducibility evidence.

## v0.18 connected build + manifest/DEX reachability — implementation checkpoint

- Static report schema 1.16 adds bounded manifest-component -> DEX lifecycle/call-graph reachability evidence.
- `resources.arsc` resolution now records bounded `TYPE_REFERENCE` chains with cycle/depth/unresolved evidence and follows chains for Network Security Config resolution.
- Benign structural IL2CPP fixtures now cover AArch64, ARM EABI5 and x86-64 with pinned SHA-256.
- Connected Ghidra CI matrix analyzes all three ABIs and asserts codegen-module method-pointer slot -> native RVA evidence.
- Android connected CI gate now runs unit tests, lint, debug assembly and release assembly after Rust JNI build.
- v0.18/v0.17/v0.16/v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Ghidra worker 4/4 and coordinator 13/13: PASS.
- Current container cannot download Android SDK/Gradle/Ghidra; connected Android/Ghidra jobs remain pending external execution and are not reported as PASS here.
- Next (step 19 after connected gates pass): coordinator HTTP sync UX, richer resource configuration/split aggregation, CVE feed provenance, and release-grade APK/AAB build/signing pipeline.

## v0.17 codegen modules + resources + intent/provider — completed

- Ghidra result schema 1.3 adds structurally validated `Il2CppCodeGenModule` evidence and bounded method-pointer slot samples.
- Android IL2CPP correlation maps MethodDef token RID to a native RVA only when assembly/module identity and a sampled codegen-module slot agree; previous evidence paths remain conservative fallbacks.
- Real benign ELF fixtures cover AArch64, ARM EABI5 and x86-64 and are SHA-256 pinned.
- Pure-Kotlin `resources.arsc` parsing now covers ordinary, `FLAG_SPARSE`, `FLAG_OFFSET16`, and bounded complex/bag entry structure.
- Intent-filter analysis now records port, path, pathPrefix, pathPattern and MIME type; provider analysis records authorities, URI grants, provider permissions and path-permissions.
- Static report schema advanced to 1.15 and the RE Browser surfaces codegen-module evidence.
- Coordinator accepts Ghidra 1.3 while retaining legacy 1.1/1.2 import; regression suite: 13 tests passing.
- Android build configuration now has a deterministic preflight for AGP/SDK/NDK/Gradle/version contract before connected compilation.
- v0.17/v0.16/v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Next (step 18): connected Android Gradle/SDK compile gate, real Ghidra multi-ABI IL2CPP integration fixtures, resource-reference/config chaining, and intent/provider-to-DEX graph correlation.

## v0.16 structural native + resources — completed

- Ghidra result schema 1.2 adds processor/pointer-size/endianness provenance.
- P-code backed recovery of `il2cpp_codegen_register` call arguments when Ghidra resolves constant addresses.
- Architecture-aware bounded scan of CodeRegistration count/pointer pairs for executable pointer-table candidates; no one-to-one managed method claim is emitted from table order alone.
- `JNINativeMethod` evidence now carries table RVA and bounded RegisterNatives/FindClass function context; uniquely recovered class identity is propagated only across adjacent table rows.
- Pure-Kotlin bounded `resources.arsc` parser resolves simple compiled resource IDs to package/type/key/string/file entries.
- Manifest `@0x...` Network Security Config references now resolve to an exact `res/xml/...` entry before parsing when evidence is available.
- Static report schema advanced to 1.14; RE Browser surfaces IL2CPP structural pointer-table evidence.
- Coordinator accepts Ghidra 1.2 while preserving legacy 1.1 import; regression suite: 12 tests passing.
- v0.16/v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Next (step 17): validated IL2CPP codegen-module/method-pointer mapping with real multi-ABI benign fixtures, sparse/offset16/complex resources.arsc layouts, deeper intent/provider analysis, and connected Android Gradle/SDK build gate.

## v0.15 cross-runtime correlation + durable Ghidra history — completed

- Evidence-backed DEX native declaration ↔ Ghidra JNI function correlation with ambiguity rejection.
- Evidence-backed IL2CPP registration cross-check and conservative metadata method ↔ native RVA mapping.
- Android bounded Ghidra result JSON import with assessment/artifact identity validation.
- RE Browser cross-runtime links between DEX, JNI, Ghidra and IL2CPP.
- Native function-level version diff and deterministic report schema 1.13 correlation section.
- SQLite-backed coordinator assessment/result persistence with idempotent content-addressed revisions and history endpoint.
- Coordinator regression suite: 11 tests passing.
- v0.15/v0.14/v0.13/v0.12/static-core/M2.4/M2.5 host regressions: PASS.
- Next (step 16): architecture-aware IL2CPP registration structure recovery / method-pointer tables, deeper `RegisterNatives` class recovery, resources.arsc resolver and connected Android build gate.

## v0.14 Ghidra product integration — completed

- Typed Ghidra result 1.1 domain model in the Android source tree.
- Static report schema 1.12 carries normalized deep-native function/CFG/xref/JNI/IL2CPP evidence.
- RE Browser shows and searches Ghidra functions and registration evidence.
- Coordinator ingest/list endpoints enforce assessment identity, artifact SHA-256 and reverse-mode authorization.
- Coordinator regression suite: 8 tests passing in the current host environment.
- Kotlin v0.14 plus v0.12/v0.13/static-core/M2.4/M2.5 host regression smokes: PASS.
- Next (step 15): durable result/history storage, Android coordinator client/import, DEX↔Ghidra JNI correlation, deeper IL2CPP registration→metadata correlation, function-level binary diff.

## v0.13 RE browser + signing + version diff — completed

- DEX package/class/method browser with incoming/outgoing xrefs, strings, fields, types, constants and CFG blocks.
- Native library/import/export/JNI browser with symbol RVA/size evidence.
- IL2CPP searchable type/method/token browser and registration candidates.
- Framework-backed X.509 signer details and proof-of-rotation history.
- Android 36+ framework signature verification status.
- Raw binary AXML ↔ PackageManager manifest cross-check.
- In-memory baseline and deterministic version/security diff JSON schema 1.0.
- Static report schema 1.11.

## Next Android/client integration work

1. validate IL2CPP `Il2CppCodeGenModule` structures and method-pointer/index tables against metadata/version evidence before managed-method RVA claims;
2. real ARM64/ARM32/x86_64 benign Ghidra/IL2CPP integration fixtures in connected CI;
3. sparse, offset16 and complex/bag `resources.arsc` layouts plus split-resource aggregation;
4. manifest intent-filter path/pathPrefix/pathPattern and provider authority/URI-permission analysis;
5. CVE/advisory correlation and vulnerability-feed provenance;
6. Android coordinator HTTP sync UX on top of bounded file import;
7. connected Android compile/unit/instrumentation gate;
8. Gradle Wrapper/reproducible build metadata;
9. next APK checkpoint after the connected build gate is green.
