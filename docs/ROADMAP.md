# UniRevLab Security Roadmap

## v0.21 range resolver + RBAC + signed provenance — completed

- npm/NuGet/Maven-safe-subset version-range resolver with fail-closed unsupported grammar.
- Coordinator VIEWER/ANALYST/ADMIN RBAC, rotation-window keysets, PostgreSQL schema/migration export.
- Detached Ed25519 advisory/package-index provenance and connected release attestation.
- Static report schema 1.19; host regressions through v0.21 PASS.
- Local APK build attempted and blocked only by unavailable Android/Gradle download access.
- Next: execute connected Android build and ingest trusted package indexes for range expansion beyond the safe comparator subset.

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


## v0.12 Android source + manifest hardening — current

- File / Installed application source chooser.
- Searchable installed application inventory and system-app filter.
- Base APK + split APK deep static aggregation.
- Source provenance in report schema 1.10.
- Pure-Kotlin binary AXML fallback.
- APK signature scheme scanner (v1/v2/v3/v3.1).
- Network Security Config parser and findings.
- Result sections: Overview / Manifest / DEX / Native / Runtime / SBOM / Findings.
- Next: full framework-vs-AXML manifest cross-check, certificate lineage details, DEX search/xref navigation, native symbol browser, assessment history/diff.

# Implementation backlog

## Current engineering checkpoint — 0.12.0-dev-installed-source

Completed on top of the 0.10/M3 source:

1. Android source chooser: file or installed package;
2. searchable installed-package inventory with system-app filter, version, installer and split count;
3. `base.apk + split APK` static aggregation for DEX/native/runtime/supply chain;
4. report artifact provenance fields and schema 1.9;
5. pure-Kotlin bounded binary AXML fallback for security attributes and deep links;
6. result navigation: Overview / Manifest / DEX / Native / Runtime / SBOM / Findings;
7. Manifest triage for dangerous permissions/exported components/deep links;
8. native import/export/JNI/URL search.

## Next Android client work

1. installed-app scan progress with per-split phase reporting and cancellation;
2. application icon/package detail caching and large-list paging;
3. signing-scheme v1/v2/v3/v4 verification and certificate-history UI;
4. Network Security Config binary/resource resolution;
5. APK resources.arsc/resource-reference resolver;
6. manifest intent-filter path/pathPrefix/pathPattern and provider authority analysis;
7. DEX method detail view with caller/callee/basic-block navigation;
8. native library detail view with imports/exports/JNI/IL2CPP registration evidence;
9. diff UI between two file/installed-app assessments;
10. connected Android compile/unit-test gate (no APK artifact until explicitly requested).

## Current engineering checkpoint — 0.10.0-m3-ghidra-worker-dev

Completed in the current source tree:

1. all static/runtime features from checkpoint 0.9 remain present;
2. Ghidra/PyGhidra worker package and CLI with versioned job/result schemas 1.1;
3. target artifact and scope-receipt SHA-256 verification before analysis;
4. post-analysis target re-hash and atomic validated result publication;
5. function inventory with RVA/name/namespace/signature/size/thunk state;
6. Ghidra BasicBlockModel CFG extraction;
7. in-program call/jump/data/read/write xref extraction;
8. selected-function or complete reported-function decompiler mode;
9. classic `Java_*` JNI export inventory;
10. static `JNINativeMethod` table recovery when Ghidra resolves table/string/code references;
11. IL2CPP CodeRegistration/MetadataRegistration/codegen symbol evidence and codegen callsite references;
12. benign project-owned Ghidra regression fixture;
13. Ghidra 12.1.3 checksum-pinned bootstrap and connected integration workflow;
14. worker unit/fake-launcher tests and schema validation.

## Next — M3.1 deep native correlation and product integration

1. recover architecture-aware arguments to `il2cpp_codegen_register` using decompiler/P-code value propagation;
2. validate CodeRegistration/MetadataRegistration structures against on-device IL2CPP metadata counts;
3. correlate managed IL2CPP methods/types with native function RVAs where evidence is sufficient;
4. enrich dynamic `RegisterNatives` recovery with Java class identity from FindClass/RegisterNatives call context;
5. add native function/signature diff between application versions;
6. ingest Ghidra result contracts through coordinator storage/job lifecycle;
7. add Android graph/search UI for Ghidra functions, CFG, xrefs, JNI and decompiler output;
8. record worker/Ghidra/analyzer provenance and signed result attestation;
9. real ARM64/ARM32/x86_64/x86 benign integration fixtures in connected CI.

## M3.5 — supply-chain/security interoperability

1. vulnerability database snapshot ingestion with provenance and freshness metadata;
2. CVE correlation only when component/version identity meets configured confidence requirements;
3. SARIF export for static/security findings;
4. SBOM dependency relationships and license evidence where explicitly recoverable;
5. reproducible scan attestation tying artifact hash, ruleset, engine and worker versions together.

## M4 — disposable dynamic lab

1. isolated Android emulator lifecycle;
2. filesystem/log/network observations;
3. scoped runtime instrumentation for authorized assessments;
4. regression test replay;
5. environment destruction and evidence attestation.

## Definition of Done for static/runtime layer

- every parsed DEX/ELF/PE/CLI/HBC range is bounds/overflow checked;
- malformed corpus cannot trigger target execution or unbounded allocation;
- native `.so`, managed DLL, JS/HBC, snapshots, and content containers are never executed by the local analyzer;
- raw discovered credentials are never persisted by default;
- static xrefs distinguish syntactic references from confirmed runtime reachability;
- unsupported runtime/container versions fail closed and report partial coverage;
- dependency versions are not guessed without explicit evidence;
- reports/SBOMs are deterministic and versioned;
- Android and Rust connected-CI gates pass for a release candidate.
