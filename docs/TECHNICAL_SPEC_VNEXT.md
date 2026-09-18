# ModKit / UniRevLab Security vNext — Canonical Technical Specification

> **Status:** CANONICAL / source of truth for further development  
> **Repository:** `Ffenuss/UniRevLab-Security`  
> **Working branch:** `Modkit1`  
> **Protected branch:** `main` — do not modify or merge without explicit user instruction.

## 0. Non-negotiable interpretation rule

Every capability must be tracked as one of:

- **DONE**
- **IMPLEMENTED_BUT_INCOMPLETE**
- **TO_ADD**
- **TO_REWORK**
- **HIDE_FROM_SIMPLE_UX_KEEP_INTERNAL**

Never treat “already exists” as “finished” if the current implementation has known gaps.

For every subsystem always record:

1. what exists now;
2. what is incomplete;
3. what must be added;
4. when it should run;
5. what output proves completion;
6. what known blockers/limitations remain.

Fail-closed remains mandatory. Weak evidence must never be promoted to exact/patch-ready evidence.

---

# 1. Product goal

ModKit is an Android application for authorized analysis of closed/release Android APK/APK-set targets without requiring source code.

The primary user workflow must be:

**select target → fast analysis → conclusions → targeted additional search/confirmation if needed → runtime escalation only if static analysis is insufficient → patch/inject/mod → build/sign/verify → receive APK/APK-set.**

The product must not expose the internal engine architecture as the main workflow.

The internal architecture should remain:

`APK/APK-set → profiler → artifact inventory → runtime detection → specialized engines → cross-runtime graph → evidence graph → Simple Mode / reports / Patch Lab`

but the user should interact with a compact linear workflow.

---

# 2. Main UX flow

Simple Mode should expose five primary stages:

1. **Target selection**
2. **Analysis**
3. **Results**
4. **Prepare changes**
5. **Built APK**

All low-level controls go to Expert Lab or internal automation.

---

# 3. Target selection

The start screen must provide:

- **Installed application**
- **APK / APK-set / file**

## Installed application

ModKit must automatically obtain:

- package name;
- base APK;
- split APKs;
- versionCode/versionName;
- available ABI(s);
- source relationship for later Patch Lab use.

## File input

Support at minimum:

- `.apk`
- `.apks`
- `.xapk`
- ZIP APK-set
- `.dex`
- `.so`
- extensionless ELF
- `global-metadata.dat`
- `.dll`
- `.wasm`
- `.pak`
- `.utoc`
- `.ucas`
- `.pck`
- `.gd`
- `.tscn`
- `.tres`
- `.arci`
- `.arcd`
- `.dmanifest`
- `.qml`
- `.qmlc`
- `.jsc`
- JavaScript bundles
- Hermes HBC/bundles
- Lua/Lua bytecode
- other files supported by registered backends.

Individual files are primarily for Expert Lab.

---

# 4. Analysis must be fast-first, not “run everything”

The historical pipeline contains many engines/stages. That is coverage, not a mandate to fully execute every engine for every APK.

Introduce an Analysis Scheduler with four classes:

| Class | Purpose |
|---|---|
| FAST | Mandatory triage and first useful result |
| TARGETED | Run when runtime/artifacts justify it |
| CONFIRMATION | Run only to resolve an uncertainty/blocker |
| BACKGROUND | Heavy enrichment that must not block useful output |

## FAST examples

- archive inventory;
- Manifest;
- runtime profiler;
- ABI detection;
- DEX inventory;
- ELF inventory;
- basic string index;
- artifact classification;
- protection fingerprint;
- IL2CPP pair detection;
- target SHA fingerprints.

## TARGETED examples

- IL2CPP metadata/dump after IL2CPP detection;
- Flutter/Dart only if Flutter is detected;
- Unreal only if Unreal artifacts are present;
- Mono/.NET only when managed CLI metadata is found;
- native deep only for relevant ABI/libraries.

## CONFIRMATION examples

- exact xrefs;
- CodeGenModule recovery;
- Deep Resolver;
- targeted call/data-flow;
- exact executable binding;
- runtime confirmation.

## BACKGROUND examples

- exhaustive network/API scan;
- TLS/crypto enrichment;
- exhaustive xrefs;
- broad evidence graph enrichment;
- deep protection heuristics.

BACKGROUND must not prevent the user from opening results, dump, or confirmed findings.

---

# 5. Single-pass ArtifactIndex

Build a central reusable `ArtifactIndex` once per target.

It should include:

- archive entries;
- paths;
- compressed/uncompressed size;
- CRC/hash;
- file type;
- runtime tags;
- ABI tags;
- DEX references;
- ELF references;
- string index references;
- metadata references;
- resource references;
- container/split relationships;
- ownership/source APK relation.

Engines should consume the index instead of rescanning the APK independently.

Cache key:

`artifactSHA + engineID + engineVersion`

Do not repeat decompression, hashing, DEX parsing, ELF parsing, or metadata parsing when a valid cached result exists.

---

# 6. Runtime Profiler

## Existing

Multi-label runtime detection already covers:

- android_dex
- native_elf
- unity_il2cpp
- unity_mono
- unreal
- flutter
- react_native_hermes
- react_native_jsc
- dotnet_android
- cordova
- capacitor
- cocos
- godot
- defold
- qt_qml
- libgdx
- lua_runtime
- webview_hybrid
- webassembly
- unknown

ABI detection includes:

- arm64-v8a
- armeabi-v7a
- x86
- x86_64

APK-set is supported.

## Required changes

Runtime detection remains **multi-label**.

Do not reduce an APK to a single engine identity.

One APK may contain DEX + native + WebView + game engine + SDKs simultaneously.

However, detection must drive scheduler routing rather than automatically triggering full deep analysis for every detected component.

---

# 7. Engine Router

## Existing

The router can map:

- one runtime → multiple engines;
- multiple runtime routes;
- FULL_BUNDLED;
- PARTIAL_BUNDLED;
- GENERIC_FALLBACK.

## Required changes

Router output must include:

- `fastEngines`
- `recommendedEngines`
- `confirmationEngines`
- `backgroundEngines`
- `missingCapabilities`

Do not claim FULL_BUNDLED where a real deep parser/data-flow backend is absent.

Unknown/custom runtime must never become a dead end. Use generic fallback:

- APK/resources;
- DEX;
- ELF;
- strings;
- loaders;
- obfuscation/protection;
- artifacts;
- security evidence.

---

# 8. Incremental results

Replace “no useful result until all stages finish” with progressive publication.

Example:

- Runtime detected ✓
- IL2CPP dump ready ✓
- Gameplay index ready ✓
- Native deep 68%
- Network/TLS running in background

The user must be able to open already finished outputs immediately.

---

# 9. Speed objective

The main KPI is **time to first useful result**, not total time for every deep engine.

Targets:

- inventory/runtime detection: seconds where feasible;
- first useful findings quickly;
- IL2CPP dump must not wait for network/TLS/crypto;
- deep/background analysis may run longer without blocking normal use.

No fixed universal wall-clock SLA can be guaranteed for all APK sizes, but there must be no architecture that intentionally serializes unrelated heavy engines.

---

# 10. Heartbeat / watchdog

Every engine must expose:

- engine ID;
- current task;
- current artifact;
- processed count;
- total count when known;
- heartbeat timestamp;
- elapsed time;
- cancel checkpoint.

A RUNNING engine with no heartbeat beyond watchdog threshold must become **STALLED**.

UI must show:

- stalled engine;
- file/task;
- time since last heartbeat;
- **Skip**
- **Retry**
- **Cancel**

Other engines must be allowed to continue where safe.

---

# 11. Cancellation

Every long-running scan must regularly check cancellation.

On cancel:

1. UI immediately changes to “Cancelling…”;
2. no new engine starts;
3. current engine receives cancellation signal;
4. already produced results are preserved;
5. worker exits;
6. UI shows “Analysis cancelled. Partial results saved.”

---

# 12. Bounded scanning

Never read very large `.pak`, `.ucas`, `.so`, `.dat`, etc. fully into RAM unless strictly required.

Use:

- mmap where appropriate;
- bounded windows;
- indexed reads;
- chunk processing;
- streaming output;
- lazy loading.

---

# 13. Evidence Graph 2

Evidence Graph becomes the central state machine from discovery to actionable change.

For every target keep:

- target ID;
- runtime;
- class;
- method;
- field;
- semantic role;
- artifact;
- ABI;
- MethodDef/token;
- RVA;
- VA when available;
- file offset;
- executable section;
- xrefs;
- metadata evidence;
- native evidence;
- runtime evidence;
- confidence;
- blockers;
- change readiness.

---

# 14. Formal proof levels

Use explicit proof levels:

- **LEVEL 0 — DISCOVERED**
- **LEVEL 1 — SEMANTIC**
- **LEVEL 2 — STRUCTURAL**
- **LEVEL 3 — EXACT_METADATA**
- **LEVEL 4 — EXACT_BINARY**
- **LEVEL 5 — RUNTIME_CONFIRMED**
- **LEVEL 6 — CHANGE_READY**

Transitions must be evidence-driven and fail-closed.

---

# 15. Fail-closed rules

Never promote:

- string proximity → method identity;
- entropy → encryption proof;
- short obfuscated identifier → invented semantic name;
- runtime resolver evidence → patch-ready;
- file extension alone → validated format;
- `.jsc` → source JavaScript;
- `.dll` → guaranteed managed CLI;
- adjacent global slots → function pointer table without common-base proof.

Optimizations must not weaken these rules.

---

# 16. Fix “exact locators found, PATCH_READY = 0”

This is a top-priority defect class.

For every transition failure:

`EXACT_METADATA → EXACT_BINARY`

or

`EXACT_BINARY → CHANGE_READY`

store a precise blocker, for example:

- CodeGenModule not resolved;
- ambiguous image;
- ABI mismatch;
- RVA outside executable range;
- stripped mapping;
- binary unavailable;
- unsupported metadata version;
- runtime-only binding;
- source APK mismatch;
- stale analysis;
- target SHA mismatch.

Do not expose unexplained zero counts.

---

# 17. No inconsistent states

Invalid:

`Preflight = BLOCK`
`blockers = 0`

Rule:

If state is BLOCK, at least one blocker must exist.

If the reason cannot be determined:

`INTERNAL_ERROR: unresolved block reason`

---

# 18. IL2CPP Fast Path

When both are detected:

- `global-metadata.dat`
- `libil2cpp.so`

immediately run:

1. metadata version detection;
2. metadata parser;
3. images;
4. assemblies;
5. classes;
6. fields;
7. methods;
8. tokens;
9. MethodDef;
10. CodeGen module recovery;
11. RVA correlation;
12. executable-range validation;
13. semantic indexing;
14. evidence publication.

Do not wait for unrelated security scans.

---

# 19. IL2CPP dump

Produce a standalone human-readable dump early.

Include where available:

- namespace;
- class;
- inheritance;
- fields;
- field offsets;
- methods;
- signatures;
- tokens;
- RVA;
- VA;
- file offset.

The dump must be available before full analysis completes.

---

# 20. IL2CPP / ARM64 current status

## Existing

ARM64/native deep already includes:

- BL
- ADR
- ADRP
- ADD
- MOV
- LDR
- STR
- stack slots
- global slots
- ABI clobber model
- IL2CPP runtime APIs
- dlsym flow
- PLT relocation recovery
- pointer store/load flow
- global cross-function flow
- function pointer tables
- resolver objects

## Still incomplete

This does **not** automatically mean patch-ready.

Still required:

- exact CodeGen association;
- exact binary binding;
- executable range validation;
- conflict handling;
- evidence invalidation when overwritten/changed.

---

# 21. Universal ELF

## Existing

ELF inventory covers:

- ELF32
- ELF64
- ARM32
- ARM64
- x86
- x86-64
- extensionless ELF

and exposes bits, machine, architecture, ABI, ELF type, entry point, ABI/path mismatch, deep availability.

## Still incomplete

Deep analysis remains much stronger for AArch64 than non-ARM64.

---

# 22. ARMv7 / Thumb-2

Complete:

- ARM/Thumb mode detection;
- BL/BLX;
- branches;
- conditional branches;
- function boundaries;
- literal pools;
- PC-relative LDR;
- register moves;
- stack model;
- PLT/GOT;
- JNI;
- dlopen/dlsym;
- indirect BLX Rn;
- data-flow;
- cross-function flow.

---

# 23. x86

Complete:

- rel32 CALL;
- JMP;
- conditional branches;
- ModRM/SIB;
- stack arguments;
- register flow;
- PLT/GOT;
- indirect CALL;
- import recovery;
- dlsym pointer flow.

---

# 24. x86-64

Complete:

- rel32 calls;
- RIP-relative addressing;
- SysV/Android ABI register flow (RDI/RSI/RDX/RCX/R8/R9);
- PLT/GOT;
- indirect calls;
- dlsym → function pointer → call.

---

# 25. Capstone

Capstone can be used as an instruction-decoder backend only if Android integration is reliable.

Before making it mandatory validate:

- Chaquopy compatibility;
- Android ABI availability;
- APK size impact;
- Gradle compatibility;
- CI compatibility;
- compatible wheels;
- offline/reproducible build.

If unsafe/unreliable:

- keep current ARM64 decoder;
- use an `InstructionDecoder` abstraction;
- provide architecture-specific internal decoders;
- keep Capstone optional.

---

# 26. .NET / Unity Mono

## Existing

Real ECMA-335 metadata parsing:

- BSJB;
- metadata streams;
- TypeDef;
- TypeRef;
- Field;
- MethodDef;
- Assembly;
- AssemblyRef;
- semantic strings.

## Still incomplete

Need:

- PE section mapping;
- method RVA;
- CIL method headers;
- CIL instruction decoder;
- IL CFG;
- method call graph;
- property/field/method reconstruction;
- `call`;
- `callvirt`;
- `newobj`;
- `ldfld`;
- `stfld`;
- string correlation;
- semantic correlation;
- NativeAOT;
- ReadyToRun/CoreCLR mapping.

---

# 27. Unreal

## Existing

- uasset ↔ uexp ↔ ubulk;
- UTOC ↔ UCAS;
- PAK footer magic;
- Unreal runtime markers;
- /Script/ and reflection-related names;
- gameplay semantic strings.

## Still incomplete

Need:

- version detection;
- version-specific PAK index;
- IoStore TOC;
- package/object names;
- UObject/UClass/FName model;
- Blueprint semantic reconstruction.

---

# 28. Godot

## Existing

- GDPC PCK header;
- pack format / engine version;
- `.gd`;
- class_name;
- extends;
- signals;
- functions;
- `.tscn/.tres`;
- nodes;
- resources;
- scene graph.

## Still incomplete

Binary/encrypted PCK must not be claimed as fully decoded.

Need:

- binary PCK file table;
- binary resource parsing;
- compiled GDScript versions where feasible.

---

# 29. Defold

## Existing

- `.arci`
- `.arcd`
- `.dmanifest`
- `.projectc`
- `libdmengine.so`
- compiled resource paths
- semantic strings

## Still incomplete

Do not claim original Lua source recovery.

Need:

- deeper archive index;
- manifest parsing;
- resource dependency graph.

---

# 30. Qt/QML

## Existing

Source QML parsing includes:

- imports;
- components;
- ids;
- properties;
- signals;
- functions;
- semantics.

Inventory includes:

- `.qmlc`
- QML `.jsc`
- `.rcc`

## Still incomplete

Do not claim source recovery from compiled QML cache.

Need version-specific cache parsing.

---

# 31. JavaScriptCore

## Existing

Source JS / RN bundle:

- functions;
- arrows;
- strings;
- semantics.

Binary JSC:

- inventory;
- header evidence;
- strings.

## Still incomplete

No fake source reconstruction.

Need version-specific bytecode decoder.

---

# 32. WebAssembly

## Existing

- magic/version;
- ULEB128;
- section directory;
- standard/custom sections;
- exports;
- functions;
- tables;
- memory;
- globals;
- tags.

## Still incomplete

Need:

- instruction body decoder;
- CFG;
- calls;
- global flow;
- memory accesses.

---

# 33. Deobfuscation / Protection

## Existing

- R8/ProGuard-like minimization detection;
- deterministic aliases;
- cross-report identity;
- DexClassLoader;
- InMemoryDexClassLoader;
- PathClassLoader;
- embedded DEX/JAR/APK/SO;
- packer/protector markers;
- anti-debug/TracerPid;
- Frida/Xposed/Magisk/Zygisk/root/emulator markers;
- signature/package integrity;
- Play Integrity/SafetyNet markers;
- high-entropy asset detection.

## Still incomplete

Must not:

- equate entropy with encryption;
- invent source names;
- convert deobfuscation evidence directly to patch-ready.

Need:

- reflection resolution;
- dynamic class-loader correlation;
- encrypted-string decoder pattern detection;
- R8 merge evidence;
- control-flow flattening indicators;
- native symbol stripping analysis;
- JNI obfuscation correlation;
- resource obfuscation;
- packer/loader boundary.

---

# 34. ConfirmationQueue

After primary analysis build a queue only for findings that lack enough proof.

Examples:

- exact MethodDef + exact binary mapping → no extra deep resolve;
- MethodDef without RVA → CodeGen recovery;
- string-only candidate → targeted xrefs/data-flow;
- native pointer candidate → targeted call/data-flow validation;
- runtime-only behavior → runtime confirmation.

Do not deep-scan the entire APK just because one candidate is uncertain.

---

# 35. Runtime escalation

Use staged escalation:

1. **Static**
2. **Repacked test runtime**
3. **Runtime without root**
4. **Root runtime only when required**

Root must never be a default prerequisite for normal analysis.

If root is required, show exactly why and what unresolved targets need runtime memory evidence.

---

# 36. Root/runtime capabilities

Authorized runtime mode should support, where technically feasible:

- process discovery;
- `/proc/<pid>/maps`;
- load-base recovery;
- module mapping;
- RVA → runtime VA;
- dynamically loaded modules;
- memory-backed ELF detection;
- runtime target confirmation;
- JNI correlation;
- dlsym runtime correlation.

Runtime evidence must feed back into Evidence Graph.

---

# 37. AutoMod / Patch Lab UX

Remove **Menu / Runtime** as a separate user-facing screen.

Remove manual Simple Mode controls for:

- Exact prepare
- Preflight
- Phase 7

Keep these as internal stages.

---

# 38. New AutoMod screen

Show a compact summary:

- Targets found
- Confirmed
- Ready for change
- Require confirmation

Primary button:

**Prepare changes**

Internally:

1. refresh plan;
2. SHA validation;
3. exact prepare;
4. binding;
5. preflight;
6. conflict check;
7. output plan.

Secondary button:

**Build APK**

If prepare has not been run or is stale, execute required preparation automatically.

---

# 39. User-facing statuses

Simple Mode should use:

- Found
- Confirming
- Confirmed
- Ready
- Runtime required
- Could not confirm

Raw statuses such as:

- CORRELATED_EVIDENCE
- READY_FOR_PREFLIGHT
- Phase 7

belong in Technical details / Expert Mode.

---

# 40. Patching architecture

Use runtime-specific executors:

- DEX/Smali patch;
- resources/config patch;
- archive-entry replacement;
- managed IL patch;
- native binary patch;
- runtime-module injection into a test build;
- JNI/native integration;
- local state/save modification;
- manifest modification;
- controlled network-response simulation for authorized client-side trust testing;
- menu/control generation.

AutoMod must choose the executor from runtime + evidence + target capability.

Only CHANGE_READY targets may be applied automatically.

---

# 41. Menu Builder

Menu Builder must become part of AutoMod, not a separate confusing workflow.

Flow:

1. select confirmed controls;
2. generate UI/menu;
3. bind controls only to confirmed targets;
4. validate runtime/ABI;
5. add required components;
6. rebuild.

---

# 42. Build pipeline

Final build must automatically perform:

1. source SHA validation;
2. apply modifications;
3. DEX/resource rebuild;
4. native replacement/injection;
5. archive rebuild;
6. remove old signatures;
7. alignment;
8. signing;
9. APK integrity validation;
10. signer verification;
11. installability checks;
12. mutation diff.

Output:

- signed APK/APK-set;
- SHA-256;
- signer info;
- mutation report;
- human-readable report;
- evidence bundle;
- optional raw artifacts.

---

# 43. Re-verification

After build provide:

**Install and verify**

It should:

- install the test build where possible;
- run fast structural reanalysis;
- compare original vs modified;
- verify intended entries changed;
- verify signature;
- verify container integrity;
- report unexpected changes.

---

# 44. Storage UX

Simple Mode storage should expose:

- Main report
- Dump
- Confirmed targets
- Unconfirmed targets
- Patch plan
- Built APK

All raw JSON/JSONL files go under:

**Technical files**

---

# 45. Human-readable report

Main report sections:

## Target
- package;
- version;
- SHA;
- ABI.

## Runtime
Only detected runtimes by default.

## Findings
Categories:
- gameplay;
- premium/purchase;
- local state;
- network/server trust;
- integrity;
- crypto;
- native/JNI;
- debug/test;
- protection.

## Confirmed targets
With supporting evidence.

## Unconfirmed targets
With explicit reasons.

## Modification opportunities
What can be tested/changed and by which mechanism.

## Recommendations
Defensive remediation guidance for the assessed application.

---

# 46. Deep Evidence UX

Do not flood the screen with “Lua not detected”, “Flutter not detected”, etc.

Show detected backends first.

Put absent runtimes behind a collapsed section such as:

**Not detected: Lua, Cocos, Flutter, …**

---

# 47. Expert Lab

Expert Lab is mandatory and independent from the full analysis workflow.

Input can be:

- current target;
- another APK;
- installed app;
- APK-set;
- individual supported file.

Expert Lab must allow direct execution of individual tools.

## General
- Runtime Profiler
- Artifact Inventory
- strings
- hashes
- resource viewer
- protection/deobfuscation

## DEX
- inventory
- methods/fields
- disassembly
- Smali viewer/editor
- xrefs
- search

## IL2CPP
- metadata parser
- dump
- metadata ↔ ELF pair
- CodeGen recovery
- exact RVA resolver

## Native
- ELF parser
- symbols/imports/exports
- relocations
- ARM64
- ARMv7/Thumb
- x86
- x86-64
- CFG
- xrefs

## Managed
- .NET metadata
- CIL

## Other runtimes
- Flutter
- Hermes
- JSC
- Lua
- Unreal
- Godot
- Defold
- Qt/QML
- WASM
- Cocos

## Security
- Network/API
- TLS
- crypto
- server/trust
- integrity
- anti-debug
- root detection
- packer/protection

## Runtime
- process modules
- load base
- RVA → VA
- root probe

## Patch/build
- APK unpack
- Smali editor
- archive replace
- manifest editor
- native replace
- rebuild
- sign
- align
- verify
- mutation diff

If a tool is incompatible with the selected input, fail cleanly with an explicit reason.

---

# 48. Simple Mode

Simple Mode must hide low-level complexity but continue consuming all valid existing report sources.

Do not break older output integrations while simplifying UX.

---

# 49. Preserve existing coverage

Optimization must not remove engines.

Change **when** they run, not whether they exist.

---

# 50. Unknown/custom runtime

Never return only “unsupported”.

Always run generic fallback and explicitly state which specialized backend is missing.

---

# 51. MLBB/libCEZ regression sample

May be used for:

- defensive detection;
- static architecture analysis;
- IL2CPP resolver recovery;
- evidence graph;
- signatures;
- generic analyzer regression.

Do not hardcode MLBB-specific names into generic analyzers.

Do not turn generic development into operational multiplayer cheat deployment.

---

# 52. Backend status matrix

| Backend | Current state | Required work |
|---|---|---|
| Runtime Profiler | Exists | Faster routing-driven use |
| Engine Router | Exists | Demand-driven scheduling |
| Artifact Inventory | Exists | Shared ArtifactIndex |
| Deobfuscator | Exists | Reflection/loaders/strings/JNI/resource |
| ARM64 | Strong | Exact binding/proof improvements |
| ARMv7/Thumb | Partial | Full data-flow |
| x86 | Partial | Full backend |
| x86-64 | Partial | Full backend |
| IL2CPP | Substantial | Fast dump + exact CodeGen binding |
| Mono/.NET | Metadata exists | CIL/CFG/calls |
| Unreal | Structural | Real package/index/model |
| Godot | Source/scene | Binary PCK |
| Defold | Inventory | Archive dependency graph |
| QML | Source | Cache decoder |
| JSC | Source/inventory | Bytecode decoder |
| WASM | Sections | Instruction CFG |
| Flutter | Backend exists | Extend AOT coverage |
| Hermes | Backend exists | Extend HBC coverage |
| Cocos | Correlation exists | Extend |
| Network/TLS/Crypto | Exists | Background/targeted scheduling |

---

# 53. UI removals

Remove from Simple Mode:

- Menu / Runtime
- Exact prepare button
- Preflight button
- Phase 7 button/state
- separate cards for every absent runtime
- huge raw control lists on the main screen
- internal enum/status names

Keep internal functionality.

---

# 54. UI additions

Add:

- fast summary;
- runtime badges;
- detected engines;
- finding categories;
- confirmed/unconfirmed counts;
- per-engine progress;
- current file/task;
- heartbeat;
- skip stalled engine;
- partial results;
- Expert Lab;
- one-click Prepare changes;
- one-click Build APK;
- human-readable blocker reasons.

---

# 55. Reboot recovery

Persist:

- analysis ID;
- target SHA;
- completed stages;
- partial outputs;
- pending/current stage.

After app/device restart show:

**Previous analysis was interrupted**

Actions:

- Resume
- Open partial results
- Delete

Never keep a dead worker shown as RUNNING forever.

---

# 56. RU / EN

Maintain RU/EN UI support.

Technical raw terminology may remain available in Expert Mode, but Simple Mode should be human-readable in the selected language.

---

# 57. Null / zero handling

Minimize unexplained:

- null
- 0
- “no links”

If a value is unavailable, preserve a reason:

- `not_applicable`
- `not_scanned`
- `unsupported_version`
- `not_resolved`
- `runtime_required`
- `parser_failed`
- `cancelled`
- `stalled`

Never hide recoverable data behind generic nulls.

---

# 58. Internal diagnostics

Every engine should record:

- start time;
- stop time;
- elapsed;
- bytes read;
- artifacts processed;
- output size;
- cancellation checks;
- warnings;
- exceptions;
- heartbeat history/last heartbeat.

This data is required to diagnose unexpectedly long scans.

---

# 59. Versioned outputs

Every report/output schema must include:

- schemaVersion;
- engineVersion;
- artifact SHA;
- timestamp;
- input relationships.

Bindings/results become stale when target SHA or incompatible engine versions change.

---

# 60. Target change invalidation

Selecting a different APK invalidates old executable bindings.

Never reuse an old RVA merely because package name matches.

Require target SHA validation.

---

# 61. Development and CI

For every finished layer:

1. commit to `Modkit1`;
2. canonical GitHub Actions run;
3. source hygiene;
4. Python/runtime tests;
5. Android unit tests;
6. Java/Kotlin compile;
7. lint;
8. Android assemble;
9. APK container check;
10. zipalign;
11. signature;
12. release hygiene;
13. artifact upload.

Do not treat a run as green because only early tests passed.

Do not modify or merge `main` without explicit instruction.

---

# 62. Implementation priority

## Phase 1 — Stabilize analysis execution

Implement:

- ArtifactIndex
- scheduler
- FAST/TARGETED/CONFIRMATION/BACKGROUND classes
- incremental results
- heartbeat
- watchdog
- responsive cancellation
- reboot recovery

**Goal:** analysis stops hanging and stops waiting for irrelevant engines.

## Phase 2 — IL2CPP Fast Path

Implement:

- immediate metadata/lib detection
- fast dump
- human-readable dump
- partial-result publication

**Goal:** IL2CPP target yields useful methods/fields/RVA quickly.

## Phase 3 — Exact Binding

Fix:

`many exact locators → zero PATCH_READY`

Implement:

- CodeGen recovery
- metadata ↔ binary proof
- executable mapping
- blocker reasons

**Goal:** genuinely proven targets become CHANGE_READY.

## Phase 4 — Evidence Graph 2

Implement formal proof levels and consistency checks.

Fix:

- BLOCK + blockers 0
- unexplained null
- stale bindings
- invalid confidence transitions

## Phase 5 — AutoMod UX

Remove Menu / Runtime and manual prepare/preflight UX.

Implement:

- Prepare changes
- Build APK
- human statuses
- automatic internal exact prepare/preflight

## Phase 6 — Build pipeline

Implement reliable:

`modify → rebuild → align → sign → verify → export`

## Phase 7 — Expert Lab

Implement direct per-backend testing on APK/APK-set/installed app/individual files.

## Phase 8 — Dynamic escalation

Implement:

- runtime without root
- root when required
- RVA/VA
- runtime confirmation
- return evidence to graph

## Phase 9 — Non-ARM64 completion

Complete:

- ARMv7
- Thumb-2
- x86
- x86-64

## Phase 10 — Remaining deep backends

Continue:

- .NET/CIL
- Unreal
- Godot
- Defold
- QML
- JSC
- WASM
- Deobfuscator
- Flutter/Hermes/Cocos depth improvements

---

# 63. Definition of Done for the core product flow

The core product is considered complete when a user can:

1. select an installed app or APK;
2. start analysis;
3. quickly obtain runtime detection and useful preliminary results;
4. open a dump where the runtime supports it;
5. see clear findings;
6. see which findings are confirmed;
7. automatically run only the additional confirmation needed;
8. receive an explicit explanation when static proof is insufficient;
9. escalate to runtime/root only when required;
10. select confirmed changes;
11. press **Prepare changes**;
12. press **Build APK**;
13. receive a signed APK/APK-set;
14. see SHA/signature/mutation diff;
15. install and re-verify the result.

The user must not be forced through:

`Menu/Runtime → Phase 7 → Exact prepare → Preflight → Builder`

---

# 64. Canonical architecture

```text
TARGET
  ↓
FAST INVENTORY
  ↓
ARTIFACT INDEX
  ↓
MULTI-RUNTIME PROFILER
  ↓
SMART ENGINE ROUTER
  ↓
FAST / TARGETED ENGINES
  ↓
PARTIAL RESULTS AVAILABLE
  ↓
EVIDENCE GRAPH
  ↓
CONFIRMED?
 ┌───────────────┐
 YES             NO
 ↓               ↓
CHANGE READY   TARGETED DEEP RESOLVE
                 ↓
            STATIC ENOUGH?
             ↓         ↓
            YES        NO
             ↓         ↓
        CHANGE READY   RUNTIME
                       ↓
                  ROOT IF REQUIRED
                       ↓
                  CONFIRMATION
                       ↓
                  CHANGE READY
                       ↓
               AUTOMOD / PATCH LAB
                       ↓
               INTERNAL PREPARE
                       ↓
               INTERNAL PREFLIGHT
                       ↓
                  APPLY CHANGES
                       ↓
                 BUILD / SIGN
                       ↓
                   VERIFY
                       ↓
                     APK
```

Separate direct-tool path:

```text
EXPERT LAB
  ↓
Any supported backend
  ↓
APK / APK-set / installed app / individual file
```

---

# 65. Final product principle

The goal is **not** “as many engines as possible, therefore the user waits longer”.

The goal is:

**identify the target quickly → show useful evidence early → deepen only where necessary → preserve fail-closed proof quality → automate confirmation and preparation → produce a verified signed APK.**

Existing engines must be preserved, incomplete engines must remain explicitly marked as incomplete, and every “implemented, but…” limitation in this specification remains an active development requirement until its missing capability is actually implemented and tested.
