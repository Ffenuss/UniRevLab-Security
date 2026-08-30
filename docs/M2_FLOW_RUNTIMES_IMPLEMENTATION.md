# M2.2 — DEX flow analysis and runtime profiles

Checkpoint: `0.6.0-m2-flow-runtimes-dev`

## Scope

This checkpoint deepens the non-executing local static analyzer. Target APK/DEX/ELF inputs remain hostile data. No target class, native library, Unity runtime, JavaScript bundle, or managed assembly is loaded or executed by the Android client.

## DEX flow index

The bounded DEX code scanner now produces:

- method → method xrefs;
- method → string xrefs with secret redaction and URL query/fragment stripping;
- method → type xrefs;
- method → field xrefs (`INSTANCE_GET/PUT`, `STATIC_GET/PUT`);
- normal-control-flow basic blocks and successor offsets;
- conservative per-basic-block constant observations;
- bounded invoke observations that associate known sanitized register values with a specific callee.

Constant state is deliberately killed for unmodelled instructions and never merged across branches. This reduces false confidence and makes the output suitable for security-rule grading without claiming full runtime data flow.

## Code-level rule grading

`DexRuleEngine` distinguishes syntactic API references from stronger evidence. Current stronger evidence includes statically known `true` arguments for selected risky WebView/WebSettings configuration calls. Presence-only signals remain manual-review findings.

## Local analyst search

The Android dashboard provides bounded local search over:

- classes;
- methods/prototypes;
- sanitized string xrefs;
- fields;
- caller/callee edges.

Search operates only on the normalized local report index and does not execute or instrument the target.

## IL2CPP structured metadata

For validated metadata versions 27–31 the IL2CPP scanner reconstructs a bounded identity-level subset of `global-metadata.dat`:

- metadata string table;
- type-definition table;
- method-definition table;
- type namespace/name;
- method name and declaring type;
- method/field ranges and metadata tokens;
- table ranges and a versioned layout profile.

Unknown layouts fall back to passive candidate inventory rather than guessing. No runtime address/offset recovery, patch generation, hooks, or bypass generation is part of this checkpoint.

## Runtime/framework fingerprints

`RuntimeProfileScanner` passively selects relevant follow-up analyzers using archive paths, normalized DEX class descriptors, native-library names, and IL2CPP evidence. Profiles currently include:

- `UNITY_IL2CPP`;
- `UNITY_MONO`;
- `UNREAL_ENGINE`;
- `FLUTTER`;
- `REACT_NATIVE_HERMES`;
- `XAMARIN_DOTNET`;
- `CORDOVA_WEBVIEW`.

These profiles are technology fingerprints, not vulnerabilities.

## Defensive limits

- per-method instruction-unit limit;
- total decoded instruction-unit budget;
- bounded call/string/type/field xref lists;
- bounded basic-block list;
- bounded constant and invoke-observation lists;
- bounded metadata file/string/type/method counts;
- explicit `truncated`/partial-analysis state.

## Regression fixtures

The repository contains synthetic/non-proprietary fixtures that verify:

- caller/callee and sanitized string xrefs;
- field xrefs and conditional CFG edges;
- constant-to-invoke observations;
- IL2CPP v29 metadata type/method reconstruction;
- passive detection of all runtime profiles listed above.

## Runtime-specific artifact inventories

The passive runtime scanner also records technology-specific packaging metadata:

- Flutter: `flutter_assets`, manifest files, snapshot/kernel entries, `libflutter.so`/`libapp.so`, engine Build-ID where available;
- Hermes: bounded HBC header validation, bytecode version, declared length and basic function/identifier/string counters;
- Unity Mono/.NET: bounded PE/CLI metadata-root validation and printable managed-name candidates; malformed assemblies remain parse errors rather than executable inputs;
- Unreal: `.pak`, `.utoc`, `.ucas`, OBB and command-line/build marker inventory.

These inventories do not unpack proprietary formats beyond the documented bounded header/metadata subsets and never load target runtimes.
