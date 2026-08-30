# M2.3 Runtime-specific artifact analysis

Checkpoint: `0.7.0-m2-runtime-artifacts-dev` / report schema `1.6`.

## Goal

Add passive, bounded static analyzers for application runtimes that hide meaningful application logic outside ordinary Java/Kotlin DEX code. This layer improves coverage without executing target code and without generating patches, bypasses, or runtime hooks.

## Flutter

The scanner records:

- `libflutter.so` and its Build-ID when available;
- `libapp.so` presence as a strong Android AOT packaging indicator;
- `flutter_assets` inventory with bounded representative entries;
- `AssetManifest.json`, `AssetManifest.bin`, `FontManifest.json`, and `NOTICES.Z` locations;
- legacy snapshot entry names (`vm_snapshot_*`, `isolate_snapshot_*`) when packaged separately;
- `kernel_blob.bin` / `.dill` development-style artifacts when present.

No Dart snapshot is executed or dynamically loaded. `libapp.so` remains an untrusted ELF input handled by the existing native scanner.

## React Native / Hermes

Hermes bytecode candidates are validated by the official HBC magic `0x1F1903C103BC1FC6`. The parser reads only the stable leading header fields:

- bytecode version;
- source SHA-1 field;
- declared file length;
- global code index;
- function count;
- identifier count;
- string count.

Header reads are capped to 128 bytes. Version-specific instruction decoding is deliberately deferred until a tested format table is introduced. Plain JavaScript bundle candidates are inventoried separately.

The runtime fingerprint layer now distinguishes `REACT_NATIVE`, `HERMES`, and their combined `REACT_NATIVE_HERMES` profile instead of assuming every React Native package uses Hermes.

## Unity Mono / managed assemblies

Managed DLL candidates are no longer accepted by filename alone. The parser validates:

1. DOS `MZ` header;
2. PE signature and bounded section table;
3. PE32/PE32+ optional header;
4. CLI data-directory entry;
5. CLI header RVA mapping through PE sections;
6. ECMA-335 metadata root signature `BSJB`;
7. bounded metadata version string and printable managed-name candidates.

This is enough to distinguish an actual CLI assembly from arbitrary data renamed to `.dll`. Full ECMA-335 table reconstruction is a later task.

## Unreal Engine

The current Unreal layer inventories:

- `libUE4.so` / `libUnreal.so` native engine libraries;
- `.pak` containers;
- IoStore `.utoc` and `.ucas` pairs;
- packaged `.obb` entries when present;
- `UECommandLine.txt`, generic command-line, and `Build.version` marker entries.

PAK/IoStore payload parsing is not attempted in this checkpoint because container versions, optional encryption, and project-specific packaging require a separately versioned parser.

## IL2CPP registration groundwork

The IL2CPP summary now exposes explicit native registration-symbol candidates when dynamic symbols preserve any of:

- CodeRegistration-like symbols;
- MetadataRegistration-like symbols;
- `il2cpp_codegen_register`.

These are **candidates**, not runtime-address claims. Stripped production libraries often remove these names. The next native worker layer validates registration structures with architecture-aware analysis and Ghidra/PyGhidra before correlating metadata methods to function RVAs.

## Ghidra worker boundary

Versioned JSON schemas now define the next worker contract:

- `workers/ghidra/job.schema.json`;
- `workers/ghidra/result.schema.json`.

The worker is designed for a read-only target mount, disabled outbound network, bounded CPU/memory/time, disposable workspace, and UniRevLab-maintained scripts only. Results use structured RVAs, functions, xrefs, JNI registration evidence, and IL2CPP registration evidence.

## Safety properties

- APK/DLL/HBC/ELF input is never executed;
- parser allocations and archive enumeration are bounded;
- malformed PE/CLI and HBC inputs degrade to explicit parse errors;
- no target-provided scripts/plugins are loaded;
- no patch generation, injection, hook installation, anti-cheat bypass, or persistence behavior is implemented;
- framework detection is evidence, not a vulnerability finding.
