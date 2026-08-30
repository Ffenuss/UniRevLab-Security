# M2.1 / M2.2 implementation note — DEX code xrefs + Unity IL2CPP

Version: `0.5.0-m2-code-il2cpp-dev`

## DEX code index

The local analyzer now parses bounded `code_item` structures and walks Dalvik instruction streams using opcode-width validation. It does not instantiate classes, call methods, or execute target code.

Current normalized xrefs:

- method → method (`invoke-*`, including polymorphic forms);
- method → string (`const-string`, `const-string/jumbo`);
- method → type (`const-class`, `check-cast`, `instance-of`, `new-instance`, array creation).

Safety limits cap methods with code, instruction units per method, total instruction units and xref counts. Malformed/unsupported instruction streams are recorded as partial coverage rather than being guessed through.

String-xref evidence follows the same privacy rule as the DEX inventory: URL query/fragment data are removed and token-like values are replaced by a cryptographic fingerprint/redacted marker.

The first xref-driven review rules identify:

- dynamic DEX/native-library loading paths;
- process-execution API references;
- security-sensitive WebView/WebSettings API references.

These are review signals, not automatic vulnerability claims; argument/value and reachability analysis remains the next semantic layer.

## Unity IL2CPP baseline

The analyzer now identifies the standard Android IL2CPP pairing:

- `global-metadata.dat` (typically under `assets/bin/Data/Managed/Metadata/`);
- one or more `libil2cpp.so` files.

Without loading native code it records:

- IL2CPP metadata magic (`0xFAB11BAF`) and metadata version;
- conservatively validated metadata header offset/count pairs;
- assembly-name candidates such as `Assembly-CSharp.dll`;
- bounded managed-name candidates from metadata string material;
- Unity version candidates from known Unity data assets;
- exported/imported `il2cpp_*` API symbols from the existing ELF scanner;
- confidence and explicit partial/error state.

This checkpoint intentionally does **not** perform runtime-offset recovery, patch generation, hook generation or protection bypass. Version-aware table decoding and managed↔native correlation are planned for the next static-analysis milestone, with unknown versions retaining a safe fallback rather than assuming a layout.

## Regression corpus

`test-corpus/smoke/StaticCoreSmoke.kt` now builds:

1. a synthetic DEX containing `const-string`, `invoke-static`, `const-class` and `return-void`, and asserts the resulting xrefs;
2. a synthetic IL2CPP APK fixture containing a valid metadata header and non-proprietary marker strings, paired with a mock `libil2cpp` ELF inventory.

No Unity proprietary binary or third-party application artifact is committed to the test corpus.
