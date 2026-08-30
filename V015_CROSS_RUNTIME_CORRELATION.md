# v0.15 Cross-runtime correlation and durable Ghidra history

Checkpoint: `0.15.0-dev-cross-runtime`  
Static report schema: `1.13`

## Implemented

- Added conservative DEX native declaration ↔ Ghidra JNI function correlation.
  - Exact class/method/signature matches are preferred.
  - Static JNI exports without a prototype are accepted only when the DEX declaration is unambiguous.
  - Dynamic `RegisterNatives` results with unknown class identity are accepted only when method+signature uniquely identify one DEX native declaration.
  - Ambiguous overloads are intentionally left unresolved.
- Added IL2CPP static-scanner ↔ Ghidra registration correlation.
  - Matching RVA + validated static symbol is high-confidence evidence.
  - Unique symbol identity is retained as medium-confidence evidence.
- Added conservative IL2CPP metadata method ↔ native RVA correlation.
  - No pointer-order guessing is used.
  - A mapping requires a unique metadata-token literal or a unique type+method identity in a recovered Ghidra function.
- Added `GhidraResultIntegrator`, which rejects results for the wrong assessment/artifact or for a scope without reverse-engineering authorization before attachment to the local report.
- Added bounded Android-side import of one Ghidra result JSON object or an array of per-library results.
- RE Browser now shows DEX→JNI native targets and Ghidra→DEX/IL2CPP cross-runtime links.
- Static report schema 1.13 includes deterministic cross-runtime correlation evidence.
- Version diff now includes Ghidra native-function additions/removals and function-shape changes (size, CFG/xref counts and decompiler-preview digest).
- Coordinator persistence moved from process-local dictionaries to SQLite.
  - assessments survive process restart;
  - Ghidra result revisions are content-addressed with SHA-256;
  - duplicate identical submissions are idempotent;
  - latest-per-library and revision-history endpoints are available.

## Safety / correctness constraints

- Target code is never loaded or executed by the correlator/importer.
- Correlation emits no native method address when evidence is ambiguous.
- Imported Ghidra results must match both `assessmentId` and immutable artifact SHA-256.
- Ghidra JSON import is byte-count and item-count bounded.
- IL2CPP method mapping does not infer addresses from metadata ordering alone.

## Verification

- v0.15 Kotlin cross-runtime/schema smoke: PASS.
- Static report schema 1.13 validation: PASS.
- Coordinator tests: 11/11 PASS.
- v0.14 Ghidra regression smoke: PASS.
- v0.13 RE/diff regression smoke: PASS.
- v0.12 signing/AXML/network-security smoke: PASS.
- static-core: PASS.
- M2.4: PASS.
- M2.5: PASS.

## Deferred connected gate

The current host has `kotlinc` but no Android SDK/Gradle executable. Compose/framework compilation, the Android `org.json` import path and instrumentation tests remain a connected Android build gate. No APK is produced for this checkpoint.
