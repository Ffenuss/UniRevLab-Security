# v0.22 performance + UX checkpoint

Checkpoint: `0.22.0-dev-performance-ux` / Android versionCode `18` / static report schema `1.19`.

## Performance changes

- DEX inventory and bytecode/xref analysis share the validated structural index; incomplete structural indexes fall back to the full parser path rather than silently reducing coverage.
- Base/split assessments reuse identical DEX and native content by SHA-256 while rebasing provenance to the correct archive entry.
- DEX and native parsing use a bounded process-wide two-worker executor; ZIP extraction and byte budgets remain bounded and deterministic.
- `ApkArchiveIndex` performs one bounded central-directory classification pass and is reused by DEX/native/runtime/supply-chain stages when duplicate entry names do not require legacy enumeration fallback.
- Runtime/supply-chain/result merges avoid large `flatMap -> distinct -> take` intermediates and retain prior ordering/limits.
- DEX/native rules classify already-normalized facts in a single pass.
- Cross-runtime correlation pre-normalizes Ghidra identities once and stops uniqueness searches as soon as ambiguity is established.
- IL2CPP symbol inventory consumes imports/exports in one pass.
- RE Browser builds indexes on `Dispatchers.Default`, debounces search and stops after the requested unique result limit.
- Exact warm re-analysis can load an app-private normalized report from a versioned SHA-256 cache after artifact hashing; changing engine version invalidates it.
- Dashboard cancellation uses interruptible IO so blocking analysis receives interruption instead of merely hiding the progress UI.

## UX changes

- New launcher and round icons derived from the approved UniRevLab visual.
- Dark Material 3 color system used across Agreement, Assessment, Dashboard, Installed Apps and Help.
- Main actions are separated: file analysis, installed package analysis, Ghidra import, advisory import, coordinator sync, JSON report, CycloneDX and SPDX.
- New `Справка и функции` page explains what each action does, why it exists and when it is available.

## Verification in this runtime

- Static-core smoke + report schema: PASS.
- M2.4 runtime metadata/supply-chain: PASS.
- M2.5 Hermes/ECMA-335/version evidence/SBOM: PASS.
- Historical regression smokes v0.13 through v0.21, including v0.21 provenance/signature contracts: PASS.
- Normalized analysis cache serialization round-trip + engine-version invalidation: PASS.
- Compose/API compile-only stub typecheck of the redesigned UI: PASS.
- DEX `classes7.dex` parity benchmark: old full code scan `1452.43 ms`; shared-index code scan `759.16 ms`; `~1.91x` for that stage in this container, with identical `DexCodeScanner.FileResult`.

A real Android Gradle build is not marked PASS locally. This runtime currently cannot resolve/download the Gradle/Android SDK distribution. The connected CI remains the authoritative `testDebugUnitTest + lintDebug + assembleDebug + assembleRelease` gate.
