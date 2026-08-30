# Verification — v0.22.0-dev-performance-ux

## Passing host-side gates

- v0.21 ecosystem range/correlation smoke: PASS
- v0.21 signed feed/package-index + release-attestation smoke: PASS
- external advisory / signed-envelope Kotlin compile against compile-only `org.json` API stubs: PASS
- static report schema 1.19 validation: PASS
- normalized advisory-feed schema 1.0 validation: PASS
- signed-feed-envelope schema 1.0 validation: PASS
- release-manifest schema 1.1 validation: PASS
- release-attestation schema 1.0 validation: PASS
- detached-signature schema 1.0 validation: PASS
- release-toolchain schema 1.0 validation: PASS
- v0.20 regression: PASS
- v0.19 regression: PASS
- v0.18 regression: PASS
- v0.17 regression: PASS
- v0.16 regression: PASS
- v0.15 regression: PASS
- v0.14 regression: PASS
- v0.13 regression: PASS
- v0.12 regression: PASS
- static-core regression: PASS
- M2.4 runtime metadata / supply-chain regression: PASS
- M2.5 deep metadata / SBOM regression: PASS
- Ghidra worker unit tests: 4/4 PASS
- coordinator RBAC / rotation / migration / auth / sync / audit tests: 26/26 PASS
- workflow YAML parse: PASS
- Android/release build-configuration preflight: PASS
- secret preflight: PASS


## v0.22 performance/UX verification

- shared DEX structural-index parity on a real `classes7.dex`: PASS;
- DEX/native SHA-256 content dedup preserves archive-entry provenance: PASS;
- normalized whole-analysis cache serialization round-trip and engine-version invalidation: PASS;
- runtime/supply-chain streaming merge parity: PASS;
- DEX/native one-pass rule-engine parity: PASS;
- redesigned Agreement / Assessment / Dashboard / Installed Apps / Help UI compile-only Compose/API typecheck: PASS;
- real cancellation is wired through interruptible IO so long-running parser loops can observe interruption.

## v0.22 retained security/evidence coverage

- exact affected versions remain preferred advisory evidence;
- npm/NuGet strict SemVer and a conservative Maven subset support bounded comparator ranges;
- unsupported range syntax is unknown and cannot create a vulnerability finding;
- signed feed/package-index envelopes use detached Ed25519 signatures with pinned public-key material;
- report provenance records verified signing key ID, algorithm and envelope SHA-256;
- coordinator keysets support VIEWER/ANALYST/ADMIN roles and overlapping activation/expiration windows;
- write endpoints require ANALYST, global audit requires ADMIN, and legacy key lists remain ANALYST-compatible;
- SQLite schema 3 retains full-synchronous WAL and hash-chained audit events;
- PostgreSQL baseline DDL and deterministic migration exports preserve assessment/result/audit rows and per-table hashes;
- connected release attestation binds signed Android evidence and all three multi-ABI Ghidra result hashes, then receives a detached Ed25519 signature.

## APK build attempt

A real build was attempted after all host regressions above passed.

The runtime contains no Android SDK, `android.jar`, `sdkmanager`, or Gradle installation. Running `scripts/bootstrap_toolchain.sh` fails on the first Android SDK download with:

```text
curl: (6) Could not resolve host: dl.google.com
```

Therefore this checkpoint does **not** claim a newly built v0.22 APK. The connected Android workflow is configured to install Android SDK 37 / Build Tools 36.0.0 / NDK 28.2.13676358 / Gradle 9.5.0 and run:

```text
:app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease
```

The tag release additionally requires the real AArch64/ARM32/x86-64 Ghidra gate before signed APK/AAB generation and attestation.
