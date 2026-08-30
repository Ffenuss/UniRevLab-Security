# v0.21 range resolver + RBAC/key rotation + migration + signed provenance

Checkpoint: `0.21.0-dev-range-rbac-attestation` / static report schema `1.19` / coordinator DB schema `3` / sync schema `1.1` / Ghidra result schema `1.3`.

## Implemented

- Conservative ecosystem-aware range resolver for npm, NuGet and a strict Maven subset. Exact affected versions remain preferred; unsupported syntax returns unknown and never creates a vulnerability match.
- OSV `ECOSYSTEM`/`SEMVER` events and GitHub advisory ranges are retained only when the resolver can interpret them safely. NVD CPE matching remains exact-version-only in this checkpoint.
- Vulnerability evidence records whether a result came from `EXACT_COMPONENT_VERSION` or an ecosystem range resolver.
- Optional detached Ed25519 envelope verification for advisory feeds; report provenance records key ID, algorithm and envelope SHA-256 only after verification succeeds.
- Generic signed provenance tooling for advisory-feed and package-index snapshots.
- Coordinator RBAC roles `VIEWER`, `ANALYST`, `ADMIN`; legacy API-key lists map to `ANALYST` for compatibility.
- JSON keyset configuration supports overlapping key-rotation windows with `notBefore` / `notAfter`; expired/future keys fail authentication.
- Admin-only global audit endpoint plus authenticated `whoami`; write operations require at least `ANALYST`.
- SQLite reference schema advances to 3; PostgreSQL baseline DDL and deterministic SQLite->NDJSON migration export are versioned and regression-tested.
- Connected release workflow emits a release attestation only after the multi-ABI Ghidra gate and signed Android release gate have passed; the attestation is detached-Ed25519 signed.

## Host verification

- v0.21 range/correlation smoke: PASS.
- v0.21 signed feed/package-index + release-attestation smoke: PASS.
- advisory/signed-envelope Kotlin compile against compile-only `org.json` API stubs: PASS.
- coordinator RBAC/rotation/migration/auth/sync/audit tests: 26/26 PASS.
- Ghidra worker tests: 4/4 PASS.
- v0.20..v0.12 regressions: PASS.
- static-core, M2.4, M2.5: PASS.
- JSON schemas, workflow YAML, build/release config and secret preflight: PASS.

## APK build attempt

A real local Android build was attempted after the host regression suite passed. No Android SDK/Gradle installation exists in the runtime, and `scripts/bootstrap_toolchain.sh` fails before installation with:

`curl: (6) Could not resolve host: dl.google.com`

Therefore this checkpoint does **not** claim a newly built v0.21 APK. The connected Android workflow is configured to run `:app:testDebugUnitTest`, lint, `assembleDebug`, and release compilation with Android SDK 37 / Build Tools 36.0.0 / Gradle 9.5.0.
