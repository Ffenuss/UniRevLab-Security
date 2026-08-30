# v0.20 Authenticated Coordinator / Upstream Feed / Release Evidence

Checkpoint: `0.20.0-dev-auth-feed-evidence` / static report schema `1.18` / coordinator sync schema `1.1` / release manifest schema `1.1`.

## Coordinator transport and storage

- `/v1/**` is fail-closed unless `UNIREVLAB_COORDINATOR_API_KEYS` is configured; an explicit `UNIREVLAB_ALLOW_ANONYMOUS_LAB=1` override exists only for isolated lab use.
- Bearer and `X-API-Key` authentication are accepted. Raw keys are never persisted; the audit trail records only a SHA-256-derived actor fingerprint.
- SQLite keeps WAL mode, foreign keys, busy timeout and `synchronous=FULL` durability behavior.
- Assessment and Ghidra-result writes append SHA-256 hash-linked audit events. `/v1/status` verifies SQLite quick-check and audit-chain integrity; `/v1/assessments/{id}/audit` exposes bounded audit evidence.
- Sync schema 1.1 adds the current audit-tail hash while preserving Android import of legacy sync 1.0.
- Android sends API keys only as HTTP headers. Plain HTTP remains limited to literal localhost/127.0.0.0/8/`10.0.2.2`/IPv6 loopback lab endpoints; arbitrary DNS names are not accepted as cleartext exceptions.

## Upstream advisory adapters

The Android importer accepts:

- UniRevLab normalized advisory schema 1.0;
- OSV JSON with explicit `affected[].versions`;
- NVD CVE 2.0 JSON with vulnerable CPE criteria only when the CPE itself contains a literal version and no range bounds;
- GitHub Global Advisory JSON only when `vulnerable_version_range` is an exact equality rather than a range.

Range-only evidence is deliberately skipped when UniRevLab cannot evaluate the ecosystem ordering safely. Provenance records input SHA-256, detected format, adapter version, accepted normalized advisory count and skipped source-advisory count.

## Release evidence

- Tag release is blocked on the AArch64 / ARM32 / x86-64 headless Ghidra IL2CPP matrix.
- Release manifest 1.1 records APK/AAB SHA-256, source-manifest SHA-256, signer certificate SHA-256, signing-evidence SHA-256, toolchain-evidence SHA-256 and the actual captured tool versions.
- `SOURCE_DATE_EPOCH` is pinned to the release commit timestamp before build/evidence generation.
- The release artifact bundle includes APK, AAB, signer evidence, toolchain evidence, release manifest and checksum list.

## Host verification

- v0.20 model/report/release-contract smoke: PASS.
- external advisory adapter Kotlin compile against compile-only Android JSON API stubs: PASS.
- v0.19 through v0.12 regressions: PASS.
- static-core, M2.4 and M2.5 regressions: PASS.
- Ghidra worker tests: 4/4 PASS.
- coordinator auth/sync/audit tests: 21/21 PASS.
- release-manifest 1.1 synthetic evidence validation: PASS.

## Connected verification boundary

The current container still lacks a usable Android SDK/Gradle/Ghidra installation and cannot download them from required external hosts. Therefore the Android JVM tests for the real `org.json` adapters, signed APK/AAB build, `apksigner` release evidence, and real headless Ghidra release matrix remain connected gates. They are configured in CI but are not claimed as locally executed.
