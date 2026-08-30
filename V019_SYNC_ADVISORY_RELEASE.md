# v0.19 — Coordinator Sync, Split Resources, Advisory Provenance and Signed Release

Checkpoint: `0.19.0-dev-sync-advisory-release` / static report schema `1.17`.

## Coordinator sync

The coordinator accepts an authorized assessment under its pre-existing local UUID only when authority is confirmed. Re-registering the same identity is idempotent; changing the artifact hash or immutable scope under the same ID is rejected. The sync response returns current assessment identity plus latest and historical Ghidra revisions. The Android client verifies assessment ID and artifact SHA-256 before integrating downloaded evidence.

## Split/config resources

Each `resources.arsc` table keeps the source APK/split name and a SHA-256 over its raw configuration structure. Aggregation preserves variants instead of deduplicating by resource ID alone. Reference-chain resolution prefers the same source/configuration and records ambiguity when a deterministic fallback is needed. This permits base resources to resolve into split-delivered values without losing provenance.

## Advisory correlation

Advisory feeds use normalized schema 1.0 and are imported as explicit offline inputs. The raw feed is SHA-256 hashed and feed ID/source/generation time/hash are attached to the report. Findings are emitted only for an exact component identity and an exact version explicitly listed by the feed. No inferred semver range or heuristic CVE claim is generated. CycloneDX 1.6 export carries the resulting vulnerability evidence.

## Release pipeline

Tag-triggered CI restores a release keystore from repository secrets, verifies all signing inputs, builds release APK/AAB, verifies the APK certificate/signature with Android build-tools, and emits deterministic release metadata plus SHA-256 files. No signing secrets are stored in the source tree.

## Verification boundary

Host-side Kotlin/Python/schema/regression tests pass for this checkpoint. Android SDK/Gradle and a downloadable Ghidra distribution are unavailable inside the current isolated container, so connected Android signing/build and headless Ghidra execution remain external release gates rather than locally claimed PASS results.
