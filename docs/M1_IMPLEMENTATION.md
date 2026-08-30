# Milestone M1 — APK Static Analysis Core

## Objective

Turn the v0.1 artifact fingerprint prototype into a reproducible offline static-assessment pipeline that produces evidence-backed findings without executing the selected APK.

## Implemented data flow

```text
User-selected APK/AAB-like artifact
        |
        v
SAF read-only stream
        |
        +--> bounded private temp copy --> SHA-256 artifact identity
        |
        v
ZIP central-directory scan (no bulk extraction)
        |
        +--> DEX/native/manifest/path metadata
        |
        +--> bounded AndroidManifest.xml read (<= 4 MiB)
        |        |
        |        +--> Rust binary AXML parser --> manifest overlay
        |
        +--> PackageManager archive metadata --> package/components/permissions/signers
                         |
                         v
                   ManifestSummary
                         |
                         v
                  ManifestRuleEngine
                         |
                         v
                 normalized findings
                         |
                         v
              deterministic JSON report
```

## Trust decisions

- Selected artifacts are hostile input.
- No target code is loaded or executed.
- The local analyzer does not request broad storage access.
- Unknown or inaccessible state is represented as `null`/unknown, not inferred as safe or unsafe.
- Active testing remains outside M1 and requires a separately authorized dynamic-lab assessment.

## Parser limits

Rust AXML defaults currently cap:
- input: 8 MiB;
- chunks: 100,000;
- strings: 100,000;
- elements: 100,000;
- attributes per element: 4,096;
- decoded string bytes: 1 MiB.

Android local inspection caps:
- artifact size: 2 GiB;
- ZIP entries inspected: 20,000;
- extracted binary manifest: 4 MiB.

These are defensive limits, not format guarantees. Later releases may make policy limits configurable per deployment while preserving hard ceilings.

## Report identity

Every report contains the assessment ID/timestamp and the SHA-256 hash of the exact analyzed artifact. The JSON Schema requires `authorityConfirmed=true` and a lowercase 64-character SHA-256 artifact identity.

## M1.1 attack-surface extension

The manifest overlay now also inventories browsable VIEW intent filters and normalizes:
- HTTP/HTTPS App Links and whether `android:autoVerify=true` is requested;
- custom URL schemes for mandatory handler review;
- app-declared custom permission base protection levels;
- exported unprotected ContentProviders as a dedicated finding.

Report schema `1.1` added `declaredPermissions` and `deepLinks`; the current M2 native developer schema is `1.3` and additionally carries bounded DEX class/method/native-method indexing plus ELF/JNI inventory. The official client also records a versioned, Android-Keystore-signed agreement receipt before assessments can be created.

## Remaining M1 release-gate work

- run Android SDK build/tests in CI and retain the APK artifact;
- run Rust `fmt`, `clippy`, tests, and fuzz smoke in CI;
- generate and commit a standard Gradle Wrapper from the trusted Gradle 9.5.0 build environment;
- add release signing only after production signing-key custody is defined;
- add instrumented Android corpus tests on emulator/device.


## Transition to M2

M2 begins with a non-executing DEX string-table scanner. APK DEX entries are copied one at a time under per-file and aggregate decompression ceilings, then parsed using checked offsets/counts. HTTP/HTTPS evidence is sanitized before persistence, secret-shaped strings are represented only by type/location/SHA-256/redaction metadata, and parser failures or limit hits are surfaced as partial-coverage findings. See `rules/dex-rules.md`.
