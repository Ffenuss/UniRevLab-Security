# M1 verification record

Date: 2026-08-28

## Locally executed

- Pure Kotlin model/rule/report smoke compilation with `kotlinc`: pass.
- Deterministic report equality check: pass.
- JSON report validation against `schemas/static-analysis-report.schema.json`: pass (5 representative findings).
- Coordinator tests from the same working directory used by CI: `4 passed`.
- Offline secret preflight: no obvious credentials found.
- Python module compilation: pass.
- Workflow YAML parsing: pass.
- Android XML resource/manifest parsing: pass.
- Malformed APK/ZIP corpus opens as expected, including the intentional `../escape.txt` entry used for path-traversal detection tests.

## Not locally executable in this environment

The current execution container does not provide Android SDK/Gradle or Rust/Cargo. Therefore the following remain connected-CI gates and are **not** claimed as locally verified:

- Android `:app:testDebugUnitTest`;
- Android `:app:assembleDebug`;
- Rust `cargo fmt --check`;
- Rust `cargo clippy`;
- Rust `cargo test`;
- JNI Android cross-build via `cargo-ndk`;
- fuzz execution.

The repository contains workflows for these gates. A standard Gradle 9.5.0 Wrapper remains a release-preparation task because its trusted wrapper JAR could not be generated in this local environment.

## 0.2.1-m1 local verification extension

- pure-Kotlin compile/run smoke for new deep-link and custom-permission rules: pass;
- deterministic exporter output including `declaredPermissions` and `deepLinks`: pass;
- exported report validation against JSON Schema draft 2020-12 schema v1.1: pass;
- coordinator tests after version bump: `4 passed`;
- offline secret preflight after agreement/signing changes: pass.

Android Keystore receipt code requires the Android runtime and remains covered by the connected Android build/instrumentation gate rather than claimed as locally executed here.


## 0.3.0-m2-dev local verification extension

- pure-Kotlin compilation/run of `DexStringScanner`, DEX rules, models and report exporter: pass;
- synthetic DEX fixture: 4 declared/scanned strings, one sanitized HTTPS URL, one HTTP URL and one JWT-like candidate detected: pass;
- raw HTTPS query test value absent from exported report: pass;
- secret candidate output is length-only redaction plus SHA-256 rather than raw value: pass;
- exported report validation against JSON Schema draft 2020-12 schema v1.2: pass.

Full Android integration tests remain a connected-CI gate because Android SDK/Gradle are not installed in this local execution environment.
- DEX top-level `type_ids`, `proto_ids`, `field_ids`, `method_ids`, and `class_defs` fixed-table bounds validation: malformed `method_ids` fixture rejected as expected.
