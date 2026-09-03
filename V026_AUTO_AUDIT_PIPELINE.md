# v0.26 Auto Audit pipeline

## Product goal

Reduce a repeated authorized Android assessment to two deliberate actions after initial setup:

1. confirm that the current target is inside the contracted scope;
2. select an installed application or APK/archive.

The analysis, artifact discovery, evidence normalization, report generation and evidence-package
signing then continue as a persistent background job.

## Pipeline

| Stage | Automatic work | Primary evidence |
|---|---|---|
| Prepare | validate persisted scope, resolve selected URI or installed base/split paths, hash input | assessment/job spec, artifact SHA-256 |
| Archive | bounded central-directory index and signing-scheme inventory | archive/signing report fields |
| Manifest | binary AXML, components, permissions, deep links, resources and network-security config | `full-report.json` |
| DEX | bounded class/method/string/code/xref/CFG inventory and trust-surface rules | `full-report.json` |
| Native | non-executing ELF/JNI inventory, hardening and defined-symbol RVA evidence | `offset-evidence.json` |
| Runtime | automatic IL2CPP metadata/library discovery plus Unity Mono, Flutter, Hermes and Unreal artifacts | `analysis-artifacts.zip` |
| Supply chain | packaged dependency inventory and available advisory evidence | `full-report.json` |
| Report | customer-readable findings, impact and remediation | `customer-report.md` |
| Verification | defensive test objectives selected from observed trust surfaces | `verification-plan.json` |
| Sign | SHA-256 manifest plus device-keystore ECDSA signature | `signed-evidence-package.zip` |

The v0.22 normalized result cache, shared APK index and bounded two-way DEX/native parallelism remain
part of the analyzer. Cached technical evidence is rebound to the new authorized assessment identity;
the report and signature are generated again for that job.

## Output contract

- `full-report.json`: deterministic machine-readable static-analysis report.
- `customer-report.md`: concise Russian report with findings and remediation.
- `offset-evidence.json`: static RVA values relative to the library image base, IL2CPP metadata file
  offsets/tokens and any already-attached Ghidra registration/codegen evidence.
- `analysis-artifacts.zip`: automatically located bounded inputs such as DEX, ELF, `global-metadata.dat`,
  managed assemblies and supported runtime assets, plus an inventory with hashes.
- `verification-plan.json`: unexecuted defensive checks and secure expected behaviour.
- `evidence-manifest.json`: filename, size and SHA-256 for every report/artifact output.
- `evidence-signature.json`: `SHA256withECDSA` signature and X.509 public key for independent verification.
- `signed-evidence-package.zip`: all items above in one exportable archive.

## Address semantics

An RVA is not a live process address. It is evidence relative to a particular library image and is
bound to the target artifact hash/build ID in the same report. IL2CPP MethodDef tokens and metadata
table offsets are metadata evidence; they are not asserted to be executable method addresses unless
a structurally validated Ghidra result supplies that correlation.

## Explicit method boundary

The Android client never loads target native libraries, executes target bytecode, rewrites DEX/ELF,
injects a payload, generates an executable hook or re-signs a third-party target APK. A universal
hook/mod-menu injector would turn the assessment client into a general-purpose tampering tool and
would also produce unreliable security conclusions across runtimes, ABIs and protection schemes.

For an active customer engagement, use `verification-plan.json` with a separate test/source build.
The application owner controls the instrumentation and signs that build with its own test key. The
final report records the observed trust boundary, the expected secure result and the remediation.

## Failure and recovery

- WorkManager owns the persistent job and reports progress through both WorkInfo and a job-state file.
- UI recreation does not restart a running audit; it reconnects through the persisted work UUID.
- cancellation is checked between archive, DEX, native, runtime, export and signing operations.
- bounded input/entry/total-size limits prevent an untrusted archive from consuming unbounded storage.
- partial results are never presented as a completed signed package; a summary is written only after
  the package signature succeeds.
