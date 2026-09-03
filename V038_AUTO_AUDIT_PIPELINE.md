# v0.38.1 Auto Audit

## Outcome

v0.38.1 keeps the complete v0.37 analyzer/product backend and replaces the operator workflow with a
persistent one-selection audit pipeline. The customer profile is saved once. For each engagement the
operator confirms authority, selects an installed application or APK/APKS/XAPK archive, and waits for
one signed evidence package.

v0.38.1 writes the full JSON and IL2CPP managed dump directly to disk instead of constructing a
second artifact-sized String in the Android heap. It also invalidates pre-v0.38.1 analysis cache
entries and reports `libil2cpp.so` ELF coverage separately from metadata correlation.

## Automatic stages

| Stage | Work performed |
|---|---|
| Source | resolve installed `base.apk` + split APKs, or persistently granted document URI |
| Core analysis | existing v0.37 bounded hashing/cache, manifest/resources, DEX/xrefs/CFG, native ELF/JNI, IL2CPP, runtime and supply-chain analysis |
| Dump | locate `global-metadata.dat` automatically and write a reconstructed C#-like `il2cpp-dump.cs` |
| Offsets | export defined native symbol RVAs, IL2CPP table file offsets/tokens, validated managed-method↔native-RVA and JNI↔native-RVA correlations, plus attached Ghidra evidence |
| Trust review | include v0.37 IL2CPP modding-resistance classification and prioritized hardening actions in the customer report |
| Artifacts | copy bounded DEX, native, IL2CPP, managed and supported runtime inputs to an indexed ZIP |
| Gradle/module evidence | inspect base/split manifests, dynamic-feature delivery, AGP/AAR/Kotlin metadata and any embedded Gradle build files |
| Verification | select defensive owner-build test objectives from the observed trust surfaces |
| Integrity | hash every output, sign the manifest with an Android Keystore ECDSA key and package all results |

WorkManager owns the long-running job. The UI can be recreated without losing the job, progress is
read from the analyzer's precise callback, and cancellation is propagated to the existing bounded
scanner checks.

## Outputs

- `signed-evidence-package.zip` — primary customer handoff;
- `customer-report.md` — findings, IL2CPP trust-boundary result and remediation;
- `full-report.json` — complete deterministic v0.37 static report;
- `il2cpp-dump.cs` — reconstructed metadata dump when IL2CPP metadata is available;
- `gradle-module-evidence.json` — base/split/dynamic-feature map plus bounded Gradle/AGP/AAR/Kotlin metadata;
- `offset-evidence.json` — RVA/file-offset/token evidence with explicit address semantics;
- `analysis-artifacts.zip` — automatically located bounded analysis inputs and hashes;
- `verification-plan.json` — defensive test plan for an owner-supplied test/source build;
- `evidence-manifest.json` and `evidence-signature.json` — independently verifiable integrity data.

## Method boundary

The pipeline never executes target code, rewrites DEX/ELF, injects a payload, generates an executable
hook or re-signs a third-party target APK. A general hook/mod-menu/re-signing pipeline would be a
universal tampering system and would make the same feature usable outside the authorized engagement.
For active checks, the report supplies the exact trust surface and expected secure result; the owner
adds instrumentation to a separate test/source build and signs that build with its own test key.

This boundary does not reduce the defensible result: the customer still receives the immutable target
hash, automatically collected evidence, recovered IL2CPP identities, static offset evidence, an
assessment of client/server authority, concrete fixes and cryptographic integrity for the handoff.
