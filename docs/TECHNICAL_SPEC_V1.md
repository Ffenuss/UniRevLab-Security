# UniRevLab Security — Technical Specification v1.0

## Product goal

Android-first, open-source platform for authorized Android application security assessment and reverse engineering. The official distribution is defensive: it discovers weaknesses, correlates evidence, supports expert review, and produces reproducible reports tied to an immutable artifact hash.

## Product surfaces

### Android client
- agreement and policy acknowledgement;
- project / assessment scope creation;
- artifact import via Storage Access Framework;
- local static inspection and RE workspace;
- job submission to a self-hosted coordinator;
- findings triage and report viewing;
- offline mode for supported static analyzers.

### Coordinator
- organizations, users and RBAC;
- authorization manifests and immutable scopes;
- artifact/job metadata;
- policy engine;
- worker scheduling;
- normalized findings;
- reports and signed attestations;
- audit log.

### Workers
- Android static analysis;
- dependency/SBOM/CVE analysis;
- headless Ghidra native analysis;
- disposable Android dynamic lab;
- report generation.

## Release architecture

```text
Android client
  | mTLS/OIDC (enterprise) or local-only
  v
Coordinator API ---- PostgreSQL
  |                  Object storage (optional, self-hosted)
  +---- queue ---- Static workers
  +---- queue ---- Ghidra workers
  +---- queue ---- Dynamic-lab workers
```

Artifacts are addressed by SHA-256. A worker receives only the minimum secret material required for its job. Dynamic workers are ephemeral and have no coordinator/database credentials.

## Android modules (target layout)

- `app`: Compose UI and composition root.
- `core-model`: pure Kotlin domain models.
- `core-storage`: encrypted project metadata and local cache.
- `analysis-api`: stable analyzer interfaces and finding schema.
- `analysis-apk`: APK/ZIP/AXML/resources.
- `analysis-dex`: DEX indexes, strings, classes, methods, xrefs.
- `analysis-elf`: ELF, symbols, imports/exports, relocations.
- `analysis-rules`: versioned defensive rules.
- `native-bridge`: JNI bindings to Rust core.

The current repository starts with a single `app` module to keep milestone v0.1 small; the split occurs when parser APIs stabilize.

## Finding schema

Every finding must contain:

- stable rule ID and rule version;
- title and category;
- severity and confidence;
- artifact SHA-256;
- component/location;
- evidence references, never unbounded raw dumps;
- OWASP MASVS/MASTG/MASWE mappings when applicable;
- CWE/CVE mappings when applicable;
- remediation guidance;
- analyzer/tool versions;
- status: new / confirmed / false-positive / accepted-risk / fixed / needs-retest.

## Authorization invariant

Active analysis is permitted only if a stored assessment scope contains:

- artifact or target identity;
- owner/organization;
- purpose;
- authorized modes;
- authority confirmation;
- creator identity;
- creation and expiry timestamps;
- audit identifier.

The public static analyzer can inspect an explicitly selected local artifact without broad package visibility. Network/API testing and dynamic instrumentation require an active scoped assessment.

## Local static-analysis pipeline

1. import via SAF;
2. bounded copy to app-private cache;
3. SHA-256 identity;
4. ZIP central-directory inspection without decompression;
5. APK signature/certificate parsing;
6. binary AndroidManifest parsing;
7. DEX indexing;
8. resource/config extraction;
9. native ELF indexing;
10. dependency/SDK inference;
11. rules;
12. normalized findings;
13. report.

## Native analysis

Rust is the preferred parser implementation for attacker-controlled binary formats. APIs must:

- accept bounded slices/files;
- avoid unchecked arithmetic;
- cap counts, recursion depth and allocation sizes;
- return structured errors;
- expose no implicit code execution;
- have corpus tests and fuzz targets before production enablement.

## Dynamic lab

A dynamic job runs in a disposable Android emulator/VM with:

- no host credentials;
- restricted egress by default;
- per-assessment network allowlist;
- resource/time quotas;
- snapshot reset/destruction after job;
- captured logcat/process/network/filesystem evidence;
- audit trail tied to target hash and scope.

The coordinator never executes uploaded APKs directly.

## Reverse-engineering workspace

Planned views:

- package/components/permissions;
- DEX package/class/method browser;
- strings/constants/search;
- smali and decompiler representation;
- native ELF/functions/imports/exports/strings;
- xrefs and call graph;
- JNI Java↔native graph;
- notes/bookmarks/labels;
- binary version diff.

Headless Ghidra output is normalized into project data; Ghidra itself remains isolated in a worker.

## Supply chain

- CycloneDX and SPDX output;
- dependency/SDK fingerprints;
- CVE/advisory correlation;
- stale/abandoned dependency indicators;
- source/build provenance when provided;
- scanner feed version recorded in each assessment.

## Marketplace gate

Policy result is separate from technical findings. Example outputs:

- PASS;
- PASS_WITH_WARNINGS;
- NEEDS_HUMAN_REVIEW;
- BLOCK.

Every gate result references artifact hash, policy version, rule bundle version and scan timestamp. The platform never claims that a passing scan proves absence of vulnerabilities.

## Privacy

Default deployment is local/self-hosted. Pre-release application artifacts must not be uploaded to a vendor cloud without explicit organization configuration. Reports should redact detected secrets by default.

## Release gates for this project

- Android unit/instrumentation tests;
- Rust unit + fuzz tests;
- coordinator tests;
- SAST and secret scanning;
- dependency/SBOM generation;
- parser corpus tests;
- reproducible signed release metadata;
- threat-model review for new privileged capability;
- no critical/high unresolved vulnerabilities in release dependencies unless documented and risk-accepted.

## Milestones

### M0 — Foundation (current)
Agreement, scope, safe artifact import/fingerprint, repo/CI boundaries.

### M1 — APK static core
APK signatures, AXML manifest, permissions/components, resources, baseline rules, JSON report.

### M2 — DEX + supply chain
DEX index/search, strings/secrets, SDK/dependency inference, SBOM/CVE, SARIF.

### M3 — Native RE
ELF parser, symbols, JNI graph, Ghidra worker, function/xref views, version diff.

### M4 — Dynamic lab
Emulator orchestration, runtime evidence, network lab, scoped non-destructive test cases.

### M5 — Enterprise/marketplace
RBAC, PostgreSQL, worker queue, policy gates, signed attestations, CI/CD and batch scanning.

### M6 — Release hardening
Fuzzing at scale, external security review, privacy/legal review, reproducible builds, store submissions.
