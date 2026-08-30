# v0.14 — Ghidra product integration

Checkpoint: `0.14.0-dev-ghidra-integration`  
Static report schema: `1.12`  
Ghidra worker result schema: `1.1`

## Implemented

### Android domain/report layer
- Added typed Ghidra engine, coverage, function, CFG, xref, JNI and IL2CPP registration models.
- `StaticAnalysisReport` now carries zero or more normalized Ghidra library results.
- Deterministic report export includes Ghidra evidence and remains bounded by the worker contract.
- RE Browser builds a searchable function-level index with:
  - library + RVA;
  - name / namespace / signature;
  - CFG block count;
  - incoming/outgoing xref counts;
  - resolved JNI registrations;
  - IL2CPP registration evidence;
  - bounded decompiler preview.

### Coordinator ingestion
New endpoints:
- `POST /v1/assessments/{assessment_id}/ghidra-results`
- `GET /v1/assessments/{assessment_id}/ghidra-results`

Ingestion invariants:
1. assessment must exist;
2. reverse-engineering mode must be authorized in the assessment;
3. worker `assessmentId` must match the route assessment;
4. worker `artifactSha256` must match the immutable assessment artifact identity;
5. Ghidra schema must be `1.1`;
6. results are keyed by library entry to make retries/idempotent replacement deterministic.

### Verification
- JSON schemas validate with Draft 2020-12.
- Coordinator regression suite passes: 8 tests.
- Kotlin v0.14 smoke passes for Ghidra RE indexing and report schema 1.12.
- v0.12, v0.13, static-core, M2.4 and M2.5 host regressions pass after updating their fixed Kotlin source lists for the new Ghidra model dependency.
- Gradle/Android SDK are not available in this execution environment, so Android framework/Compose compilation remains the connected build gate.
- No APK is produced for this checkpoint.

## Next — step 15
- Persist assessments/results in the coordinator data layer instead of process memory.
- Add Android coordinator client/import path for Ghidra results.
- Correlate Ghidra JNI registration evidence with DEX native declarations.
- Correlate IL2CPP registration structures with reconstructed metadata method/type tables where confidence is sufficient.
- Add function-level version diff using normalized RVA/name/signature evidence.
