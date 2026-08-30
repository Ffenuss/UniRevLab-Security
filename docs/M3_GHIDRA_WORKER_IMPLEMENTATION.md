# M3 — Headless Ghidra/PyGhidra worker

Checkpoint: `0.10.0-m3-ghidra-worker-dev`

## Purpose

M3 moves deep native reverse engineering out of the Android process and into a disposable Ghidra/PyGhidra worker. The target library is treated as hostile data and is never executed by UniRevLab.

## Implemented worker pipeline

1. Validate job JSON against `workers/ghidra/job.schema.json` v1.1.
2. Verify SHA-256 of the immutable target library.
3. Verify SHA-256 of the assessment/scope receipt.
4. Require the production network-isolation declaration.
5. Create a disposable Ghidra project directory.
6. Launch Ghidra in PyGhidra headless mode with the target imported read-only.
7. Run only the repository-maintained `UniRevLabExport.py` post-analysis script.
8. Export deterministic structured native-analysis JSON.
9. Validate result schema v1.1 and job/result identity.
10. Re-hash the target after analysis and atomically publish the result.

## Analysis modes

### Function inventory

Exports function RVA, name, namespace, signature, body size and thunk state. A `DEEP` job may request the complete discovered function inventory subject only to the infrastructure capacity assigned to the worker.

### CFG

Uses Ghidra `BasicBlockModel` to return basic blocks and typed flow edges for discovered functions.

### Xrefs

Returns in-program call, jump, data, read and write references using Ghidra's reference model. External references that do not resolve to target memory are not misrepresented as target RVAs.

### Decompiler

`DECOMPILER` supports either explicit `decompilerTargets` RVAs or all reported functions when the list is absent/empty. Resource ceilings exist to contain malicious or pathological inputs; they do not remove the capability to request full decompilation when the deployment has sufficient capacity.

### JNI

Two recovery tiers are implemented:

- classic exported `Java_*` JNI functions;
- static `JNINativeMethod`-shaped table recovery by following references to JNI signature strings and validating name/signature/function-pointer triples against target memory/code.

Dynamic table entries whose Java class cannot yet be proven are reported with `<dynamic>` class identity rather than guessed.

### IL2CPP

The worker correlates high-confidence defined symbols for CodeRegistration, MetadataRegistration and `il2cpp_codegen_register`, and records callsite references to codegen registration when Ghidra has them. This complements the on-device IL2CPP metadata parser. Architecture-aware argument/value recovery from registration callsites remains the next M3 increment.

## Reproducibility

The integration target is pinned to Ghidra `12.1.3 PUBLIC 20260817`. `scripts/bootstrap_ghidra.sh` verifies the official release SHA-256 before extraction. Ghidra 12.1+ includes PyGhidra integration and requires JDK 21 for the current official release line.

## Regression fixture

`test-corpus/ghidra/ghidra_fixture.c` is benign project-owned code containing:

- classic JNI export;
- synthetic `JNINativeMethod` table;
- branch and call edges for CFG/xref tests;
- IL2CPP-like registration symbols and callsite.

No proprietary Unity binaries or third-party applications are required for worker regression.

## Current verification boundary

Local runtime verification covers job/result schemas, worker command construction, hashes, fail-closed checks and an end-to-end fake-launcher test. The current container cannot download the ~569 MB Ghidra distribution, so real Ghidra execution is a connected CI gate in `.github/workflows/ghidra-worker.yml`.
