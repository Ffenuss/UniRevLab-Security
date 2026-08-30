# Ghidra / PyGhidra Worker

UniRevLab M3 uses an isolated headless Ghidra worker for authorized static reverse engineering of native libraries. The Android process never loads the target `.so`; a worker receives one immutable library object plus an assessment/scope receipt and returns structured RVAs/evidence.

## Supported analysis

- complete function inventory up to the infrastructure resource ceiling;
- function signatures, namespaces, sizes and thunk markers;
- basic-block CFG and typed edges;
- code/data/read/write/call/jump xrefs;
- decompiler output for selected functions or all reported functions when `DECOMPILER` is requested without `decompilerTargets`;
- classic `Java_*` JNI exports;
- static recovery of `JNINativeMethod`-shaped registration tables, table RVAs, and bounded FindClass/RegisterNatives function context when Ghidra has recoverable references;
- IL2CPP `CodeRegistration`, `MetadataRegistration`, and `il2cpp_codegen_register` symbol/callsite evidence;
- result architecture provenance (processor, pointer size, endianness);
- P-code recovered `il2cpp_codegen_register` argument RVAs and bounded executable pointer-table candidates from CodeRegistration.

The worker does **not** execute the target binary. Resource ceilings in the job are containment controls for untrusted input, not feature restrictions; a `DEEP` job may request all analysis modes and decompile the full discovered function set subject to the capacity assigned by the operator.

## Runtime contract

Production invocation requires:

- Ghidra/PyGhidra installed under `GHIDRA_INSTALL_DIR`;
- JDK 21;
- a read-only target artifact mount;
- a read-only scope-receipt mount;
- disposable writable project/output storage;
- outbound network disabled by the container/VM runtime;
- `UNIREVLAB_NETWORK_DISABLED=1` so the launcher fails closed when the production sandbox declaration is missing.

The launcher verifies both SHA-256 values before starting Ghidra, re-hashes the target after analysis, validates result schema 1.3, and atomically publishes the result.

## Local contract tests

```bash
python -m pip install -e 'workers/ghidra[test]'
pytest -q workers/ghidra/tests
```

## Ghidra integration test

The pinned integration target is **Ghidra 12.1.3 PUBLIC 20260817**. `scripts/bootstrap_ghidra.sh` verifies the official release SHA-256 before extracting it.

```bash
GHIDRA_INSTALL_DIR="$(./scripts/bootstrap_ghidra.sh | tail -n 1)"
FIXTURE="$(./test-corpus/ghidra/build-fixture.sh | tail -n 1)"
printf '%s\n' '{"assessment":"fixture","authorityConfirmed":true}' > /tmp/scope.json
python scripts/make_ghidra_fixture_job.py "$FIXTURE" /tmp/scope.json /tmp/job.json
UNIREVLAB_NETWORK_DISABLED=1 python -m unirevlab_ghidra_worker.cli \
  --job /tmp/job.json \
  --input "$FIXTURE" \
  --scope-receipt /tmp/scope.json \
  --output /tmp/result.json \
  --ghidra-install-dir "$GHIDRA_INSTALL_DIR"
python scripts/assert_ghidra_fixture_result.py /tmp/result.json
```

Network isolation must be enforced by the surrounding container/VM in production; the environment flag is only a fail-closed declaration checked by the launcher.
