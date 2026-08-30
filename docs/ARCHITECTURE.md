# Architecture v1

## Trust boundaries

1. Android client: local import, fingerprinting, lightweight static inspection, report viewing.
2. Coordinator: identities, scopes, immutable job metadata, policy and result aggregation.
3. Static workers: no execution of target code.
4. Ghidra workers: disposable static native-analysis sandboxes.
5. Dynamic lab: disposable emulator/VM, isolated from coordinator secrets and production networks.

## Core invariant

Every active operation MUST reference an assessment containing an immutable artifact hash, authorized modes, owner/organization, purpose, timestamps and audit identity.

## Artifact model

Target artifacts are hostile input. Parsers must be bounded, fuzz-tested and must not extract paths directly from archive names without canonicalization.
