"""Shared release gate for exact-fresh secondary IL2CPP evidence.

Used by AutoMod-adjacent flows and standalone report generation. It does not classify
findings or promote readiness; it only guarantees that structural cross-check,
metadata-identity and exact no-RVA native-recovery summaries correspond to the current
bytes of metadata.bin, library.so and analysis.methods.jsonl.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from modkit.mobile import automod_cancellable as _auto


def ensure_workspace(workdir: str | Path, cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    gate = _auto._Gate(cb)
    gate.force()
    fingerprints = _auto._FingerprintCache()
    crosscheck = _auto._ensure_crosscheck(root, gate, fingerprints)
    identity = _auto._ensure_identity(root, gate, fingerprints)
    native = _auto._ensure_native(root, gate, fingerprints)
    gate.force()
    return {
        "schema": "modkit-secondary-il2cpp-release-1.0",
        "freshnessPolicy": "EXACT_INPUT_SHA256",
        "mtimeTrustedAsIdentity": False,
        "cancelAware": cb is not None,
        "crosscheck": crosscheck,
        "metadataIdentity": identity,
        "nativeRecovery": native,
    }
