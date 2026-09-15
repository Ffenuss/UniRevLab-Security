"""Release entry point for exact no-RVA native recovery with SHA-256 freshness.

The recovery proof itself remains in :mod:`il2cpp_no_rva_native`. This adapter reuses
the same exact-input fingerprint policy as the cancellable AutoMod planner so the
stage-six standalone recovery and the following AutoMod pass never need to repeat the
native recovery for identical metadata/library/method catalogue bytes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import automod_cancellable as _auto


def recover_workspace(workdir: str | Path, output_path: str | Path | None = None,
                      cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    expected = root / "il2cpp-no-rva-native.json"
    destination = Path(output_path) if output_path else expected
    gate = _auto._Gate(cb)
    gate.force()
    result = _auto._ensure_native(root, gate, _auto._FingerprintCache())
    gate.force()

    # The Android release flow uses the canonical workspace path. Keep the optional
    # output argument compatible for callers which request a second summary location,
    # but never move/delete the canonical evidence rows used by AutoMod/reporting.
    if destination != expected:
        part = destination.with_name(destination.name + ".part")
        part.unlink(missing_ok=True)
        try:
            part.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            gate.force()
            part.replace(destination)
        except Exception:
            part.unlink(missing_ok=True)
            raise
    return result
