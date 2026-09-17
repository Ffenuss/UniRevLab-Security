"""Cancellation-aware release entry point for ``simple_mode.build_catalog``.

The ranking/ownership/readiness semantics remain owned by ``simple_mode``.  This
adapter temporarily wraps the high-volume row/card hooks and replaces engine detection
with an equivalent cancellable implementation. The release catalogue is enriched with
bounded file-backed IL2CPP MethodDef/RVA evidence, then passed through the evidence-
quality layer which deduplicates normalized surfaces/candidates without promoting weak
evidence. The final catalogue is only written after a last cancellation check, so user
cancellation never publishes a partial file.
"""
from __future__ import annotations

import json
from pathlib import Path
import threading
from typing import Any, Iterable
import zipfile

from modkit.mobile import simple_mode as _base
from modkit.mobile import evidence_quality as _quality
from modkit.mobile import filebacked_method_handoff as _handoff

# Keep the cancellation-aware entry point on the exact same public catalogue
# contract as the canonical implementation; otherwise consumers see different
# schemas depending on which execution path ran.
SCHEMA = _base.SCHEMA
_LOCK = threading.RLock()


class CatalogueCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


class _Gate:
    def __init__(self, cb: Any | None, interval: int = 128):
        self.cb = cb
        self.interval = max(1, int(interval))
        self.count = 0

    def force(self) -> None:
        if _cancelled(self.cb):
            raise CatalogueCancelled("Evidence Graph catalogue cancelled")

    def tick(self) -> None:
        self.count += 1
        if self.count % self.interval == 0:
            self.force()


def _iter_rows(obj: Any, wanted: set[str], gate: _Gate):
    gate.tick()
    if isinstance(obj, dict):
        for key, value in obj.items():
            gate.tick()
            if key in wanted and isinstance(value, list):
                for row in value:
                    gate.tick()
                    if isinstance(row, dict):
                        yield key, row
            if isinstance(value, dict):
                yield from _iter_rows(value, wanted, gate)
    elif isinstance(obj, list):
        for value in obj:
            gate.tick()
            if isinstance(value, dict):
                yield from _iter_rows(value, wanted, gate)


def _detect_engines(apk_paths: Iterable[str | Path], gate: _Gate) -> dict:
    evidence: dict[str, list[str]] = {
        "unity_il2cpp": [], "unity_mono": [], "cocos2dx_cpp": [], "cocos2dx_lua": [],
        "cocos2dx_js": [], "cocos_creator": [], "lua_runtime": [], "android_dex": [], "native": [],
    }
    seen: set[str] = set()
    for raw in apk_paths:
        gate.force()
        path = Path(raw)
        if not path.is_file():
            continue
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
        except CatalogueCancelled:
            raise
        except Exception:
            continue
        low_names = [name.casefold() for name in names]
        joined_sample = " ".join(low_names[: min(len(low_names), 5000)])
        cocos_layout = "cocos" in joined_sample or any(
            name.startswith(("assets/src/", "assets/res/")) for name in low_names
        )

        def mark(key: str, value: str) -> None:
            token = f"{key}:{value}"
            if token not in seen:
                seen.add(token)
                evidence[key].append(value)

        for name, low in zip(names, low_names):
            gate.tick()
            base = low.rsplit("/", 1)[-1]
            if base.startswith("classes") and base.endswith(".dex"):
                mark("android_dex", name)
            if low.endswith(".so"):
                mark("native", name)
            if base == "libil2cpp.so" or low.endswith("global-metadata.dat"):
                mark("unity_il2cpp", name)
            if base in {"libunity.so", "libmain.so"}:
                mark("unity_mono", name)
            if low.endswith((".lua", ".luac", ".luae")) or "liblua" in base or "xlua" in low or "slua" in low:
                mark("lua_runtime", name)
                if cocos_layout:
                    mark("cocos2dx_lua", name)
            if low.endswith((".js", ".jsc")) and ("jsb-adapter" in low or low.startswith("assets/src/")):
                mark("cocos2dx_js", name)
            if "jsb-adapter" in low or (low.endswith((".prefab", ".scene")) and ("assets/" in low or "res/" in low)):
                mark("cocos_creator", name)
            if low.endswith((".csb", ".ccb")):
                mark("cocos2dx_cpp", name)
    gate.force()
    return {"schema": "modkit-engine-detection-1.0", "detected": [k for k, v in evidence.items() if v], "evidence": evidence}


def build_catalog(workdir: str | Path, output_path: str | Path | None = None,
                  cb: Any | None = None) -> dict:
    gate = _Gate(cb)
    gate.force()
    with _LOCK:
        original_iter = _base._iter_rows
        original_detect = _base.detect_engines
        original_generic = _base._generic_card
        original_menu = _base._menu_card
        original_json = _base._json

        def wrapped_iter(obj, wanted):
            yield from _iter_rows(obj, wanted, gate)

        def wrapped_detect(paths):
            return _detect_engines(paths, gate)

        def wrapped_generic(*args, **kwargs):
            gate.tick()
            return original_generic(*args, **kwargs)

        def wrapped_menu(*args, **kwargs):
            gate.tick()
            return original_menu(*args, **kwargs)

        def wrapped_json(path):
            gate.force()
            value = original_json(path)
            gate.force()
            return value

        _base._iter_rows = wrapped_iter
        _base.detect_engines = wrapped_detect
        _base._generic_card = wrapped_generic
        _base._menu_card = wrapped_menu
        _base._json = wrapped_json
        try:
            report = _base.build_catalog(workdir, None)
        finally:
            _base._iter_rows = original_iter
            _base.detect_engines = original_detect
            _base._generic_card = original_generic
            _base._menu_card = original_menu
            _base._json = original_json

    gate.force()
    # The compact analysis.json intentionally does not inline hundreds of thousands
    # of IL2CPP methods. Stream the bounded autopilot index here so exact MethodDef
    # identities/RVAs reach AutoMod/connected-report without loading the full JSONL.
    report = _handoff.enrich_catalog(report, workdir, gate.tick)
    gate.force()
    report = _quality.refine_catalog(report)
    gate.force()
    if isinstance(report, dict):
        # Normalization may carry its own internal schema; the public output must
        # remain compatible with the canonical catalogue consumer contract.
        report["schema"] = _base.SCHEMA
        report["cancelAware"] = cb is not None
    if output_path:
        gate.force()
        destination = Path(output_path)
        temporary = destination.with_name(destination.name + ".part")
        temporary.unlink(missing_ok=True)
        try:
            temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            gate.force()
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return report
