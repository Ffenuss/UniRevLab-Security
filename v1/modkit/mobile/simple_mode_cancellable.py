"""Cancellation-aware release entry point for ``simple_mode.build_catalog``.

The ranking/ownership/readiness semantics remain owned by ``simple_mode``. This
adapter temporarily wraps the high-volume row/card hooks and replaces engine detection
with an equivalent cancellable implementation. The release catalogue is then passed
through the evidence-quality layer which deduplicates normalized surfaces/candidates
without promoting weak evidence. The final catalogue is only written after a last
cancellation check, so user cancellation never publishes a partial file.
"""
from __future__ import annotations

import json
from pathlib import Path
import threading
from typing import Any, Iterable
import zipfile

from modkit.mobile import simple_mode as _base
from modkit.mobile import evidence_quality as _quality

# The cancellable adapter must publish the exact same catalogue schema as the
# canonical implementation. Keeping a second literal here allowed the two entry
# points to drift (1.3 vs 1.4) and made consumers depend on which path happened
# to execute rather than on the ModKit catalogue contract.
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
            if "libcocos" in base or "cocos2d" in low:
                mark("cocos2dx_cpp", name)
            if "cocos" in low and ("creator" in low or "jsb-adapter" in low):
                mark("cocos_creator", name)
    return evidence


def build_catalog(workspace: str | Path, output: str | Path | None = None, cancel: Any | None = None) -> dict:
    root = Path(workspace)
    gate = _Gate(cancel)
    gate.force()

    original_iter = _base._iter_rows
    original_detect = _base._detect_engines

    def iter_rows(obj: Any, wanted: set[str]):
        yield from _iter_rows(obj, wanted, gate)

    def detect_engines(paths: Iterable[str | Path]):
        return _detect_engines(paths, gate)

    # build_catalog uses module-level helpers. The lock keeps the temporary adapter
    # replacement thread-safe for callers sharing one embedded Python interpreter.
    with _LOCK:
        _base._iter_rows = iter_rows
        _base._detect_engines = detect_engines
        try:
            report = _base.build_catalog(root)
        finally:
            _base._iter_rows = original_iter
            _base._detect_engines = original_detect

    gate.force()
    report = _quality.normalize_catalog(report)
    # Preserve the canonical catalogue contract after quality normalization too.
    report["schema"] = _base.SCHEMA
    gate.force()

    if output is not None:
        dst = Path(output)
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".part")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        gate.force()
        tmp.replace(dst)
    return report
