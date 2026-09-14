"""Small content-addressed cache for expensive generic APK correlation.

The cache is deliberately scoped to static generic evidence.  Runtime/probe
truth and final Menu eligibility are never cached here.  Entries are keyed by
strong SHA-256 input identities plus an explicit algorithm namespace.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable


CACHE_SCHEMA = "modkit-re-content-cache-1"


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    name: str
    size: int
    sha256: str


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as src:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fingerprint(path: str | Path) -> FileFingerprint:
    p = Path(path)
    return FileFingerprint(p.name, p.stat().st_size, sha256_file(p))


class CorrelationCache:
    def __init__(self, root: str | Path, *, namespace: str = "generic-dev33-v1",
                 max_entries: int = 4, max_bytes: int = 192 * 1024 * 1024):
        self.root = Path(root)
        self.namespace = str(namespace)
        self.max_entries = max(1, int(max_entries))
        self.max_bytes = max(8 * 1024 * 1024, int(max_bytes))

    @property
    def enabled(self) -> bool:
        return os.environ.get("MODKIT_DISABLE_RE_CACHE", "").strip().lower() not in {"1", "true", "yes"}

    def identity(self, paths: Iterable[str | Path]) -> tuple[str, list[FileFingerprint]]:
        fps = [fingerprint(p) for p in paths if Path(p).is_file()]
        payload = {
            "schema": CACHE_SCHEMA,
            "namespace": self.namespace,
            "files": [asdict(x) for x in fps],
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), fps

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json.gz"

    def load(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        path = self._path(key)
        try:
            with gzip.open(path, "rt", encoding="utf-8") as src:
                wrapper = json.load(src)
            if wrapper.get("schema") != CACHE_SCHEMA or wrapper.get("namespace") != self.namespace:
                return None
            payload = wrapper.get("payload")
            if not isinstance(payload, dict):
                return None
            os.utime(path, None)
            return payload
        except (FileNotFoundError, OSError, EOFError, json.JSONDecodeError):
            return None

    def store(self, key: str, payload: dict) -> None:
        if not self.enabled:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        wrapper = {"schema": CACHE_SCHEMA, "namespace": self.namespace, "payload": payload}
        fd, temp_name = tempfile.mkstemp(prefix=".re-cache-", suffix=".tmp", dir=str(self.root))
        os.close(fd)
        temp = Path(temp_name)
        try:
            with gzip.open(temp, "wt", encoding="utf-8", compresslevel=5) as dst:
                json.dump(wrapper, dst, ensure_ascii=False, separators=(",", ":"))
            os.replace(temp, self._path(key))
            self.prune()
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def prune(self) -> None:
        if not self.root.is_dir():
            return
        entries = []
        total = 0
        for p in self.root.glob("*.json.gz"):
            try:
                st = p.stat()
            except OSError:
                continue
            entries.append((st.st_mtime_ns, st.st_size, p))
            total += st.st_size
        entries.sort(reverse=True)
        for _mtime, size, p in entries[self.max_entries:]:
            try:
                p.unlink(); total -= size
            except OSError:
                pass
        if total <= self.max_bytes:
            return
        kept = sorted((x for x in entries[:self.max_entries] if x[2].exists()))
        for _mtime, size, p in kept:
            if total <= self.max_bytes:
                break
            try:
                p.unlink(); total -= size
            except OSError:
                pass
