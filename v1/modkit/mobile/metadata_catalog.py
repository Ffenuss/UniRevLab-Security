"""Disk-backed indexes for the complete IL2CPP metadata method catalogue.

The JSONL catalogue remains the source of truth.  This module adds a compact
exact-token hash index which maps common class/method/image search terms to
metadataMethodId values without loading the catalogue into RAM.  Hash collisions
are harmless: consumers still evaluate the original JSON row before displaying
it, so the index can only widen the candidate set, never create evidence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
from typing import Callable, Iterable

MAGIC = b"MKSIDX1\0"
BUCKETS = 64
RECORD = struct.Struct(">QI")
_HEADER = struct.Struct(">8sII")


def fnv1a64(text: str) -> int:
    h = 0xCBF29CE484222325
    for b in str(text).encode("utf-8", "replace"):
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def search_tokens(values: Iterable[object]) -> set[str]:
    """Return deterministic exact tokens shared by the Python and Android UI."""
    out: set[str] = set()
    for raw in values:
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            out.update(search_tokens(raw))
            continue
        text = str(raw).strip()
        if not text:
            continue
        camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        words = re.findall(r"[a-z0-9]+", camel.casefold())
        for word in words:
            if 2 <= len(word) <= 64:
                out.add(word)
        compact = "".join(words)
        if not re.search(r"\s", text) and 3 <= len(compact) <= 64:
            out.add(compact)
    return out


def _row_tokens(row: dict) -> set[str]:
    return search_tokens((
        row.get("image"), row.get("class"), row.get("name"), row.get("label"),
        row.get("method_role"), row.get("semantic") or (),
    ))


def build_method_search_index(catalog_path: str | Path, index_path: str | Path | None = None,
                              *, poll: Callable[[], None] | None = None) -> dict:
    """Build a bounded-memory 64-bucket token-hash -> metadataMethodId index."""
    catalog = Path(catalog_path)
    target = Path(index_path) if index_path is not None else Path(str(catalog) + ".search.idx")
    if not catalog.is_file():
        return {"available": False, "error": "catalog-missing"}
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".method-search-", dir=str(target.parent)))
    bucket_paths = [work / f"b{i:02d}.bin" for i in range(BUCKETS)]
    handles: dict[int, object] = {}
    rows = 0
    associations = 0
    malformed = 0
    unique_hashes = set()
    temp_target = Path(str(target) + ".tmp")
    try:
        with catalog.open("r", encoding="utf-8") as src:
            for line_no, line in enumerate(src):
                if line_no % 4096 == 0 and poll is not None:
                    poll()
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    mid = int(row.get("metadata_method_id", row.get("id")))
                except (ValueError, TypeError, json.JSONDecodeError):
                    malformed += 1
                    continue
                rows += 1
                hashes = {fnv1a64(t) for t in _row_tokens(row)}
                unique_hashes.update(hashes)
                for h in hashes:
                    bucket = h & (BUCKETS - 1)
                    fh = handles.get(bucket)
                    if fh is None:
                        fh = bucket_paths[bucket].open("ab")
                        handles[bucket] = fh
                    fh.write(RECORD.pack(h, mid & 0xFFFFFFFF))
                    associations += 1
        for fh in handles.values():
            fh.close()
        handles.clear()

        header_size = _HEADER.size + (BUCKETS + 1) * 8
        offsets = [header_size]
        written_records = 0
        with temp_target.open("wb") as out:
            out.write(b"\0" * header_size)
            for bucket, bp in enumerate(bucket_paths):
                if poll is not None and bucket % 8 == 0:
                    poll()
                records = []
                if bp.is_file():
                    data = bp.read_bytes()
                    for pos in range(0, len(data) - (len(data) % RECORD.size), RECORD.size):
                        records.append(RECORD.unpack_from(data, pos))
                records = sorted(set(records))
                for h, mid in records:
                    out.write(RECORD.pack(h, mid))
                written_records += len(records)
                offsets.append(out.tell())
            out.seek(0)
            out.write(_HEADER.pack(MAGIC, BUCKETS, RECORD.size))
            for offset in offsets:
                out.write(struct.pack(">Q", offset))
        os.replace(temp_target, target)
        return {
            "available": True,
            "schema": "modkit-method-search-index-1",
            "file": target.name,
            "rows": rows,
            "tokenHashes": len(unique_hashes),
            "associations": associations,
            "records": written_records,
            "malformedRows": malformed,
            "buckets": BUCKETS,
            "recordSize": RECORD.size,
            "encoding": "MKSIDX1; bucket-offset-table; sorted big-endian (u64-fnv1a-token-hash,u32-metadata-method-id)",
        }
    finally:
        for fh in handles.values():
            try:
                fh.close()
            except Exception:
                pass
        try:
            temp_target.unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(work, ignore_errors=True)


def lookup_method_ids(index_path: str | Path, query: str) -> list[int]:
    """Reference reader used by tests and non-Android clients."""
    tokens = sorted(search_tokens((query,)))
    if not tokens:
        return []
    path = Path(index_path)
    with path.open("rb") as fh:
        head = fh.read(_HEADER.size)
        magic, buckets, record_size = _HEADER.unpack(head)
        if magic != MAGIC or buckets <= 0 or record_size != RECORD.size or buckets & (buckets - 1):
            raise ValueError("unsupported metadata search index")
        raw_offsets = fh.read((buckets + 1) * 8)
        offsets = [struct.unpack_from(">Q", raw_offsets, i * 8)[0] for i in range(buckets + 1)]
        current: set[int] | None = None
        for token in tokens:
            h = fnv1a64(token)
            bucket = h & (buckets - 1)
            fh.seek(offsets[bucket])
            remaining = offsets[bucket + 1] - offsets[bucket]
            ids = set()
            while remaining >= RECORD.size:
                rh, mid = RECORD.unpack(fh.read(RECORD.size))
                remaining -= RECORD.size
                if rh == h:
                    ids.add(mid)
            current = ids if current is None else current & ids
            if not current:
                return []
        return sorted(current or ())
