#!/usr/bin/env python3
"""Deterministically export SQLite coordinator state for audited PostgreSQL migration."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

TABLES = (
    ("assessments", "id"),
    ("ghidra_results", "id"),
    ("coordinator_meta", "key"),
    ("audit_events", "id"),
)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def export(db_path: Path, out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {"schemaVersion": "1.0", "source": str(db_path), "tables": []}
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        quick = connection.execute("PRAGMA quick_check").fetchone()
        if not quick or quick[0] != "ok":
            raise RuntimeError("SQLite quick_check failed")
        for table, order_by in TABLES:
            rows = connection.execute(f"SELECT * FROM {table} ORDER BY {order_by} ASC").fetchall()
            path = out_dir / f"{table}.ndjson"
            digest = hashlib.sha256()
            with path.open("wb") as fh:
                for row in rows:
                    line = canonical(dict(row)).encode("utf-8") + b"\n"
                    fh.write(line)
                    digest.update(line)
            manifest["tables"].append({
                "name": table,
                "rows": len(rows),
                "file": path.name,
                "sha256": digest.hexdigest(),
            })
    finally:
        connection.close()
    manifest_path = out_dir / "migration-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    export(args.db, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
