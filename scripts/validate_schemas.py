#!/usr/bin/env python3
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = [
    ROOT / "schemas/static-analysis-report.schema.json",
    ROOT / "schemas/advisory-feed.schema.json",
    ROOT / "schemas/release-manifest.schema.json",
    ROOT / "schemas/release-toolchain.schema.json",
    ROOT / "schemas/signed-feed-envelope.schema.json",
    ROOT / "schemas/release-attestation.schema.json",
    ROOT / "schemas/detached-signature.schema.json",
    ROOT / "workers/ghidra/job.schema.json",
    ROOT / "workers/ghidra/result.schema.json",
]

for path in SCHEMAS:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    print(f"{path}: PASS")
