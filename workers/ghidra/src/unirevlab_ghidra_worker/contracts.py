from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

WORKER_ROOT = Path(__file__).resolve().parents[2]
JOB_SCHEMA_PATH = WORKER_ROOT / "job.schema.json"
RESULT_SCHEMA_PATH = WORKER_ROOT / "result.schema.json"


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def validate_document(document: dict[str, Any], schema_path: Path) -> None:
    schema = load_json(schema_path)
    Draft202012Validator(schema).validate(document)


def validate_job(job: dict[str, Any]) -> None:
    validate_document(job, JOB_SCHEMA_PATH)


def validate_result(result: dict[str, Any]) -> None:
    validate_document(result, RESULT_SCHEMA_PATH)
