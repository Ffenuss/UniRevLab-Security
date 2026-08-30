from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from unirevlab_ghidra_worker.contracts import validate_job, validate_result
from unirevlab_ghidra_worker.runner import WorkerError, build_command, run_job


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sample_job(artifact: bytes, receipt: bytes) -> dict:
    return {
        "schemaVersion": "1.1",
        "assessmentId": "assessment-test",
        "artifactSha256": sha(artifact),
        "scopeReceiptSha256": sha(receipt),
        "libraryEntry": "lib/arm64-v8a/libfixture.so",
        "inputObjectId": "object-1",
        "analysisProfile": "DEEP",
        "analysisModes": ["FUNCTION_INDEX", "CFG_INDEX", "XREF_INDEX", "JNI_REGISTRATION_RECOVERY", "IL2CPP_REGISTRATION_CORRELATION", "DECOMPILER"],
        "decompilerTargets": [4096],
        "limits": {
            "wallClockSeconds": 60,
            "memoryMiB": 1024,
            "maxFunctions": 100000,
            "maxCfgBlocks": 500000,
            "maxXrefs": 1000000,
            "maxDecompilerCharsPerFunction": 100000,
            "maxDecompilerTotalChars": 1000000,
        },
    }


def sample_result(job: dict) -> dict:
    return {
        "schemaVersion": "1.3",
        "assessmentId": job["assessmentId"],
        "artifactSha256": job["artifactSha256"],
        "libraryEntry": job["libraryEntry"],
        "status": "COMPLETE",
        "engine": {"name": "Ghidra", "version": "12.1.3", "pyGhidra": True, "analysisProfile": "DEEP"},
        "architecture": {"processor": "AARCH64", "pointerSize": 8, "endian": "LITTLE"},
        "coverage": {
            "functionsDiscovered": 1,
            "functionsReported": 1,
            "cfgBlocksReported": 1,
            "xrefsReported": 0,
            "decompilerFunctionsReported": 1,
            "truncated": False,
        },
        "functions": [{
            "rva": 4096,
            "name": "fixture",
            "namespace": "Global",
            "signature": "void fixture(void)",
            "sizeBytes": 12,
            "isThunk": False,
            "decompilerPreview": "void fixture(void) {}",
        }],
        "cfg": [{
            "functionRva": 4096,
            "blocks": [{"startRva": 4096, "endRva": 4107, "flowType": "TERMINATOR"}],
            "edges": [],
        }],
        "xrefs": [],
        "jniRegistrations": [],
        "il2cppRegistrations": [],
        "il2cppCodegenCalls": [],
        "il2cppPointerTables": [],
        "il2cppCodegenModules": [],
        "warnings": [],
    }


def test_contract_examples_validate():
    artifact = b"ELF-fixture"
    receipt = b"scope receipt"
    job = sample_job(artifact, receipt)
    result = sample_result(job)
    validate_job(job)
    validate_result(result)


def test_command_uses_pyghidra_headless_and_read_only(tmp_path: Path):
    command = build_command(
        launcher=tmp_path / "pyghidraRun",
        project_dir=tmp_path / "project",
        input_path=tmp_path / "target.so",
        job_path=tmp_path / "job.json",
        output_path=tmp_path / "result.json",
        script_dir=tmp_path / "scripts",
        wall_clock_seconds=120,
    )
    assert command[1] == "-H"
    assert "-readOnly" in command
    assert "-analysisTimeoutPerFile" in command
    assert "UniRevLabExport.py" in command
    assert "-deleteProject" in command


def test_hash_mismatch_fails_before_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = b"actual"
    receipt = b"scope"
    job = sample_job(b"expected", receipt)
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    input_path = tmp_path / "input.so"
    input_path.write_bytes(artifact)
    receipt_path = tmp_path / "scope.json"
    receipt_path.write_bytes(receipt)
    monkeypatch.setenv("UNIREVLAB_NETWORK_DISABLED", "1")
    with pytest.raises(WorkerError, match="artifact SHA-256 mismatch"):
        run_job(
            job_path=job_path,
            input_path=input_path,
            scope_receipt_path=receipt_path,
            output_path=tmp_path / "result.json",
            ghidra_install_dir=tmp_path / "missing-ghidra",
        )


def test_runner_end_to_end_with_fake_pyghidra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = b"safe synthetic ELF fixture"
    receipt = b"signed assessment scope receipt"
    job = sample_job(artifact, receipt)
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    input_path = tmp_path / "input.so"
    input_path.write_bytes(artifact)
    receipt_path = tmp_path / "scope.json"
    receipt_path.write_bytes(receipt)

    ghidra = tmp_path / "ghidra"
    support = ghidra / "support"
    support.mkdir(parents=True)
    launcher = support / "pyghidraRun"
    result_payload = json.dumps(sample_result(job), separators=(",", ":"))
    launcher.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "prev=''\n"
        "job=''\n"
        "out=''\n"
        "for arg in \"$@\"; do\n"
        "  if [ \"$prev\" = 'script' ]; then job=\"$arg\"; prev='job'; continue; fi\n"
        "  if [ \"$prev\" = 'job' ]; then out=\"$arg\"; prev=''; continue; fi\n"
        "  if [ \"$arg\" = 'UniRevLabExport.py' ]; then prev='script'; fi\n"
        "done\n"
        "test -n \"$job\"\n"
        "test -n \"$out\"\n"
        f"printf '%s\\n' '{result_payload}' > \"$out\"\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    monkeypatch.setenv("UNIREVLAB_NETWORK_DISABLED", "1")

    output = tmp_path / "result.json"
    result = run_job(
        job_path=job_path,
        input_path=input_path,
        scope_receipt_path=receipt_path,
        output_path=output,
        ghidra_install_dir=ghidra,
    )
    assert result["status"] == "COMPLETE"
    assert output.is_file()
    assert result["functions"][0]["rva"] == 4096
