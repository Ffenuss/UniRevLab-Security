from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .contracts import load_json, validate_job, validate_result


class WorkerError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise WorkerError(f"{label} must be a regular non-symlink file")
    return resolved


def verify_inputs(job: dict[str, Any], input_path: Path, scope_receipt_path: Path) -> tuple[Path, Path]:
    input_path = _require_regular_file(input_path, "input artifact")
    scope_receipt_path = _require_regular_file(scope_receipt_path, "scope receipt")
    actual_artifact = sha256_file(input_path)
    actual_receipt = sha256_file(scope_receipt_path)
    if actual_artifact != job["artifactSha256"]:
        raise WorkerError(f"artifact SHA-256 mismatch: expected {job['artifactSha256']}, got {actual_artifact}")
    if actual_receipt != job["scopeReceiptSha256"]:
        raise WorkerError(f"scope receipt SHA-256 mismatch: expected {job['scopeReceiptSha256']}, got {actual_receipt}")
    return input_path, scope_receipt_path


def find_launcher(ghidra_install_dir: Path) -> Path:
    candidates = [
        ghidra_install_dir / "support" / "pyghidraRun",
        ghidra_install_dir / "support" / "pyghidraRun.bat",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise WorkerError(f"PyGhidra launcher not found under {ghidra_install_dir}/support")


def build_command(
    *,
    launcher: Path,
    project_dir: Path,
    input_path: Path,
    job_path: Path,
    output_path: Path,
    script_dir: Path,
    wall_clock_seconds: int,
) -> list[str]:
    analysis_timeout = max(1, wall_clock_seconds - 5)
    return [
        str(launcher),
        "-H",
        str(project_dir),
        "UniRevLabWorker",
        "-import",
        str(input_path),
        "-overwrite",
        "-readOnly",
        "-analysisTimeoutPerFile",
        str(analysis_timeout),
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "UniRevLabExport.py",
        str(job_path),
        str(output_path),
        "-deleteProject",
    ]


def run_job(
    *,
    job_path: Path,
    input_path: Path,
    scope_receipt_path: Path,
    output_path: Path,
    ghidra_install_dir: Path,
    require_network_isolation: bool = True,
) -> dict[str, Any]:
    job = load_json(job_path)
    validate_job(job)
    input_path, _ = verify_inputs(job, input_path, scope_receipt_path)

    if require_network_isolation and os.environ.get("UNIREVLAB_NETWORK_DISABLED") != "1":
        raise WorkerError("worker must run in a network-disabled sandbox (UNIREVLAB_NETWORK_DISABLED=1)")

    launcher = find_launcher(ghidra_install_dir.resolve(strict=True))
    script_dir = Path(__file__).resolve().parents[2] / "ghidra_scripts"
    if not (script_dir / "UniRevLabExport.py").is_file():
        raise WorkerError("UniRevLab Ghidra export script is missing")

    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_output = output_path.with_suffix(output_path.suffix + ".tmp")
    tmp_output.unlink(missing_ok=True)

    limits = job["limits"]
    with tempfile.TemporaryDirectory(prefix="unirevlab-ghidra-") as temp:
        project_dir = Path(temp) / "project"
        project_dir.mkdir(mode=0o700)
        cmd = build_command(
            launcher=launcher,
            project_dir=project_dir,
            input_path=input_path,
            job_path=job_path.resolve(strict=True),
            output_path=tmp_output,
            script_dir=script_dir,
            wall_clock_seconds=limits["wallClockSeconds"],
        )
        env = os.environ.copy()
        env["GHIDRA_HEADLESS_MAXMEM"] = f"{limits['memoryMiB']}M"
        env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + " -Djava.awt.headless=true"
        proc = subprocess.run(
            cmd,
            cwd=temp,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=limits["wallClockSeconds"] + 30,
            check=False,
        )
        if proc.returncode != 0:
            tail = proc.stdout[-12000:] if proc.stdout else ""
            raise WorkerError(f"Ghidra exited with code {proc.returncode}\n{tail}")
        if not tmp_output.is_file():
            tail = proc.stdout[-12000:] if proc.stdout else ""
            raise WorkerError(f"Ghidra completed without result JSON\n{tail}")

    # Re-hash the immutable target after analysis to detect accidental mutation.
    if sha256_file(input_path) != job["artifactSha256"]:
        tmp_output.unlink(missing_ok=True)
        raise WorkerError("input artifact changed during analysis")

    result = load_json(tmp_output)
    validate_result(result)
    if result["assessmentId"] != job["assessmentId"] or result["artifactSha256"] != job["artifactSha256"]:
        tmp_output.unlink(missing_ok=True)
        raise WorkerError("result identity does not match the submitted job")
    os.replace(tmp_output, output_path)
    return result
