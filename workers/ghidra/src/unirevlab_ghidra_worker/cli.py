from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .runner import WorkerError, run_job


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="UniRevLab disposable Ghidra/PyGhidra worker")
    p.add_argument("--job", type=Path, required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--scope-receipt", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--ghidra-install-dir", type=Path, default=Path(os.environ.get("GHIDRA_INSTALL_DIR", "")))
    p.add_argument("--dev-allow-network", action="store_true", help="development only: skip sandbox network assertion")
    return p


def main() -> int:
    args = parser().parse_args()
    if not str(args.ghidra_install_dir):
        raise SystemExit("--ghidra-install-dir or GHIDRA_INSTALL_DIR is required")
    try:
        result = run_job(
            job_path=args.job,
            input_path=args.input,
            scope_receipt_path=args.scope_receipt,
            output_path=args.output,
            ghidra_install_dir=args.ghidra_install_dir,
            require_network_isolation=not args.dev_allow_network,
        )
    except WorkerError as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": result["status"], "functions": len(result["functions"]), "xrefs": len(result["xrefs"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
