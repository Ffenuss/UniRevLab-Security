"""Cancellation-aware release adapter for IL2CPP metadata identity evidence."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import il2cpp_metadata_identity as _base

SCHEMA = _base.SCHEMA


class MetadataIdentityCancelled(RuntimeError):
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
            raise MetadataIdentityCancelled("IL2CPP metadata identity cancelled")

    def tick(self) -> None:
        self.count += 1
        if self.count % self.interval == 0:
            self.force()


def _part(path: Path) -> Path:
    return path.with_name(path.name + ".part")


def build_identity_evidence(metadata_path: str | Path, methods_path: str | Path,
                            output_path: str | Path, rows_path: str | Path | None = None,
                            cb: Any | None = None) -> dict[str, Any]:
    gate = _Gate(cb)
    gate.force()
    parsed = _base.parse_metadata_identities(metadata_path)
    gate.force()
    method_names: set[str] = parsed["methodNames"]
    qualified: set[tuple[str, str]] = parsed["qualifiedMethods"]
    method_tokens: dict[int, dict[str, Any]] = parsed.get("methodTokens") or {}
    output = Path(output_path)
    rows_output = Path(rows_path) if rows_path else output.with_name("il2cpp-metadata-identity.methods.jsonl")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows_output.parent.mkdir(parents=True, exist_ok=True)
    output_part = _part(output)
    rows_part = _part(rows_output)
    output_part.unlink(missing_ok=True)
    rows_part.unlink(missing_ok=True)

    counts = {
        "catalogRows": 0,
        "rowsWithoutRva": 0,
        "tokenMethodConfirmedNoRva": 0,
        "qualifiedMethodConfirmedNoRva": 0,
        "methodNamePresentNoRva": 0,
        "tokenConflictNoRva": 0,
        "unresolvedNoRva": 0,
    }
    samples: list[dict[str, Any]] = []
    try:
        with Path(methods_path).open("r", encoding="utf-8", errors="replace") as source, rows_part.open("w", encoding="utf-8") as sink:
            for index, line in enumerate(source):
                gate.tick()
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                counts["catalogRows"] += 1
                if _base._rva(row) is not None:
                    continue
                counts["rowsWithoutRva"] += 1

                method = _base._method_name(row)
                cls = _base._class_name(row)
                token = _base._method_token(row)
                token_entry = method_tokens.get(token) if token is not None else None
                token_method = str(token_entry.get("methodName") or "") if token_entry else ""
                token_class = str(token_entry.get("class") or "") if token_entry else ""
                token_conflict = bool(token_entry and (
                    (method and token_method and method != token_method)
                    or (cls and token_class and not _base._same_class(cls, token_class))
                ))
                token_confirmed = bool(token_entry and not token_conflict)

                effective_method = method or (token_method if token_confirmed else "")
                effective_class = cls or (token_class if token_confirmed else "")
                pair_confirmed = bool(
                    effective_method and effective_class
                    and ((effective_class, effective_method) in qualified
                         or (effective_class.rsplit(".", 1)[-1], effective_method) in qualified)
                )
                name_present = bool(effective_method and effective_method in method_names)
                qualified_confirmed = bool(pair_confirmed or (token_confirmed and token_class))

                if token_conflict:
                    status = "METADATA_TOKEN_CONFLICT_NO_RVA"
                    counts["tokenConflictNoRva"] += 1
                elif token_confirmed:
                    status = "METADATA_TOKEN_METHOD_CONFIRMED_NO_RVA"
                    counts["tokenMethodConfirmedNoRva"] += 1
                elif pair_confirmed:
                    status = "METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA"
                    counts["qualifiedMethodConfirmedNoRva"] += 1
                elif name_present:
                    status = "METADATA_METHOD_NAME_PRESENT_NO_RVA"
                    counts["methodNamePresentNoRva"] += 1
                else:
                    status = "UNRESOLVED_NO_RVA"
                    counts["unresolvedNoRva"] += 1

                evidence = {
                    "id": _base._row_id(row, index),
                    "class": effective_class or None,
                    "methodName": effective_method or None,
                    "status": status,
                    "metadataMethodNamePresent": name_present,
                    "metadataQualifiedMethodPresent": qualified_confirmed,
                    "metadataToken": f"0x{token:08x}" if token is not None else None,
                    "metadataTokenConfirmed": token_confirmed,
                    "metadataTokenConflict": token_conflict,
                    "metadataResolvedClass": token_class or None,
                    "metadataResolvedMethodName": token_method or None,
                    "addressConfirmed": False,
                    "rva": None,
                    "actionable": False,
                    "buildable": False,
                    "promotesBuildability": False,
                }
                sink.write(json.dumps(evidence, ensure_ascii=False, separators=(",", ":")) + "\n")
                if len(samples) < 64 and status != "UNRESOLVED_NO_RVA":
                    samples.append(evidence)

        gate.force()
        result = {
            "schema": SCHEMA,
            "engine": "il2cpp.metadata-identity-embedded",
            "mode": "STATIC_METADATA_IDENTITY_ONLY",
            "metadataVersion": parsed["metadata"].get("version"),
            "typeLayout": parsed["typeLayout"],
            "typeLayoutScore": parsed.get("typeLayoutScore", 0.0),
            "typeDefinitionCount": parsed["typeDefinitionCount"],
            "uniqueMethodNameCount": len(method_names),
            "uniqueMethodTokenCount": len(method_tokens),
            "qualifiedMethodPairCount": len(qualified),
            "counts": counts,
            "rowsFile": rows_output.name,
            "addressResolver": False,
            "executesTargetCode": False,
            "writesTarget": False,
            "actionable": False,
            "promotesBuildability": False,
            "note": "Confirms metadata identity only. Missing RVA remains unresolved and cannot be used as a patch binding.",
            "samples": samples,
            "cancelAware": cb is not None,
            "atomicOutputPromotion": True,
        }
        output_part.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        gate.force()
        rows_part.replace(rows_output)
        output_part.replace(output)
        return result
    except Exception:
        output_part.unlink(missing_ok=True)
        rows_part.unlink(missing_ok=True)
        raise


def build_workspace_identity(workspace: str | Path, output_path: str | Path | None = None,
                             cb: Any | None = None) -> dict[str, Any]:
    root = Path(workspace)
    metadata = root / "metadata.bin"
    methods = root / "analysis.methods.jsonl"
    if not metadata.is_file() or not methods.is_file():
        raise ValueError("metadata.bin and analysis.methods.jsonl are required")
    output = Path(output_path) if output_path else root / "il2cpp-metadata-identity.json"
    return build_identity_evidence(
        metadata, methods, output, root / "il2cpp-metadata-identity.methods.jsonl", cb
    )
